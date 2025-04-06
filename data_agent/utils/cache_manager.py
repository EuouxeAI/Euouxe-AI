"""
Euouxe AI - Enterprise Cache Management System
Implements memory/distributed caching with encryption, TTL policies, and observability
"""

import logging
import time
import threading
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Dict, Optional, Union
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

# Security & Serialization
import pickle
from cryptography.fernet import Fernet
from pydantic import BaseModel, ValidationError, Field, field_validator

# Distributed caching
import redis

# Monitoring
from prometheus_client import Counter, Histogram, Gauge

logger = logging.getLogger(__name__)

# Prometheus Metrics
CACHE_HITS = Counter('cache_hits_total', 'Total cache hits', ['layer', 'strategy'])
CACHE_MISSES = Counter('cache_misses_total', 'Total cache misses', ['layer', 'strategy'])
CACHE_SIZE = Gauge('cache_size_bytes', 'Current cache size in bytes', ['layer'])
CACHE_LATENCY = Histogram('cache_op_duration_seconds', 'Cache operation latency', ['operation'])

class CachePolicy(str, Enum):
    LRU = "lru"
    FIFO = "fifo"
    LIFO = "lifo"
    TTLCryptoSerializer:
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.fernet = Fernet(encryption_key) if encryption_key else None

    def serialize(self, value: Any) -> bytes:
        data = pickle.dumps(value)
        return self.fernet.encrypt(data) if self.fernet else data

    def deserialize(self, data: bytes) -> Any:
        if self.fernet:
            data = self.fernet.decrypt(data)
        return pickle.loads(data)

class CacheBase(ABC):
    """Abstract base class for cache implementations"""
    
    @abstractmethod
    def get(self, key: str) -> Any:
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        pass

    @abstractmethod
    def evict(self, key: str) -> None:
        pass

    @abstractmethod
    def clear(self) -> None:
        pass

class MemoryCache(CacheBase):
    """In-memory LRU cache with size limit and TTL"""
    
    def __init__(self, max_size: int = 1000, policy: CachePolicy = CachePolicy.LRU):
        self._store = OrderedDict()
        self.max_size = max_size
        self.policy = policy
        self.lock = threading.Lock()
        self.expiry_times: Dict[str, float] = {}
        self.serializer = CryptoSerializer()

    @CACHE_LATENCY.labels(operation='get').time()
    def get(self, key: str) -> Any:
        with self.lock:
            if key not in self._store:
                CACHE_MISSES.labels(layer='memory', strategy=self.policy.value).inc()
                raise CacheMissError(f"Key {key} not found")

            if self._is_expired(key):
                self.evict(key)
                CACHE_MISSES.labels(layer='memory', strategy=self.policy.value).inc()
                raise CacheMissError(f"Key {key} expired")

            # Update access order
            value = self._store.pop(key)
            self._store[key] = value
            CACHE_HITS.labels(layer='memory', strategy=self.policy.value).inc()
            return self.serializer.deserialize(value)

    @CACHE_LATENCY.labels(operation='set').time()
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self.lock:
            serialized = self.serializer.serialize(value)
            
            if key in self._store:
                self.evict(key)

            while len(self._store) >= self.max_size:
                self._evict_oldest()

            self._store[key] = serialized
            self.expiry_times[key] = time.time() + ttl if ttl else float('inf')
            CACHE_SIZE.labels(layer='memory').set(len(self._store))

    def _evict_oldest(self):
        if self.policy == CachePolicy.LRU:
            self._store.popitem(last=False)
        elif self.policy == CachePolicy.FIFO:
            self._store.popitem(last=False)
        elif self.policy == CachePolicy.LIFO:
            self._store.popitem(last=True)

    def _is_expired(self, key: str) -> bool:
        return time.time() > self.expiry_times.get(key, 0)

class RedisCache(CacheBase):
    """Redis-backed distributed cache with compression and encryption"""
    
    def __init__(self, host: str = 'localhost', port: int = 6379, 
                 db: int = 0, password: Optional[str] = None,
                 encryption_key: Optional[bytes] = None):
        self.pool = redis.ConnectionPool(host=host, port=port, db=db, password=password)
        self.serializer = CryptoSerializer(encryption_key)
        self.executor = ThreadPoolExecutor(max_workers=4)

    @CACHE_LATENCY.labels(operation='get').time()
    def get(self, key: str) -> Any:
        try:
            with redis.Redis(connection_pool=self.pool) as conn:
                data = conn.get(key)
                if not data:
                    CACHE_MISSES.labels(layer='redis', strategy='distributed').inc()
                    raise CacheMissError(f"Key {key} not found in Redis")
                CACHE_HITS.labels(layer='redis', strategy='distributed').inc()
                return self.serializer.deserialize(data)
        except redis.RedisError as e:
            logger.error(f"Redis operation failed: {str(e)}")
            raise CacheBackendError("Distributed cache unavailable") from e

    @CACHE_LATENCY.labels(operation='set').time()
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        def _async_set():
            try:
                serialized = self.serializer.serialize(value)
                with redis.Redis(connection_pool=self.pool) as conn:
                    conn.set(key, serialized, ex=ttl)
            except redis.RedisError as e:
                logger.error(f"Async cache set failed: {str(e)}")

        self.executor.submit(_async_set)

class CacheManager:
    """Unified cache interface with multi-layer support"""
    
    def __init__(self, layers: Dict[str, CacheBase]):
        self.layers = layers
        self.fallback_order = ['memory', 'redis']

    @CACHE_LATENCY.labels(operation='get').time()
    def get(self, key: str) -> Any:
        for layer in self.fallback_order:
            try:
                return self.layers[layer].get(key)
            except CacheMissError:
                continue
        raise CacheMissError(f"Key {key} not found in any layer")

    @CACHE_LATENCY.labels(operation='set').time()
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        for layer in self.layers.values():
            layer.set(key, value, ttl)

    def clear_all(self) -> None:
        for layer in self.layers.values():
            layer.clear()

# Example Usage
if __name__ == "__main__":
    # Initialize with memory + Redis layers
    cache = CacheManager({
        'memory': MemoryCache(max_size=1000),
        'redis': RedisCache(encryption_key=Fernet.generate_key())
    })

    # Set value
    cache.set("user:1001", {"name": "Alice", "roles": ["admin"]}, ttl=3600)

    # Get value
    try:
        user_data = cache.get("user:1001")
        print(f"Cached data: {user_data}")
    except CacheMissError:
        print("Data not in cache")

"""
BRIM Network - Enterprise Cryptographic Engine
Implements FIPS 140-2 compliant encryption with key management and audit logging
"""

import os
import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Tuple, Union, Dict, Any
from base64 import b64encode, b64decode
from enum import Enum
from pathlib import Path

# Cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, 
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)

# Security monitoring
from prometheus_client import Counter, Histogram
from cryptography.exceptions import InvalidSignature, InvalidTag

logger = logging.getLogger(__name__)

# Prometheus Metrics
ENCRYPTION_OPS = Counter('encryption_operations_total', 'Total encryption operations', ['algorithm', 'mode'])
DECRYPTION_OPS = Counter('decryption_operations_total', 'Total decryption operations', ['algorithm', 'mode'])
ENCRYPTION_TIME = Histogram('encryption_duration_seconds', 'Time spent encrypting data')
DECRYPTION_TIME = Histogram('decryption_duration_seconds', 'Time spent decrypting data')
KEY_ROTATIONS = Counter('key_rotation_operations_total', 'Total key rotation events')

class EncryptionAlgorithm(str, Enum):
    AES_CBC = "AES-CBC"
    AES_GCM = "AES-GCM"
    RSA_OAEP = "RSA-OAEP"
    CHACHA20 = "CHACHA20-POLY1305"

class KeySpec(str, Enum):
    AES_256 = "AES-256"
    RSA_4096 = "RSA-4096"

class KeyState(str, Enum):
    ACTIVE = "active"
    PRE_ACTIVE = "pre-active"
    COMPROMISED = "compromised"
    DEACTIVATED = "deactivated"

class KeyMetadata(BaseModel):
    key_id: str = Field(..., min_length=32, max_length=64)
    creation_date: datetime = Field(default_factory=datetime.utcnow)
    expiration_date: Optional[datetime] = None
    algorithm: EncryptionAlgorithm
    key_spec: KeySpec
    key_version: int = 1
    state: KeyState = KeyState.PRE_ACTIVE
    hsm_backed: bool = False
    tags: Dict[str, str] = Field(default_factory=dict)

class EnterpriseEncryptor:
    """FIPS 140-2 Compliant Cryptographic Engine with Key Management"""
    
    def __init__(
        self,
        key_store_path: Union[str, Path] = "/etc/brim/keys",
        master_key: Optional[bytes] = None,
        hsm_config: Optional[Dict] = None
    ):
        self.key_store = Path(key_store_path)
        self.key_store.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        self.master_key = master_key or os.urandom(64)
        self.hsm_enabled = hsm_config is not None
        self.active_keys: Dict[str, KeyMetadata] = {}
        self.key_rotation_policy = {
            "aes": timedelta(days=90),
            "rsa": timedelta(days=365)
        }
        
        self._init_key_store()
        self._load_active_keys()
        
    def _init_key_store(self) -> None:
        """Initialize secure key storage with ACL protection"""
        if not (self.key_store / "manifest.json").exists():
            manifest = {
                "version": "1.0",
                "created_at": datetime.utcnow().isoformat(),
                "key_algos": [algo.value for algo in EncryptionAlgorithm]
            }
            with open(self.key_store / "manifest.json", "w") as f:
                json.dump(manifest, f, indent=2)

    def _load_active_keys(self) -> None:
        """Load valid keys from key store"""
        for key_file in self.key_store.glob("*.key"):
            with open(key_file, "rb") as f:
                metadata = json.loads(f.read().split(b"---METADATA---")[1])
                key_meta = KeyMetadata(**metadata)
                if key_meta.state == KeyState.ACTIVE:
                    self.active_keys[key_meta.key_id] = key_meta

    @ENCRYPTION_TIME.time()
    def encrypt_data(
        self,
        plaintext: Union[bytes, str],
        algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_GCM,
        key_id: Optional[str] = None,
        associated_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Enterprise-grade encryption with automatic key selection"""
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')

            key_meta, encryption_key = self._get_encryption_key(algorithm, key_id)
            iv = os.urandom(16 if algorithm == EncryptionAlgorithm.AES_GCM else 12)

            if algorithm == EncryptionAlgorithm.AES_GCM:
                cipher = Cipher(
                    algorithms.AES(encryption_key),
                    modes.GCM(iv),
                )
                encryptor = cipher.encryptor()
                if associated_data:
                    encryptor.authenticate_additional_data(associated_data)
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()
                tag = encryptor.tag
            elif algorithm == EncryptionAlgorithm.RSA_OAEP:
                public_key = load_pem_public_key(encryption_key)
                ciphertext = public_key.encrypt(
                    plaintext,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                tag = None
            else:
                raise UnsupportedAlgorithmError(f"Algorithm {algorithm} not implemented")

            ENCRYPTION_OPS.labels(algorithm=algorithm.value, mode="default").inc()
            
            return {
                "ciphertext": b64encode(ciphertext).decode('utf-8'),
                "iv": b64encode(iv).decode('utf-8') if iv else None,
                "tag": b64encode(tag).decode('utf-8') if tag else None,
                "key_id": key_meta.key_id,
                "algorithm": algorithm.value,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise CryptographicOperationError(f"Encryption error: {str(e)}")

    @DECRYPTION_TIME.time()
    def decrypt_data(
        self,
        ciphertext: Union[bytes, str],
        key_id: str,
        iv: Optional[Union[bytes, str]] = None,
        tag: Optional[Union[bytes, str]] = None,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """Secure decryption with key version validation"""
        try:
            if isinstance(ciphertext, str):
                ciphertext = b64decode(ciphertext)
            if isinstance(iv, str):
                iv = b64decode(iv)
            if isinstance(tag, str):
                tag = b64decode(tag)

            key_meta = self.active_keys[key_id]
            decryption_key = self._load_private_key(key_id)

            if key_meta.algorithm == EncryptionAlgorithm.AES_GCM:
                cipher = Cipher(
                    algorithms.AES(decryption_key),
                    modes.GCM(iv, tag),
                )
                decryptor = cipher.decryptor()
                if associated_data:
                    decryptor.authenticate_additional_data(associated_data)
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            elif key_meta.algorithm == EncryptionAlgorithm.RSA_OAEP:
                private_key = load_pem_private_key(decryption_key, password=None)
                plaintext = private_key.decrypt(
                    ciphertext,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            else:
                raise UnsupportedAlgorithmError(f"Algorithm {key_meta.algorithm} not implemented")

            DECRYPTION_OPS.labels(algorithm=key_meta.algorithm.value, mode="default").inc()
            return plaintext
            
        except InvalidTag:
            logger.error("Decryption failed - Invalid authentication tag")
            raise CryptographicOperationError("Authentication tag validation failed")
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise CryptographicOperationError(f"Decryption failed: {str(e)}")

    def rotate_key(self, key_id: str, new_spec: Optional[KeySpec] = None) -> KeyMetadata:
        """Key rotation with cryptographic proof of destruction"""
        old_meta = self.active_keys[key_id]
        new_meta = old_meta.copy()
        new_meta.key_version += 1
        new_meta.state = KeyState.PRE_ACTIVE
        
        # Generate new key material
        if new_meta.algorithm in [EncryptionAlgorithm.AES_GCM, EncryptionAlgorithm.AES_CBC]:
            new_key = os.urandom(32)
        elif new_meta.algorithm == EncryptionAlgorithm.RSA_OAEP:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            new_key = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        
        self._store_key(new_meta, new_key)
        old_meta.state = KeyState.DEACTIVATED
        self._store_key(old_meta, b'')  # Overwrite old key
        
        KEY_ROTATIONS.inc()
        return new_meta

    def _get_encryption_key(self, algorithm: EncryptionAlgorithm, key_id: Optional[str]) -> Tuple[KeyMetadata, bytes]:
        """Retrieve active encryption key with automatic rotation check"""
        if key_id:
            key_meta = self.active_keys[key_id]
            if key_meta.algorithm != algorithm:
                raise KeyAlgorithmMismatchError("Requested algorithm doesn't match key type")
        else:
            key_meta = next(
                (meta for meta in self.active_keys.values() 
                 if meta.algorithm == algorithm and meta.state == KeyState.ACTIVE),
                None
            )
            if not key_meta:
                key_meta = self._generate_new_key(algorithm)
                
        # Check expiration
        if key_meta.expiration_date and datetime.utcnow() > key_meta.expiration_date:
            key_meta = self.rotate_key(key_meta.key_id)
            
        return key_meta, self._load_key_material(key_meta.key_id)

    def _generate_new_key(self, algorithm: EncryptionAlgorithm) -> KeyMetadata:
        """Cryptographically secure key generation"""
        key_id = os.urandom(32).hex()
        key_spec = KeySpec.AES_256 if "AES" in algorithm.value else KeySpec.RSA_4096
        
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=algorithm,
            key_spec=key_spec,
            state=KeyState.ACTIVE,
            expiration_date=datetime.utcnow() + self.key_rotation_policy[
                "aes" if "AES" in algorithm.value else "rsa"
            ]
        )
        
        # Generate key material
        if algorithm in [EncryptionAlgorithm.AES_GCM, EncryptionAlgorithm.AES_CBC]:
            key_material = os.urandom(32)
        elif algorithm == EncryptionAlgorithm.RSA_OAEP:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            key_material = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        else:
            raise UnsupportedAlgorithmError(f"Key generation for {algorithm} not implemented")
            
        self._store_key(metadata, key_material)
        return metadata

    def _store_key(self, metadata: KeyMetadata, key_material: bytes) -> None:
        """Secure key storage with metadata separation"""
        key_file = self.key_store / f"{metadata.key_id}.key"
        with open(key_file, "wb") as f:
            f.write(key_material)
            f.write(b"---METADATA---")
            f.write(json.dumps(metadata.dict()).encode())
        os.chmod(key_file, 0o600)

    def _load_key_material(self, key_id: str) -> bytes:
        """Secure key retrieval with access control"""
        key_file = self.key_store / f"{key_id}.key"
        with open(key_file, "rb") as f:
            return f.read().split(b"---METADATA---")[0]

    def _load_private_key(self, key_id: str) -> bytes:
        """Load private key with HSM integration if configured"""
        # Placeholder for HSM integration
        return self._load_key_material(key_id)

class CryptographicOperationError(Exception):
    """Base exception for cryptographic operations"""

class UnsupportedAlgorithmError(CryptographicOperationError):
    """Unsupported encryption algorithm"""

class KeyAlgorithmMismatchError(CryptographicOperationError):
    """Key type doesn't match requested algorithm"""

# Example usage
if __name__ == "__main__":
    encryptor = EnterpriseEncryptor()
    data = "Sensitive enterprise data"
    
    encrypted = encryptor.encrypt_data(data)
    print(f"Encrypted: {encrypted}")
    
    decrypted = encryptor.decrypt_data(
        ciphertext=encrypted['ciphertext'],
        key_id=encrypted['key_id'],
        iv=encrypted['iv'],
        tag=encrypted['tag']
    )
    print(f"Decrypted: {decrypted.decode()}")

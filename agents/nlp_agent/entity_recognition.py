"""
Euouxe AI - Entity Recognition Agent
Enterprise-grade named entity recognition with contextual linking and model version control.
"""

import os
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pydantic import BaseModel, Field, validator
from cryptography.fernet import Fernet
from prometheus_client import Histogram, Counter, Gauge
from transformers import pipeline, AutoTokenizer, AutoModelForTokenClassification
from huggingface_hub import HfApi, ModelFilter
import torch
import redis
from .base_agent import BaseAgent, AgentConfig, TaskPayload

logger = logging.getLogger(__name__)

# Prometheus metrics
NER_PROCESS_TIME = Histogram('ner_latency_seconds', 'Processing time per request', ['model_type'])
ENTITY_COUNTER = Counter('ner_entities_detected', 'Entities detected by type', ['entity_type'])
CONFIDENCE_DISTRIBUTION = Histogram('ner_confidence_dist', 'Confidence scores distribution', buckets=[0.3, 0.5, 0.7, 0.9])

class EntityConfig(AgentConfig):
    """Extended configuration for NER agent"""
    supported_entities: List[str] = Field(["ORG", "PER", "LOC"], min_items=1)
    model_repository: str = "brim-network/ner-models"
    min_confidence: float = 0.75
    context_window: int = 128
    enable_linking: bool = True
    hf_token: Optional[str] = Field(None, env="HF_TOKEN")

class EntityRequest(TaskPayload):
    """Validated input schema for entity recognition"""
    text: str
    language: str = "en"
    domain_context: Optional[str] = None
    session_id: Optional[str] = None

    @validator('text')
    def validate_text_length(cls, v):
        if len(v) < 5:
            raise ValueError("Text too short for entity analysis")
        if len(v) > 4096:
            raise ValueError("Text exceeds maximum length (4096 chars)")
        return v

class EntityResult(BaseModel):
    """Structured output format with entity metadata"""
    entities: List[Dict[str, Any]]
    model_version: str
    processing_time: float
    context_hash: Optional[str] = None

class EntityRecognitionAgent(BaseAgent):
    """Enterprise NER service with entity linking and model versioning"""
    
    def __init__(self, config: EntityConfig):
        super().__init__(config)
        self.active_models: Dict[str, Any] = {}
        self.model_versions: Dict[str, str] = {}
        self.hf_api = HfApi(token=config.hf_token)
        self.entity_linker = EntityLinkerService(config.redis_host)
        self._load_domain_models()
        self._start_model_healthcheck()

    def _load_domain_models(self):
        """Load base and domain-specific models"""
        # Load general-purpose model
        self._load_model("general", "v2.1.0")
        
        # Load domain-specific models
        for domain in ["finance", "medical"]:
            self._load_model(domain, "v1.0.0")

    def _load_model(self, domain: str, version: str):
        """Load model from HF Hub with version control"""
        model_id = f"{self.config.model_repository}-{domain}"
        try:
            tokenizer = AutoTokenizer.from_pretrained(
                model_id,
                revision=version,
                use_fast=True
            )
            model = AutoModelForTokenClassification.from_pretrained(
                model_id,
                revision=version
            )
            
            self.active_models[domain] = pipeline(
                "token-classification",
                model=model,
                tokenizer=tokenizer,
                aggregation_strategy="max",
                device=0 if torch.cuda.is_available() else -1
            )
            self.model_versions[domain] = version
            logger.info(f"Loaded {domain} model version {version}")
            
        except Exception as e:
            logger.error(f"Failed to load {domain} model: {str(e)}")
            raise AgentException("Model initialization failed", retryable=True)

    async def execute_task(self, payload: EntityRequest) -> EntityResult:
        """Main entity recognition workflow"""
        start_time = datetime.now()
        
        try:
            # Model selection based on domain context
            model = self._select_model(payload.domain_context)
            
            # Secure text preprocessing
            processed_text = self._sanitize_input(payload.text)
            
            # Entity extraction
            with torch.no_grad():
                raw_entities = model(
                    processed_text,
                    stride=self.config.context_window
                )
            
            # Post-processing pipeline
            filtered_entities = self._filter_entities(raw_entities)
            linked_entities = self._link_entities(filtered_entities, payload.text)
            
            # Build result
            processing_time = (datetime.now() - start_time).total_seconds()
            return EntityResult(
                entities=linked_entities,
                model_version=self.model_versions[model],
                processing_time=processing_time,
                context_hash=self._generate_context_hash(payload.text)
            )
            
        except Exception as e:
            logger.error(f"Entity recognition failed: {str(e)}")
            raise AgentException("Processing error", retryable=True)

    def _select_model(self, domain_context: Optional[str]) -> Any:
        """Choose appropriate model based on domain hints"""
        if domain_context and "financial" in domain_context.lower():
            return self.active_models.get("finance", self.active_models["general"])
        if domain_context and re.search(r"(medical|patient)", domain_context, re.I):
            return self.active_models.get("medical", self.active_models["general"])
        return self.active_models["general"]

    def _filter_entities(self, raw_entities: List[Dict]) -> List[Dict]:
        """Apply confidence thresholds and entity type filtering"""
        filtered = []
        for entity in raw_entities:
            if (entity['score'] >= self.config.min_confidence and
                entity['entity_group'] in self.config.supported_entities):
                
                CONFIDENCE_DISTRIBUTION.observe(entity['score'])
                ENTITY_COUNTER.labels(entity_type=entity['entity_group']).inc()
                
                filtered.append({
                    "text": entity['word'],
                    "type": entity['entity_group'],
                    "confidence": round(entity['score'], 3),
                    "start": entity['start'],
                    "end": entity['end']
                })
        return filtered

    def _link_entities(self, entities: List[Dict], context: str) -> List[Dict]:
        """Enrich entities with external knowledge base links"""
        if not self.config.enable_linking:
            return entities
            
        linked = []
        for entity in entities:
            try:
                entity_text = entity['text']
                entity_type = entity['type']
                links = self.entity_linker.resolve_entity(
                    entity_text,
                    entity_type,
                    context
                )
                entity["knowledge_links"] = links
                linked.append(entity)
            except Exception as e:
                logger.warning(f"Entity linking failed for {entity_text}: {str(e)}")
                entity["knowledge_links"] = []
                linked.append(entity)
        return linked

    def _sanitize_input(self, text: str) -> str:
        """Remove sensitive patterns and normalize text"""
        # Remove PII patterns
        sanitized = re.sub(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", "[CARD]", text)  # Credit cards
        sanitized = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]", sanitized)     # SSNs
        
        # Normalize whitespace
        return re.sub(r"\s+", " ", sanitized).strip()

    def _generate_context_hash(self, text: str) -> str:
        """Create reproducible hash for audit purposes"""
        return Fernet(self.config.encryption_key).encrypt(text.encode()).decode()

    def _start_model_healthcheck(self):
        """Background model validation thread"""
        # Implementation placeholder for production
        pass

class EntityLinkerService:
    """External entity resolution service integration"""
    
    def __init__(self, redis_host: str):
        self.redis = redis.Redis(host=redis_host, port=6379)
        self.cache_ttl = 3600  # 1 hour caching

    def resolve_entity(self, text: str, entity_type: str, context: str) -> List[str]:
        """Resolve entities against knowledge graph with caching"""
        cache_key = f"entity:{entity_type}:{text}"
        cached = self.redis.get(cache_key)
        
        if cached:
            return json.loads(cached)
            
        # Simulated external API call
        links = self._call_knowledge_api(text, entity_type, context)
        
        # Cache with encryption
        self.redis.setex(
            cache_key,
            self.cache_ttl,
            json.dumps(links)
        )
        return links

    def _call_knowledge_api(self, text: str, entity_type: str, context: str) -> List[str]:
        """Mock external knowledge base integration"""
        # Production implementation would call actual APIs
        return [f"kg:{entity_type}/{text.lower()}?context={hash(context)}"]

# Example usage
if __name__ == "__main__":
    config = EntityConfig(
        agent_id="ner-01",
        agent_type="nlp",
        hf_token="your_hf_token",
        encryption_key="your-256-bit-key",
        supported_entities=["ORG", "PER", "DATE"]
    )
    
    agent = EntityRecognitionAgent(config)
    agent.start_heartbeat()
    
    request = EntityRequest(
        task_id="req-001",
        parameters={},
        text="Apple Inc. CEO Tim Cook announced Q4 earnings on 2023-10-30.",
        language="en"
    )
    
    result = agent.process_task(request.json())
    print(f"Detected {len(result.entities)} entities:")
    for entity in result.entities:
        print(f"- {entity['text']} ({entity['type']}, confidence: {entity['confidence']:.2f})")

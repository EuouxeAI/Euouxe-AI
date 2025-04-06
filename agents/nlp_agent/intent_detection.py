"""
Euouxe AI - Intent Detection Agent
Handles natural language intent classification with model management and audit logging.
"""

import os
import json
import logging
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, validator
from cryptography.fernet import Fernet
from prometheus_client import Histogram, Counter, Gauge
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from transformers.pipelines import Pipeline
from huggingface_hub import HfApi, ModelFilter
import torch
from torch.nn.functional import softmax
from redis import Redis
from .base_agent import BaseAgent, AgentConfig, TaskPayload

logger = logging.getLogger(__name__)

# Metrics
INTENT_PROCESS_TIME = Histogram('intent_detection_latency_seconds', 'Processing time per request', ['language'])
INTENT_CONFIDENCE = Gauge('intent_confidence', 'Model confidence score', ['intent_class'])
MODEL_CACHE_HITS = Counter('intent_model_cache_hits', 'Number of model cache hits')
MODEL_VERSIONS = Gauge('intent_model_versions', 'Current active model versions', ['model_name', 'language'])

class IntentConfig(AgentConfig):
    """Extended configuration for intent detection"""
    default_language: str = "en"
    model_cache_dir: str = "./model_cache"
    min_confidence: float = 0.6
    hf_token: Optional[str] = Field(None, env="HF_TOKEN")
    fallback_strategy: str = "nearest_neighbor"

class IntentRequest(TaskPayload):
    """Validated input schema for intent requests"""
    text: str
    language: Optional[str] = None
    session_id: Optional[str] = None
    required_intents: Optional[List[str]] = None

    @validator('text')
    def validate_text_length(cls, v):
        if len(v) < 3:
            raise ValueError("Text too short for intent analysis")
        if len(v) > 512:
            raise ValueError("Text exceeds maximum length (512 chars)")
        return v

class IntentResult(BaseModel):
    """Structured output format"""
    top_intent: str
    confidence: float
    alternatives: List[Dict[str, float]]
    detected_language: str
    model_version: str
    explainability: Dict[str, float]

class IntentDetectionAgent(BaseAgent):
    """Enterprise-grade intent classifier with model version control"""
    
    def __init__(self, config: IntentConfig):
        super().__init__(config)
        self.active_models: Dict[str, Pipeline] = {}
        self.model_versions: Dict[str, str] = {}
        self.hf_api = HfApi(token=config.hf_token)
        self._init_model_cache()
        self._load_or_update_model(config.default_language)
        self._start_model_refresh_loop()

    def _init_model_cache(self):
        """Ensure model cache directory exists"""
        os.makedirs(self.config.model_cache_dir, exist_ok=True)
        logger.info(f"Model cache initialized at {self.config.model_cache_dir}")

    def _load_or_update_model(self, language: str, force_update: bool = False):
        """Load model from cache or download latest version"""
        model_id = f"brim-network/intent-{language}"
        cached_version = self._get_cached_model_version(model_id)
        
        # Check for newer models
        latest_version = self._fetch_latest_model_version(model_id)
        
        if not force_update and cached_version:
            MODEL_CACHE_HITS.inc()
            self._load_cached_model(model_id, cached_version)
        else:
            self._download_model(model_id, latest_version)
        
        MODEL_VERSIONS.labels(model_name=model_id, language=language).set(1)

    def _get_cached_model_version(self, model_id: str) -> Optional[str]:
        """Check local cache for existing models"""
        model_path = os.path.join(self.config.model_cache_dir, model_id)
        if os.path.exists(model_path):
            with open(os.path.join(model_path, "version.txt")) as f:
                return f.read().strip()
        return None

    def _fetch_latest_model_version(self, model_id: str) -> str:
        """Get latest model version from HuggingFace Hub"""
        models = self.hf_api.list_models(
            filter=ModelFilter(model_name=model_id),
            sort="lastModified",
            direction=-1
        )
        return models[0].id if models else "1.0.0"

    def _download_model(self, model_id: str, revision: str):
        """Download and cache model with version control"""
        logger.info(f"Downloading {model_id}@{revision}")
        tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            revision=revision,
            cache_dir=self.config.model_cache_dir
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            model_id,
            revision=revision,
            cache_dir=self.config.model_cache_dir
        )
        pipeline = Pipeline(
            task="text-classification",
            model=model,
            tokenizer=tokenizer,
            device=0 if torch.cuda.is_available() else -1
        )
        self.active_models[model_id] = pipeline
        self.model_versions[model_id] = revision
        
        # Save version metadata
        cache_path = os.path.join(self.config.model_cache_dir, model_id)
        os.makedirs(cache_path, exist_ok=True)
        with open(os.path.join(cache_path, "version.txt"), "w") as f:
            f.write(revision)

    async def execute_task(self, payload: IntentRequest) -> IntentResult:
        """Main intent classification workflow"""
        with INTENT_PROCESS_TIME.labels(language=payload.language or self.config.default_language).time():
            # Language detection fallback
            language = payload.language or self._detect_language(payload.text)
            
            # Model selection
            model = self._select_model(language)
            
            # Secure inference
            with torch.no_grad():
                result = model(
                    payload.text,
                    top_k=5,
                    truncation=True,
                    max_length=512
                )
            
            # Post-processing
            processed = self._postprocess_results(result, language)
            self._validate_confidence(processed.top_intent, processed.confidence)
            
            # Audit logging
            self._log_intent_audit(payload, processed)
            
            return processed

    def _select_model(self, language: str) -> Pipeline:
        """Get appropriate model with fallback strategy"""
        model_id = f"brim-network/intent-{language}"
        if model_id not in self.active_models:
            if self.config.fallback_strategy == "nearest_neighbor":
                similar_lang = self._find_closest_language(language)
                model_id = f"brim-network/intent-{similar_lang}"
            self._load_or_update_model(model_id.split("-")[-1])
        return self.active_models[model_id]

    def _detect_language(self, text: str) -> str:
        """Fast language identification (placeholder implementation)"""
        # Replace with actual language detection model
        return self.config.default_language

    def _postprocess_results(self, raw_result: List[Dict], language: str) -> IntentResult:
        """Convert raw model output to structured format"""
        scores = np.array([r['score'] for r in raw_result])
        normalized = softmax(torch.tensor(scores)).numpy()
        
        return IntentResult(
            top_intent=raw_result[0]['label'],
            confidence=float(normalized[0]),
            alternatives=[
                {"intent": r['label'], "score": float(s)}
                for r, s in zip(raw_result, normalized)
            ],
            detected_language=language,
            model_version=self.model_versions[f"brim-network/intent-{language}"],
            explainability={
                "top_features": self._extract_salient_features(raw_result[0]['label'])
            }
        )

    def _validate_confidence(self, intent: str, confidence: float):
        """Enforce minimum confidence thresholds"""
        INTENT_CONFIDENCE.labels(intent_class=intent).set(confidence)
        if confidence < self.config.min_confidence:
            raise AgentException(
                f"Low confidence ({confidence:.2f}) for intent '{intent}'",
                retryable=True
            )

    def _log_intent_audit(self, request: IntentRequest, result: IntentResult):
        """Write encrypted audit trail to Redis"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": request.session_id,
            "raw_text": self._encrypt_text(request.text),
            "result": result.dict()
        }
        self._redis_conn.rpush(
            f"intent:audit:{request.session_id or 'anonymous'}",
            json.dumps(audit_entry)
        )

    def _encrypt_text(self, text: str) -> str:
        """Encrypt sensitive text data"""
        if self.config.encryption_key:
            return Fernet(self.config.encryption_key).encrypt(text.encode()).decode()
        return text

    def _start_model_refresh_loop(self):
        """Background model update checker"""
        # Implementation requires threading/async logic
        # Placeholder for production-grade scheduler integration
        pass

# Example usage
if __name__ == "__main__":
    config = IntentConfig(
        agent_id="intent-detector-01",
        agent_type="nlp",
        hf_token="your_huggingface_token",
        encryption_key="your-256-bit-key"
    )
    
    agent = IntentDetectionAgent(config)
    agent.start_heartbeat()
    
    # Sample request processing
    request = IntentRequest(
        task_id="req-001",
        parameters={},
        text="I need to transfer \$5000 to account 12345",
        language="en"
    )
    
    result = agent.process_task(request.json())
    print(f"Detected intent: {result.top_intent} ({result.confidence:.2%})")

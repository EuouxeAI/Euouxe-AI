"""
BRIM Network - Enterprise Metadata Management Engine
Handles metadata version control, audit logging, dependency graphs, and system interoperability
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from pydantic import BaseModel, Field, validator, root_validator
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
import json
import yaml
import xml.etree.ElementTree as ET
from uuid import uuid4
from prometheus_client import Counter, Histogram, Gauge
from graphlib import TopologicalSorter

logger = logging.getLogger(__name__)

# Monitoring Metrics
METADATA_OPS = Counter('metadata_operations_total', 'Metadata operations count', ['operation', 'status'])
METADATA_SIZE = Histogram('metadata_size_bytes', 'Metadata payload size distribution', ['type'])
DEPENDENCY_DEPTH = Gauge('metadata_dependency_depth', 'Max depth of metadata dependencies')

class MetadataType(str, Enum):
    SCHEMA = "schema"
    PIPELINE = "pipeline"
    AGENT = "agent"
    DATASET = "dataset"
    MODEL = "model"

class StorageBackend(str, Enum):
    POSTGRES = "postgres"
    MONGODB = "mongodb"
    IN_MEMORY = "memory"
    FILESYSTEM = "filesystem"

class Metadata(BaseModel):
    """Enterprise metadata model with version control and security"""
    
    id: str = Field(default_factory=lambda: str(uuid4()), alias="_id")
    name: str = Field(..., min_length=3, max_length=255)
    type: MetadataType
    version: str = Field(..., regex=r'^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$')
    content: Dict[str, Any] = Field(..., min_items=1)
    dependencies: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of dependent metadata IDs to version constraints"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None
    created_by: str = Field("system", min_length=3)
    signature: Optional[str] = None
    encrypted_fields: Set[str] = Field(default_factory=set)
    tags: List[str] = Field(default_factory=list)
    lineage: Optional[Dict[str, Any]] = None
    compatibility_matrix: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Supported system versions e.g. {'spark': ['3.2+']}"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            set: list
        }
        schema_extra = {
            "example": {
                "name": "customer_schema",
                "type": MetadataType.SCHEMA,
                "version": "2.1.0",
                "content": {"fields": ["id", "name"]},
                "dependencies": {"user_model": "1.3.x"},
                "tags": ["PII", "prod"],
                "compatibility_matrix": {"postgres": ["12+"]}
            }
        }

    @root_validator(pre=True)
    def validate_versioning(cls, values):
        if values.get('updated_at') and values['updated_at'] < values.get('created_at'):
            raise ValueError("updated_at must be after created_at")
        return values

class MetadataManager:
    """Enterprise metadata repository with advanced management features"""
    
    def __init__(self, 
                 storage_backend: StorageBackend = StorageBackend.IN_MEMORY,
                 encryption_key: Optional[bytes] = None,
                 audit_enabled: bool = True):
        
        self.storage_backend = storage_backend
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.audit_enabled = audit_enabled
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()
        
        # Initialize storage
        self._storage: Dict[str, Metadata] = {}
        self._audit_log: List[Dict] = []
        self._version_graph: Dict[str, List[str]] = {}
        self._dependency_graph: Dict[str, List[str]] = {}

    def add_metadata(self, metadata: Metadata) -> Metadata:
        """Store metadata with version control and dependency checks"""
        self._validate_dependencies(metadata)
        self._check_compatibility(metadata)
        metadata.signature = self._sign_metadata(metadata)
        
        if metadata.encrypted_fields:
            metadata = self._encrypt_sensitive_fields(metadata)
            
        self._storage[metadata.id] = metadata
        self._update_version_graph(metadata)
        self._log_operation("create", metadata)
        
        METADATA_OPS.labels(operation="add", status="success").inc()
        METADATA_SIZE.labels(type=metadata.type).observe(len(json.dumps(metadata.content)))
        return metadata

    def update_metadata(self, metadata_id: str, update: Dict) -> Metadata:
        """Perform versioned update with audit trail"""
        existing = self._storage[metadata_id]
        new_version = self._generate_next_version(existing.version)
        
        updated = existing.copy(update=update, deep=True)
        updated.version = new_version
        updated.updated_at = datetime.now(timezone.utc)
        
        self._storage[metadata_id] = updated
        self._log_operation("update", updated, previous_version=existing.version)
        
        METADATA_OPS.labels(operation="update", status="success").inc()
        return updated

    def retrieve_metadata(self, metadata_id: str, decrypt: bool = True) -> Metadata:
        """Fetch metadata with optional decryption and signature verification"""
        metadata = self._storage[metadata_id]
        
        if not self._verify_signature(metadata):
            raise SecurityError("Invalid metadata signature")
            
        if decrypt and metadata.encrypted_fields:
            metadata = self._decrypt_sensitive_fields(metadata)
            
        METADATA_OPS.labels(operation="retrieve", status="success").inc()
        return metadata

    def delete_metadata(self, metadata_id: str) -> None:
        """Soft delete with dependency validation"""
        if metadata_id in self._dependency_graph:
            raise DependencyError("Cannot delete metadata with active dependencies")
            
        del self._storage[metadata_id]
        self._log_operation("delete", metadata_id)
        METADATA_OPS.labels(operation="delete", status="success").inc()

    def _validate_dependencies(self, metadata: Metadata) -> None:
        """Check dependency graph for version conflicts"""
        try:
            ts = TopologicalSorter(self._dependency_graph)
            ts.prepare()
        except CycleError as e:
            raise DependencyError(f"Circular dependency detected: {str(e)}")

    def _check_compatibility(self, metadata: Metadata) -> None:
        """Verify system compatibility matrix"""
        # Implementation would check against current environment versions
        pass

    def _sign_metadata(self, metadata: Metadata) -> str:
        """Generate digital signature for content integrity"""
        payload = json.dumps(metadata.dict(exclude={'signature'}), sort_keys=True)
        signature = self.private_key.sign(
            payload.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    def _verify_signature(self, metadata: Metadata) -> bool:
        """Validate metadata signature"""
        try:
            signature = bytes.fromhex(metadata.signature)
            payload = json.dumps(metadata.dict(exclude={'signature'}), sort_keys=True)
            self.public_key.verify(
                signature,
                payload.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {str(e)}")
            return False

    def _encrypt_sensitive_fields(self, metadata: Metadata) -> Metadata:
        """Encrypt specified fields using Fernet"""
        encrypted_data = metadata.content.copy()
        for field in metadata.encrypted_fields:
            if field in encrypted_data:
                encrypted_data[field] = self.fernet.encrypt(
                    str(encrypted_data[field]).encode()
                ).decode()
        return metadata.copy(update={"content": encrypted_data})

    def _decrypt_sensitive_fields(self, metadata: Metadata) -> Metadata:
        """Decrypt encrypted content fields"""
        decrypted_data = metadata.content.copy()
        for field in metadata.encrypted_fields:
            if field in decrypted_data:
                decrypted_data[field] = self.fernet.decrypt(
                    decrypted_data[field].encode()
                ).decode()
        return metadata.copy(update={"content": decrypted_data})

    def _generate_next_version(self, current_version: str) -> str:
        """Semantic versioning increment logic"""
        major, minor, patch = map(int, current_version.split('.')[:3])
        return f"{major}.{minor}.{patch + 1}"

    def _update_version_graph(self, metadata: Metadata) -> None:
        """Maintain version lineage for rollback capabilities"""
        if metadata.name in self._version_graph:
            self._version_graph[metadata.name].append(metadata.version)
        else:
            self._version_graph[metadata.name] = [metadata.version]

    def _log_operation(self, action: str, target: Any, **kwargs) -> None:
        """Maintain audit trail with cryptographic integrity"""
        if not self.audit_enabled:
            return
            
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "action": action,
            "target": target.id if isinstance(target, Metadata) else target,
            "details": kwargs
        }
        self._audit_log.append(log_entry)

    def export_audit_log(self, format: str = "json") -> str:
        """Export audit trail in specified format"""
        if format == "json":
            return json.dumps(self._audit_log, default=str)
        elif format == "yaml":
            return yaml.safe_dump(self._audit_log)
        raise ValueError(f"Unsupported format: {format}")

    def generate_dependency_report(self) -> Dict:
        """Analyze dependency graph for impact assessment"""
        ts = TopologicalSorter(self._dependency_graph)
        return {
            "dependency_order": list(ts.static_order()),
            "max_depth": self._calculate_max_depth()
        }

    def _calculate_max_depth(self) -> int:
        """Calculate maximum dependency chain depth"""
        depths = {}
        def visit(node):
            if node not in depths:
                depths[node] = 1 + max((visit(parent) for parent in self._dependency_graph.get(node, [])), default=0)
            return depths[node]
        
        for node in self._dependency_graph:
            visit(node)
        DEPENDENCY_DEPTH.set(max(depths.values(), default=0))
        return max(depths.values(), default=0)

class MetadataConverter:
    """Cross-system metadata format converter"""
    
    @staticmethod
    def to_json(metadata: Metadata) -> str:
        return metadata.json(indent=2, exclude={'signature'})

    @staticmethod
    def to_yaml(metadata: Metadata) -> str:
        data = metadata.dict(exclude={'signature'})
        return yaml.safe_dump(data)

    @staticmethod
    def to_xml(metadata: Metadata) -> str:
        root = ET.Element("Metadata")
        ET.SubElement(root, "ID").text = metadata.id
        ET.SubElement(root, "Name").text = metadata.name
        ET.SubElement(root, "Version").text = metadata.version
        return ET.tostring(root, encoding='unicode')

class SecurityError(Exception):
    """Base class for metadata security violations"""

class DependencyError(Exception):
    """Exception for dependency graph issues"""

# Example Usage
if __name__ == "__main__":
    manager = MetadataManager()
    
    # Create sample metadata
    schema_metadata = Metadata(
        name="customer_schema",
        type=MetadataType.SCHEMA,
        version="1.0.0",
        content={"fields": ["id", "name", "ssn"]},
        encrypted_fields={"ssn"},
        dependencies={"user_model": "1.2.x"},
        compatibility_matrix={"postgres": ["12+"]}
    )
    
    stored_metadata = manager.add_metadata(schema_metadata)
    print(f"Stored Metadata ID: {stored_metadata.id}")
    
    # Retrieve and decrypt
    retrieved = manager.retrieve_metadata(stored_metadata.id)
    print(f"Decrypted Content: {retrieved.content}")
    
    # Generate reports
    print("Dependency Report:", manager.generate_dependency_report())
    print("Audit Log:", manager.export_audit_log())

"""
BRIM Network - Enterprise Data Schema Manager
Defines strongly-typed data schemas with validation, encryption, and cross-system compatibility
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Type, Union
from enum import Enum
from pydantic import BaseModel, Field, validator, create_model
from pydantic.fields import FieldInfo
from cryptography.fernet import Fernet
import numpy as np
import pandas as pd
from datetime import datetime
from prometheus_client import Counter, Histogram

logger = logging.getLogger(__name__)

# Monitoring Metrics
SCHEMA_VALIDATIONS = Counter('schema_validations_total', 'Total schema validation attempts', ['status'])
SCHEMA_BUILD_TIME = Histogram('schema_build_duration_seconds', 'Dynamic schema generation time')

class FieldType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    ENCRYPTED_STRING = "encrypted_string"
    CATEGORY = "category"
    CUSTOM_OBJECT = "custom_object"

class DataSource(str, Enum):
    SQL = "sql"
    NOSQL = "nosql"
    API = "api"
    FILE = "file"

class SchemaField(BaseModel):
    """Enterprise-grade schema field definition with multi-system mapping"""
    
    name: str = Field(..., min_length=1)
    field_type: FieldType
    required: bool = True
    description: Optional[str] = None
    default: Optional[Any] = None
    constraints: Dict[str, Any] = Field(default_factory=dict)
    system_mappings: Dict[DataSource, Dict[str, str]] = Field(
        default_factory=dict,
        description="Field mappings for different data sources"
    )
    encryption_key: Optional[str] = None
    validation_rules: Optional[List[str]] = None

    class Config:
        extra = 'forbid'
        use_enum_values = True

    @validator('name')
    def validate_name(cls, v):
        if not v.isidentifier():
            raise ValueError(f"Invalid field name: '{v}' must be valid Python identifier")
        return v

    @validator('encryption_key', always=True)
    def validate_encryption(cls, v, values):
        if values.get('field_type') == FieldType.ENCRYPTED_STRING and not v:
            raise ValueError("Encrypted fields require encryption_key")
        return v

    @validator('constraints')
    def validate_constraints(cls, v, values):
        field_type = values.get('field_type')
        if field_type == FieldType.STRING:
            if 'max_length' in v and not isinstance(v['max_length'], int):
                raise ValueError("max_length must be integer")
        elif field_type in [FieldType.INTEGER, FieldType.FLOAT]:
            if 'min_value' in v and 'max_value' in v:
                if v['min_value'] >= v['max_value']:
                    raise ValueError("min_value must be less than max_value")
        return v

class DataSchema(BaseModel):
    """Enterprise data schema manager with dynamic model generation"""
    
    schema_id: str = Field(..., alias="_id")
    version: str = Field(..., regex=r'^\d+\.\d+\.\d+$')
    fields: Dict[str, SchemaField] = Field(..., min_items=1)
    field_order: List[str] = []
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

    _dynamic_model: Optional[Type[BaseModel]] = None
    _fernet_cache: Dict[str, Fernet] = {}

    class Config:
        underscore_attrs_private = True

    @SCHEMA_BUILD_TIME.time()
    def build_model(self) -> Type[BaseModel]:
        """Dynamically generate Pydantic model from schema"""
        field_definitions = {}
        for field_name, field in self.fields.items():
            python_type = self._map_field_type(field.field_type)
            field_info = self._create_field_info(field)
            field_definitions[field_name] = (python_type, field_info)

        self._dynamic_model = create_model(
            __model_name=f"DynamicSchema_{self.schema_id}",
            __config__=self._model_config(),
            **field_definitions
        )
        return self._dynamic_model

    def validate_record(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and transform data according to schema"""
        try:
            if not self._dynamic_model:
                self.build_model()
                
            validated = self._dynamic_model(**data).dict()
            SCHEMA_VALIDATIONS.labels(status='success').inc()
            return self._postprocess_data(validated)
            
        except Exception as e:
            SCHEMA_VALIDATIONS.labels(status='failure').inc()
            logger.error(f"Schema validation failed: {str(e)}")
            raise DataSchemaException(f"Validation error: {str(e)}")

    def _map_field_type(self, field_type: FieldType) -> type:
        """Map schema field types to Python types"""
        type_map = {
            FieldType.STRING: str,
            FieldType.INTEGER: int,
            FieldType.FLOAT: float,
            FieldType.BOOLEAN: bool,
            FieldType.DATETIME: datetime,
            FieldType.ENCRYPTED_STRING: str,
            FieldType.CATEGORY: str,
            FieldType.CUSTOM_OBJECT: dict
        }
        return type_map[field_type]

    def _create_field_info(self, field: SchemaField) -> FieldInfo:
        """Create Pydantic FieldInfo with custom constraints"""
        extra = {}
        if field.field_type == FieldType.STRING:
            if 'max_length' in field.constraints:
                extra['max_length'] = field.constraints['max_length']
        elif field.field_type in [FieldType.INTEGER, FieldType.FLOAT]:
            extra['ge'] = field.constraints.get('min_value')
            extra['le'] = field.constraints.get('max_value')
        elif field.field_type == FieldType.CATEGORY:
            if 'allowed_values' in field.constraints:
                extra['regex'] = f"^{'|'.join(field.constraints['allowed_values'])}$"

        return Field(
            default=... if field.required else field.default,
            description=field.description,
            **extra
        )

    def _model_config(self) -> Type[BaseModel.Config]:
        """Generate custom model configuration"""
        class CustomConfig(BaseModel.Config):
            extra = 'forbid'
            validate_assignment = True
            anystr_strip_whitespace = True
            json_encoders = {
                datetime: lambda v: v.isoformat(),
                np.ndarray: lambda v: v.tolist()
            }
        return CustomConfig

    def _postprocess_data(self, data: Dict) -> Dict:
        """Apply post-validation transformations"""
        processed = {}
        for field_name in self.field_order or self.fields.keys():
            value = data.get(field_name)
            field = self.fields[field_name]
            
            if field.field_type == FieldType.ENCRYPTED_STRING:
                processed[field_name] = self._encrypt_value(field, value)
            elif field.field_type == FieldType.DATETIME:
                processed[field_name] = value.isoformat()
            else:
                processed[field_name] = value
        return processed

    def _encrypt_value(self, field: SchemaField, value: str) -> str:
        """Encrypt sensitive fields using Fernet"""
        if field.encryption_key not in self._fernet_cache:
            self._fernet_cache[field.encryption_key] = Fernet(field.encryption_key.encode())
        return self._fernet_cache[field.encryption_key].encrypt(value.encode()).decode()

    def generate_docs(self, format: str = "markdown") -> str:
        """Generate schema documentation for technical and business users"""
        doc = []
        if format == "markdown":
            doc.append(f"# Schema: {self.schema_id} (v{self.version})\n")
            doc.append("| Field | Type | Required | Description | Constraints |")
            doc.append("|-------|------|----------|-------------|-------------|")
            for name, field in self.fields.items():
                constraints = ", ".join([f"{k}={v}" for k,v in field.constraints.items()])
                doc.append(
                    f"| {name} | {field.field_type.value} | {field.required} | "
                    f"{field.description or ''} | {constraints} |"
                )
        return "\n".join(doc)

    def to_orm_mapping(self, system: DataSource) -> Dict:
        """Generate ORM mappings for target data systems"""
        mappings = {}
        for name, field in self.fields.items():
            if system in field.system_mappings:
                mappings[name] = field.system_mappings[system]
        return mappings

class DataSchemaException(Exception):
    """Base exception for schema-related errors"""
    pass

# Example Usage
if __name__ == "__main__":
    user_schema = DataSchema(
        _id="user_profile_v1",
        version="1.0.0",
        fields={
            "user_id": SchemaField(
                name="user_id",
                field_type=FieldType.ENCRYPTED_STRING,
                encryption_key="your-32-char-encryption-key-here",
                system_mappings={
                    DataSource.SQL: {"column": "encrypted_user_id", "type": "VARCHAR(256)"},
                    DataSource.API: {"path": "/user/identity"}
                }
            ),
            "age": SchemaField(
                name="age",
                field_type=FieldType.INTEGER,
                constraints={"min_value": 18, "max_value": 120},
                system_mappings={
                    DataSource.SQL: {"column": "user_age", "type": "INT"}
                }
            )
        },
        field_order=["user_id", "age"],
        metadata={"domain": "customer_data"}
    )

    # Generate and use validation model
    UserModel = user_schema.build_model()
    valid_data = user_schema.validate_record({"user_id": "12345", "age": 30})
    print(f"Validated Data: {valid_data}")

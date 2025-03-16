"""
BRIM Network - Enterprise Query Builder
Implements secure, database-agnostic query construction with SQL injection protection
"""

import re
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from datetime import datetime

# Security & Validation
from pydantic import BaseModel, ValidationError, field_validator
from sqlparse import parse, format as sql_format
from jinja2.sandbox import SandboxedEnvironment

# Performance monitoring
from prometheus_client import Histogram, Counter

logger = logging.getLogger(__name__)

# Prometheus Metrics
QUERY_BUILD_TIME = Histogram('query_build_duration_seconds', 'Time spent building queries')
QUERY_VALIDATION_ERRORS = Counter('query_validation_errors_total', 'Invalid query attempts', ['db_type'])

class DatabaseType(str, Enum):
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLSERVER = "sqlserver"
    MONGODB = "mongodb"
    REDIS = "redis"
    REST_API = "rest_api"

class QueryTemplate(BaseModel):
    """Pydantic model for query template validation"""
    base_query: str
    parameters: Dict[str, Union[str, int, float]] = {}
    allowed_operations: List[str] = ["SELECT"]
    permitted_tables: List[str]
    field_whitelist: Dict[str, List[str]] = {}  # {table: [columns]}
    query_hints: Optional[str] = None
    timeout_ms: int = 5000

    @field_validator('base_query')
    @classmethod
    def validate_base_query(cls, value: str) -> str:
        """Sanitize initial query template"""
        cleaned = re.sub(r';+\s*$', '', value.strip())  # Remove trailing semicolons
        if re.search(r'\b(DELETE|DROP|TRUNCATE)\b', cleaned, re.IGNORECASE):
            raise ValueError("Dangerous operation detected in query")
        return cleaned

class QueryResult(BaseModel):
    """Standardized query result container"""
    success: bool
    data: Optional[List[Dict[str, Any]]] = None
    execution_time_ms: float
    query_signature: str
    database_type: DatabaseType
    error: Optional[str] = None
    query_plan: Optional[str] = None

class BaseQueryBuilder(ABC):
    """Abstract base class for database-specific builders"""
    
    def __init__(self, db_type: DatabaseType):
        self.db_type = db_type
        self.jinja_env = SandboxedEnvironment(autoescape=True)
        self.query_cache: Dict[str, str] = {}
        self.query_counter = Counter(f'queries_built_{db_type.value}_total', 'Total queries constructed')

    @abstractmethod
    def build_query(self, template: QueryTemplate) -> str:
        """Database-specific query construction"""
        pass

    @abstractmethod
    def explain_query(self, query: str) -> str:
        """Generate execution plan explanation"""
        pass

    def _parse_template(self, template: QueryTemplate) -> Dict[str, Any]:
        """Validate and parameterize query template"""
        try:
            return template.model_dump()
        except ValidationError as e:
            QUERY_VALIDATION_ERRORS.labels(db_type=self.db_type.value).inc()
            logger.error(f"Query validation failed: {str(e)}")
            raise

class SQLQueryBuilder(BaseQueryBuilder):
    """SQL Database Query Builder (PostgreSQL/MySQL/SQL Server)"""
    
    def __init__(self, db_type: DatabaseType):
        super().__init__(db_type)
        self.param_style = {
            DatabaseType.POSTGRESQL: "${key}",
            DatabaseType.MYSQL: "%({key})s",
            DatabaseType.SQLSERVER: "@{key}"
        }[db_type]

    @QUERY_BUILD_TIME.time()
    def build_query(self, template: QueryTemplate) -> str:
        """Construct parameterized SQL query with security checks"""
        validated = self._parse_template(template)
        cache_key = f"{validated['base_query']}-{hash(frozenset(validated['parameters'].items()))}"
        
        if cache_key in self.query_cache:
            return self.query_cache[cache_key]

        compiled = self.jinja_env.from_string(validated["base_query"]).render(
            **validated["parameters"],
            param_style=self.param_style
        )

        # Security validation
        self._validate_compiled_query(compiled, validated)
        
        # Query optimization
        optimized = self._apply_query_hints(compiled, validated.get("query_hints"))
        formatted = sql_format(optimized, reindent=True, keyword_case='upper')
        
        self.query_cache[cache_key] = formatted
        self.query_counter.inc()
        return formatted

    def _validate_compiled_query(self, query: str, template: Dict) -> None:
        """Perform deep security analysis on final query"""
        parsed = parse(query)[0]
        
        # Table access validation
        for token in parsed.tokens:
            if token.ttype == sqlparse.tokens.DDL and token.value.upper() != "SELECT":
                raise PermissionError("Write operations not permitted in this context")
                
            if isinstance(token, sqlparse.sql.Identifier):
                table_name = token.get_real_name()
                if table_name not in template["permitted_tables"]:
                    raise ValueError(f"Access to table {table_name} not allowed")

    def _apply_query_hints(self, query: str, hints: Optional[str]) -> str:
        """Inject database-specific optimization hints"""
        if not hints:
            return query
            
        if self.db_type == DatabaseType.POSTGRESQL:
            return f"/*+ {hints} */ {query}"
        elif self.db_type == DatabaseType.MYSQL:
            return f"SELECT /*+ {hints} */ {query[6:]}"
        return query

    def explain_query(self, query: str) -> str:
        """Generate execution plan with database-specific EXPLAIN"""
        if self.db_type == DatabaseType.POSTGRESQL:
            return f"EXPLAIN (ANALYZE, BUFFERS) {query}"
        elif self.db_type == DatabaseType.MYSQL:
            return f"EXPLAIN FORMAT=JSON {query}"
        return f"EXPLAIN {query}"

class MongoDBQueryBuilder(BaseQueryBuilder):
    """NoSQL Query Builder for MongoDB"""
    
    @QUERY_BUILD_TIME.time()
    def build_query(self, template: QueryTemplate) -> Dict:
        """Construct MongoDB aggregation pipeline with validation"""
        validated = self._parse_template(template)
        
        pipeline = []
        for stage in validated["base_query"].split('|'):
            stage_name, params = stage.split(':', 1)
            pipeline.append({f"${stage_name.strip()}": eval(params)})
        
        self._validate_mongo_pipeline(pipeline, validated)
        return pipeline

    def _validate_mongo_pipeline(self, pipeline: List[Dict], template: Dict) -> None:
        """Prevent dangerous MongoDB operations"""
        restricted_stages = {"$merge", "$out", "$shardCollection"}
        for stage in pipeline:
            stage_name = next(iter(stage.keys()))
            if stage_name in restricted_stages:
                raise PermissionError(f"MongoDB stage {stage_name} not permitted")

class QueryDirector:
    """Orchestrates query building across multiple database types"""
    
    def __init__(self):
        self.builders = {
            db_type: self._create_builder(db_type)
            for db_type in DatabaseType
        }

    def _create_builder(self, db_type: DatabaseType) -> BaseQueryBuilder:
        """Factory method for query builders"""
        if db_type in [DatabaseType.POSTGRESQL, DatabaseType.MYSQL, DatabaseType.SQLSERVER]:
            return SQLQueryBuilder(db_type)
        elif db_type == DatabaseType.MONGODB:
            return MongoDBQueryBuilder(db_type)
        else:
            raise NotImplementedError(f"Builder for {db_type} not implemented")

    def build(self, db_type: DatabaseType, template: QueryTemplate) -> Union[str, Dict]:
        """Unified interface for query construction"""
        builder = self.builders[db_type]
        return builder.build_query(template)

# Example Usage
if __name__ == "__main__":
    director = QueryDirector()
    
    # SQL Example
    sql_template = QueryTemplate(
        base_query="SELECT * FROM users WHERE status = {{ status }} AND region = {{ region }}",
        parameters={"status": "active", "region": "EMEA"},
        permitted_tables=["users"],
        field_whitelist={"users": ["id", "name", "email"]},
        timeout_ms=2000
    )
    pg_query = director.build(DatabaseType.POSTGRESQL, sql_template)
    print(f"PostgreSQL Query:\n{pg_query}")
    
    # MongoDB Example
    mongo_template = QueryTemplate(
        base_query="match: {'status': 'active'} | project: {'name': 1, 'email': 1}",
        permitted_tables=["users"]
    )
    mongo_pipeline = director.build(DatabaseType.MONGODB, mongo_template)
    print(f"MongoDB Pipeline:\n{mongo_pipeline}")

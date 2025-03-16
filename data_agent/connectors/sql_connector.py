"""
Enterprise SQL connector with connection pooling and query auditing
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
import sqlalchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import URL
from sqlalchemy.pool import QueuePool
from prometheus_client import Counter, Histogram
import logging

logger = logging.getLogger(__name__)

SQL_QUERY_COUNT = Counter('sql_queries_total', 'Total SQL queries executed', ['operation'])
SQL_QUERY_TIME = Histogram('sql_query_duration_seconds', 'SQL query execution time')

class SQLConfig(BaseModel):
    dialect: str = "postgresql"
    host: str
    port: int = 5432
    database: str
    username: str
    password: str = Field(..., min_length=12)
    pool_size: int = 10
    max_overflow: int = 5
    encryption_key: str

class SQLConnector:
    
    def __init__(self, config: SQLConfig):
        self.engine = create_engine(
            URL.create(
                drivername=config.dialect,
                username=config.username,
                password=config.password,
                host=config.host,
                port=config.port,
                database=config.database
            ),
            poolclass=QueuePool,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_recycle=3600
        )
        self.fernet = Fernet(config.encryption_key.encode())
        self._verify_connection()

    @SQL_QUERY_TIME.time()
    def execute_query(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        SQL_QUERY_COUNT.labels(operation=self._detect_operation_type(query)).inc()
        
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(query), parameters=params).mappings().all()
                self._audit_query(query, params)
                return [dict(row) for row in result]
                
        except sqlalchemy.exc.SQLAlchemyError as e:
            logger.error(f"Query failed: {str(e)}")
            raise DataAgentException("SQL execution error")

    def _detect_operation_type(self, query: str) -> str:
        query = query.strip().lower()
        return "read" if query.startswith("select") else "write" if query.startswith(("insert","update","delete")) else "other"

    def _audit_query(self, query: str, params: Optional[Dict]):
        encrypted_query = self.fernet.encrypt(query.encode()).decode()
        logger.info(f"Audit log - Encrypted query: {encrypted_query}, Params: {params}")

    def _verify_connection(self):
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as e:
            logger.critical(f"Database connection failed: {str(e)}")
            raise DataAgentException("Database connection failure")

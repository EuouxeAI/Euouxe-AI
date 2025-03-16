"""
MongoDB connector with TLS support and document validation
"""

from pymongo import MongoClient
from pymongo.errors import PyMongoError
from pydantic import BaseModel
import ssl

class NoSQLConfig(BaseModel):
    uri: str
    tls_ca_file: str
    tls_cert_key_file: str
    auth_source: str = "admin"
    document_validation: bool = True

class NoSQLConnector:
    
    def __init__(self, config: NoSQLConfig):
        self.client = MongoClient(
            config.uri,
            ssl=True,
            ssl_ca_certs=config.tls_ca_file,
            ssl_certfile=config.tls_cert_key_file,
            authSource=config.auth_source,
            document_class=dict,
            connectTimeoutMS=5000
        )
        
    def insert_document(self, db: str, collection: str, document: dict):
        try:
            return self.client[db][collection].insert_one(
                document,
                bypass_document_validation=not config.document_validation
            )
        except PyMongoError as e:
            raise DataAgentException(f"MongoDB operation failed: {str(e)}")

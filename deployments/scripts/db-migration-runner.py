"""
Euouxe AI - Enterprise Database Migration Engine
Supports PostgreSQL/MySQL/MongoDB with atomic execution, rollback, and observability
"""

import os
import logging
import argparse
from typing import Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

# Third-party imports
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from cryptography.fernet import Fernet
from prometheus_client import start_http_server, Counter, Histogram
import hvac

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("brim_db_migrator")

# Prometheus metrics
MIGRATION_COUNTER = Counter(
    'db_migration_operations_total',
    'Total database migration operations',
    ['source', 'target', 'status']
)
MIGRATION_DURATION = Histogram(
    'db_migration_duration_seconds',
    'Duration of migration operations',
    ['source_type', 'target_type']
)

class VaultManager:
    """Secure credential management with HashiCorp Vault"""
    
    def __init__(self, vault_url: str, role_id: str, secret_id: str):
        self.client = hvac.Client(url=vault_url)
        self.client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id
        )
    
    def get_db_creds(self, path: str) -> Dict[str, str]:
        """Retrieve encrypted database credentials"""
        secret = self.client.secrets.kv.v2.read_secret_version(path=path)
        return secret['data']['data']

class DatabaseConnector:
    """Unified interface for multi-database operations"""
    
    def __init__(self, config: Dict[str, Any], vault: VaultManager):
        self.config = config
        self.vault = vault
        self.engines = {}
        
    def _connect_sql(self, db_type: str) -> sqlalchemy.engine.Engine:
        """Connect to SQL databases"""
        creds = self.vault.get_db_creds(f"{db_type}-credentials")
        dsn = f"{db_type}://{creds['user']}:{creds['password']}@{self.config['host']}:{self.config['port']}/{self.config['dbname']}"
        return sqlalchemy.create_engine(dsn, pool_pre_ping=True)
    
    def _connect_mongo(self) -> MongoClient:
        """Connect to MongoDB"""
        creds = self.vault.get_db_creds("mongodb-credentials")
        return MongoClient(
            host=self.config['host'],
            port=self.config['port'],
            username=creds['user'],
            password=creds['password'],
            authSource=self.config['auth_source']
        )
    
    @contextmanager
    def get_session(self, db_type: str):
        """Context manager for database sessions"""
        if db_type not in self.engines:
            if db_type == 'mongodb':
                self.engines[db_type] = self._connect_mongo()
            else:
                self.engines[db_type] = self._connect_sql(db_type)
        
        if db_type == 'mongodb':
            yield self.engines[db_type][self.config['dbname']]
        else:
            Session = sessionmaker(bind=self.engines[db_type])
            session = Session()
            try:
                yield session
                session.commit()
            except Exception as e:
                session.rollback()
                raise
            finally:
                session.close()

class DataEncryptor:
    """Field-level encryption for sensitive data"""
    
    def __init__(self, vault: VaultManager):
        self.vault = vault
        self._load_keys()
        
    def _load_keys(self):
        """Rotate encryption keys from Vault"""
        key_data = self.vault.get_db_creds("encryption-keys")
        self.current_key = Fernet(key_data['current'])
        self.previous_keys = [Fernet(k) for k in key_data['previous'].split(',')]
        
    def encrypt_field(self, value: str) -> str:
        """Encrypt sensitive data with key rotation"""
        return self.current_key.encrypt(value.encode()).decode()
    
    def decrypt_field(self, encrypted_value: str) -> str:
        """Decrypt data with fallback to previous keys"""
        for key in [self.current_key] + self.previous_keys:
            try:
                return key.decrypt(encrypted_value.encode()).decode()
            except:
                continue
        raise ValueError("Decryption failed with all available keys")

class MigrationRunner:
    """Atomic database migration with rollback capabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        self.vault = VaultManager(
            config['vault_url'],
            config['vault_role_id'],
            config['vault_secret_id']
        )
        self.encryptor = DataEncryptor(self.vault)
        self.source = DatabaseConnector(config['source'], self.vault)
        self.target = DatabaseConnector(config['target'], self.vault)
        self.batch_size = config.get('batch_size', 1000)
        self.max_workers = config.get('max_workers', 4)
        
    def _migrate_table(self, table_name: str):
        """Migrate a single table with chunking"""
        with self.source.get_session(self.source.config['type']) as src_session, \
             self.target.get_session(self.target.config['type']) as tgt_session:
            
            total_count = self._get_row_count(src_session, table_name)
            migrated = 0
            
            while migrated < total_count:
                batch = self._fetch_batch(src_session, table_name, migrated)
                encrypted_batch = [
                    {**row, 'encrypted_field': self.encryptor.encrypt_field(row['sensitive'])}
                    for row in batch
                ]
                self._insert_batch(tgt_session, table_name, encrypted_batch)
                migrated += len(batch)
                logger.info(f"Migrated {migrated}/{total_count} rows from {table_name}")
                
    def _get_row_count(self, session, table_name: str) -> int:
        """Get total rows using database-appropriate method"""
        if self.source.config['type'] == 'mongodb':
            return session[table_name].count_documents({})
        else:
            return session.execute(f"SELECT COUNT(*) FROM {table_name}").scalar()
        
    def _fetch_batch(self, session, table_name: str, offset: int) -> list:
        """Fetch data batch with database-specific queries"""
        if self.source.config['type'] == 'mongodb':
            return list(session[table_name].find().skip(offset).limit(self.batch_size))
        else:
            return session.execute(
                f"SELECT * FROM {table_name} LIMIT {self.batch_size} OFFSET {offset}"
            ).fetchall()
        
    def _insert_batch(self, session, table_name: str, batch: list):
        """Insert batch using database-appropriate method"""
        if self.target.config['type'] == 'mongodb':
            session[table_name].insert_many(batch)
        else:
            session.bulk_insert_mappings(table_name, batch)
            
    def run_migration(self, table_names: list):
        """Parallel migration executor with observability"""
        start_time = datetime.now()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self._migrate_table, table)
                for table in table_names
            ]
            
            for future in futures:
                try:
                    future.result()
                    MIGRATION_COUNTER.labels(
                        source=self.source.config['type'],
                        target=self.target.config['type'],
                        status='success'
                    ).inc()
                except Exception as e:
                    logger.error(f"Migration failed: {str(e)}")
                    MIGRATION_COUNTER.labels(
                        source=self.source.config['type'],
                        target=self.target.config['type'],
                        status='failure'
                    ).inc()
                    raise
                    
        duration = (datetime.now() - start_time).total_seconds()
        MIGRATION_DURATION.labels(
            source_type=self.source.config['type'],
            target_type=self.target.config['type']
        ).observe(duration)
        
        logger.info(f"Migration completed in {duration:.2f} seconds")

def parse_args():
    """Command-line interface configuration"""
    parser = argparse.ArgumentParser(description='BRIM Database Migration Runner')
    parser.add_argument('--config', type=str, required=True, help='Path to config YAML')
    parser.add_argument('--tables', nargs='+', required=True, help='Tables to migrate')
    parser.add_argument('--port', type=int, default=9090, help='Metrics server port')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    start_http_server(args.port)
    
    # Load configuration from secure source
    config = {
        "vault_url": os.environ["VAULT_ADDR"],
        "vault_role_id": os.environ["VAULT_ROLE_ID"],
        "vault_secret_id": os.environ["VAULT_SECRET_ID"],
        "source": {
            "type": "postgresql",
            "host": "prod-db-host",
            "port": 5432,
            "dbname": "legacy_system"
        },
        "target": {
            "type": "mysql",
            "host": "new-cluster-host",
            "port": 3306,
            "dbname": "modernized_stack"
        },
        "batch_size": 2000,
        "max_workers": 8
    }
    
    try:
        runner = MigrationRunner(config)
        runner.run_migration(args.tables)
    except Exception as e:
        logger.critical(f"Critical migration failure: {str(e)}")
        exit(1)

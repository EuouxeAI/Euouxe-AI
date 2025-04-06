"""
Euouxe AI - Enterprise SQL Connector Test Suite
Validates multi-database support, connection pooling, and security controls
"""

import unittest
import ssl
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import psycopg2
from brim.data.sql_connector import SQLConnector
from brim.exceptions import (
    DatabaseConnectionError,
    QueryExecutionError,
    SecurityViolationError
)

class TestSQLConnector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure multi-database test parameters
        cls.db_configs = {
            'postgresql': {
                'engine': 'postgresql',
                'host': 'db-host.prod',
                'port': 5432,
                'ssl_mode': 'verify-full',
                'ssl_cert': '/etc/ssl/certs/db-client.pem',
                'pool_size': 5
            },
            'mysql': {
                'engine': 'mysql',
                'host': 'mysql.prod',
                'port': 3306,
                'ssl_ca': '/etc/ssl/certs/mysql-ca.pem',
                'connect_timeout': 10
            }
        }

        # Create sample sensitive data
        cls.test_credentials = {
            'username': 'service_account',
            'password': 'encrypted:JWE_header.encrypted_key.iv.ciphertext.tag'
        }

    def setUp(self):
        # Mock database drivers
        self.pg_driver = MagicMock(spec=psycopg2.extensions.connection)
        self.mysql_driver = MagicMock()

        # Patch connection factories
        self.postgres_patcher = patch('psycopg2.connect', 
                                    return_value=self.pg_driver)
        self.mysql_patcher = patch('mysql.connector.connect',
                                 return_value=self.mysql_driver)
        
        self.postgres_mock = self.postgres_patcher.start()
        self.mysql_mock = self.mysql_patcher.start()

        # Initialize metrics collector
        self.metrics_mock = MagicMock()

    def tearDown(self):
        self.postgres_patcher.stop()
        self.mysql_patcher.stop()

    def test_01_secure_connection_establishment(self):
        """Validate TLS 1.3 encrypted connections"""
        for engine, config in self.db_configs.items():
            with self.subTest(engine=engine):
                connector = SQLConnector(
                    config=config,
                    credentials=self.test_credentials,
                    security_policies={
                        'min_tls_version': ssl.TLSVersion.TLSv1_3,
                        'cert_revocation_check': True
                    }
                )
                
                # Verify SSL context configuration
                connector.connect()
                if engine == 'postgresql':
                    self.postgres_mock.assert_called_with(
                        sslmode='verify-full',
                        sslrootcert=config['ssl_cert'],
                        ssl_min_protocol_version=ssl.TLSVersion.TLSv1_3
                    )
                elif engine == 'mysql':
                    self.mysql_mock.assert_called_with(
                        ssl_ca=config['ssl_ca'],
                        ssl_verify_cert=True
                    )

    def test_02_connection_pool_management(self):
        """Validate pool recycling and max connections"""
        config = self.db_configs['postgresql']
        connector = SQLConnector(
            config=config,
            credentials=self.test_credentials,
            security_policies={'max_pool_size': 5}
        )

        # Acquire all connections
        connections = [connector.get_connection() for _ in range(5)]
        
        # Test pool exhaustion
        with self.assertRaises(DatabaseConnectionError) as cm:
            connector.get_connection(timeout=1)
        self.assertEqual(cm.exception.error_code, 'pool_exhausted')

        # Release and reuse
        connector.release_connection(connections[0])
        reused_conn = connector.get_connection()
        self.assertEqual(reused_conn, connections[0])

    def test_03_query_execution_safety(self):
        """Validate SQL injection prevention"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            security_policies={'allow_parameterized': True}
        )

        # Parameterized query test
        safe_query = "SELECT * FROM users WHERE id = %s"
        connector.execute_query(safe_query, params=(123,))
        self.pg_driver.cursor().execute.assert_called_with(safe_query, (123,))

        # Block direct value interpolation
        unsafe_query = "SELECT * FROM users WHERE id = 123"
        with self.assertRaises(SecurityViolationError) as cm:
            connector.execute_query(unsafe_query)
        self.assertEqual(cm.exception.violation_type, 'unsafe_query')

    @patch('brim.data.sql_connector.statsd')
    def test_04_performance_metrics(self, statsd_mock):
        """Validate query telemetry collection"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            metrics_client=self.metrics_mock
        )

        # Execute mock query
        test_query = "SELECT * FROM audit_log"
        connector.execute_query(test_query)

        # Verify metrics
        self.metrics_mock.timer.assert_called_with('sql.query_duration')
        self.metrics_mock.increment.assert_called_with('sql.queries_executed')

    def test_05_transaction_management(self):
        """Validate ACID compliance"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials
        )

        # Test successful commit
        with connector.transaction() as tx:
            tx.execute("UPDATE accounts SET balance = balance - 100")
            tx.execute("UPDATE ledgers SET amount = amount + 100")
        self.pg_driver.commit.assert_called_once()

        # Test rollback
        with self.assertRaises(QueryExecutionError):
            with connector.transaction():
                raise Exception("Forced rollback")
        self.pg_driver.rollback.assert_called_once()

    def test_06_failure_resilience(self):
        """Validate connection recovery"""
        # Force connection failure
        self.postgres_mock.side_effect = psycopg2.OperationalError
        
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            retry_policy={'max_attempts': 3, 'backoff': 0.1}
        )

        with self.assertRaises(DatabaseConnectionError) as cm:
            connector.get_connection()
        self.assertEqual(cm.exception.retry_count, 3)
        self.assertEqual(self.postgres_mock.call_count, 3)

    def test_07_credential_rotation(self):
        """Validate secret rotation handling"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            security_policies={'secret_ttl': 3600}
        )

        # Force credential expiration
        connector._credential_expiry = datetime.utcnow() - timedelta(hours=1)
        
        with self.assertRaises(SecurityViolationError) as cm:
            connector.execute_query("SELECT 1")
        self.assertEqual(cm.exception.violation_type, 'expired_credentials')

    def test_08_schema_migration(self):
        """Validate DDL execution safety"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            security_policies={'allow_ddl': False}
        )

        with self.assertRaises(SecurityViolationError) as cm:
            connector.execute_query("ALTER TABLE users ADD COLUMN test INT")
        self.assertEqual(cm.exception.violation_type, 'ddl_blocked')

    @patch('brim.data.sql_connector.logging')
    def test_09_audit_logging(self, logging_mock):
        """Validate sensitive operation logging"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            security_policies={'audit_sensitive_queries': True}
        )

        connector.execute_query("DELETE FROM users WHERE id = 123")
        
        logging_mock.audit.assert_called_with(
            "Sensitive SQL operation",
            extra={
                'query_type': 'DELETE',
                'table_affected': 'users',
                'query_hash': connector._hash_query("DELETE FROM users WHERE id = 123")
            }
        )

    def test_10_large_result_handling(self):
        """Validate streaming/cursor management"""
        connector = SQLConnector(
            config=self.db_configs['postgresql'],
            credentials=self.test_credentials,
            security_policies={'max_result_size': 1024}
        )

        # Configure mock cursor with large dataset
        mock_cursor = self.pg_driver.cursor.return_value
        mock_cursor.fetchmany.side_effect = [
            [{'data': 'x'*512}] * 2,
            [{'data': 'x'*512}] * 2,
            []
        ]

        with self.assertRaises(QueryExecutionError) as cm:
            list(connector.stream_query("SELECT large_data FROM datasets"))
        self.assertEqual(cm.exception.error_code, 'result_size_exceeded')

if __name__ == "__main__":
    unittest.main(
        verbosity=2,
        failfast=False,
        buffer=True,
        catchbreak=True
    )

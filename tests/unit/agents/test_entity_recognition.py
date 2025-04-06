"""
Euouxe AI - Enterprise Entity Recognition Test Suite
Validates multi-model NER pipeline, PII detection, and cross-language entity resolution
"""

import unittest
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import numpy as np
from brim.nlp.entity_recognition import EntityRecognizer
from brim.exceptions import (
    EntityResolutionError,
    SensitiveDataExposure,
    ModelVersionConflict
)

class TestEntityRecognition(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize multi-model test environment
        cls.ner_models = {
            'financial': MagicMock(),
            'medical': MagicMock(),
            'geopolitical': MagicMock()
        }
        
        # Configure model responses
        cls.ner_models['financial'].extract.return_value = [
            {'text': '\$1500', 'type': 'AMOUNT', 'start': 10, 'end': 15},
            {'text': 'ACC-98765', 'type': 'ACCOUNT_ID', 'start': 30, 'end': 39}
        ]
        
        # Load cross-language test dataset
        with open('tests/data/multilingual_entities.json') as f:
            cls.cross_lingual_cases = json.load(f)
        
        # Redaction patterns
        cls.sensitive_patterns = [
            ("Credit card: 4111-1111-1111-1111", "CREDIT_CARD"),
            ("Patient ID: 123-45-6789", "SSN"),
            ("API_KEY: sk-live-abc123xyz456", "API_KEY")
        ]

    def setUp(self):
        # Create recognizer with security controls
        self.recognizer = EntityRecognizer(
            models=self.ner_models,
            security_policies={
                'auto_redact': True,
                'allowed_entity_types': ['AMOUNT', 'DATE', 'LOCATION'],
                'pattern_groups': {
                    'CREDIT_CARD': r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b',
                    'SSN': r'\b\d{3}-\d{2}-\d{4}\b'
                }
            },
            context_window=timedelta(minutes=5)
        )
        self.test_start = datetime.utcnow()

    def test_01_basic_entity_extraction(self):
        """Validate core entity detection accuracy"""
        test_cases = [
            ("Wire \$2000 to IBAN GB33BUKB20201555555555", 
             [('AMOUNT', '\$2000'), ('IBAN', 'GB33BUKB20201555555555')]),
            ("Meeting in Paris on 2023-12-15",
             [('LOCATION', 'Paris'), ('DATE', '2023-12-15')])
        ]
        
        for text, expected in test_cases:
            with self.subTest(text=text):
                entities = self.recognizer.extract_entities(text)
                detected = [(e['type'], e['text']) for e in entities]
                self.assertCountEqual(detected, expected)

    def test_02_cross_lingual_support(self):
        """Validate entity recognition across languages"""
        for case in self.cross_lingual_cases:
            with self.subTest(lang=case['language']):
                entities = self.recognizer.extract_entities(
                    text=case['text'],
                    language=case['language']
                )
                detected_types = {e['type'] for e in entities}
                self.assertSetEqual(detected_types, set(case['expected_types']))

    def test_03_sensitive_data_redaction(self):
        """Validate automatic PII detection and masking"""
        for text, pattern_type in self.sensitive_patterns:
            with self.subTest(pattern=pattern_type):
                entities = self.recognizer.extract_entities(text)
                sensitive_entities = [e for e in entities 
                                    if e['type'] == pattern_type]
                self.assertTrue(len(sensitive_entities) > 0)
                self.assertTrue(all(e['redacted'] for e in sensitive_entities))

    def test_04_context_aware_resolution(self):
        """Validate cross-sentence entity resolution"""
        # First sentence establishes context
        self.recognizer.extract_entities("Client reference: CN-2023-ABCD")
        
        # Subsequent reference
        entities = self.recognizer.extract_entities("Update status for CN-2023-ABCD")
        client_refs = [e for e in entities if e['type'] == 'CLIENT_REF']
        self.assertTrue(any(e['resolved'] for e in client_refs))

    @patch('brim.nlp.entity_recognition.psutil.Process')
    def test_05_memory_constraints(self, mock_process):
        """Validate memory protection mechanisms"""
        # Simulate memory overage
        mock_process.return_value.memory_info.return_value = Mock(rss=5*1024**3)  # 5GB
        
        with self.assertRaises(EntityResolutionError) as cm:
            self.recognizer.extract_entities("Process large document")
        self.assertIn("memory_limit_exceeded", str(cm.exception))

    def test_06_model_version_consistency(self):
        """Validate model version alignment"""
        with patch.dict(self.recognizer.model_versions, {'financial': 'v2.1.1'}):
            entities = self.recognizer.extract_entities("Transaction \$500")
            versions = {e['model_version'] for e in entities 
                       if e['model'] == 'financial'}
            self.assertEqual(versions, {'v2.1.1'})

    def test_07_concurrent_processing(self):
        """Validate thread safety under load"""
        from concurrent.futures import ThreadPoolExecutor
        
        test_texts = ["Invoice #INV-2023-{}".format(i) for i in range(100)]
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(
                lambda t: self.recognizer.extract_entities(t),
                test_texts
            ))
            
        invoice_counts = sum(
            1 for res in results 
            if any(e['type'] == 'INVOICE_ID' for e in res)
        )
        self.assertEqual(invoice_counts, 100)

    def test_08_entity_disambiguation(self):
        """Validate entity resolution accuracy"""
        test_cases = [
            ("Apple stock price", [('ORG', 'Apple Inc.')]),
            ("Apple pie recipe", [('PRODUCT', 'Apple Pie')])
        ]
        
        for text, expected in test_cases:
            with self.subTest(text=text):
                entities = self.recognizer.extract_entities(text)
                resolved = [(e['resolved_type'], e['resolved_value']) 
                          for e in entities if 'resolved_value' in e]
                self.assertCountEqual(resolved, expected)

    def test_09_audit_log_integrity(self):
        """Validate complete audit trail generation"""
        test_text = "Transfer from ACC-123 to ACC-456"
        entities = self.recognizer.extract_entities(test_text)
        
        log_entry = self.recognizer.audit_log[-1]
        self.assertEqual(log_entry['input_hash'], 
                        self.recognizer._hash_input(test_text))
        self.assertEqual(len(log_entry['entities']), len(entities))
        self.assertLessEqual(log_entry['processing_time'], 1.0)

    @patch('brim.nlp.entity_recognition.requests.post')
    def test_10_fallback_mechanism(self, mock_post):
        """Validate model failure recovery"""
        # Force primary model failure
        self.ner_models['financial'].extract.side_effect = Exception("GPU OOM")
        
        # Configure fallback service
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: [{"text": "\$500", "type": "AMOUNT"}]
        )
        
        entities = self.recognizer.extract_entities("Payment of \$500")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]['source'], 'fallback_service')

    def test_11_temporal_analysis(self):
        """Validate time-sensitive entity handling"""
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = datetime(2023, 1, 15)
            
            entities = self.recognizer.extract_entities(
                "Event scheduled for next Tuesday"
            )
            date_entities = [e for e in entities if e['type'] == 'DATE']
            self.assertEqual(date_entities[0]['normalized'], '2023-01-17')

    def test_12_invalid_input_handling(self):
        """Validate malformed input scenarios"""
        test_cases = [
            (None, "empty_input"),
            ("A"*1001, "input_length_exceeded"),
            (12345, "invalid_type")
        ]
        
        for input, expected_error in test_cases:
            with self.subTest(case=expected_error):
                with self.assertRaises(EntityResolutionError) as cm:
                    self.recognizer.extract_entities(input)
                self.assertEqual(cm.exception.error_code, expected_error)

if __name__ == "__main__":
    unittest.main(
        testRunner=unittest.TextTestRunner(
            verbosity=2,
            descriptions=True,
            resultclass=unittest.TextTestResult
        ),
        buffer=True,
        catchbreak=True
    )

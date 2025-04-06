"""
Euouxe AI - Enterprise Intent Detection Test Suite
Validates NLP pipeline, multilingual support, and adversarial input handling
"""

import unittest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from brim.nlp.intent_detection import IntentClassifier
from brim.exceptions import (
    IntentClassificationError,
    ContextExpiredError,
    SecurityPolicyViolation
)

class TestIntentDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize enterprise-grade test models
        cls.mock_model = MagicMock()
        cls.mock_model.predict.return_value = {
            'intent': 'transaction_query',
            'confidence': 0.92,
            'entities': {'account_id': 'ACC-12345'}
        }
        
        # Load multilingual test dataset
        with open('tests/data/multilingual_intents.json') as f:
            cls.multilingual_cases = json.load(f)
        
        # Security test patterns
        cls.adversarial_patterns = [
            ("SELECT * FROM users; DROP TABLE accounts;", "sql_injection"),
            ("<script>alert('XSS')</script>", "xss_attempt"),
            ("../../etc/passwd", "path_traversal")
        ]

    def setUp(self):
        # Fresh classifier with security policies
        self.classifier = IntentClassifier(
            model=self.mock_model,
            security_policies={
                "max_input_length": 500,
                "allowed_characters": r'[\w\s,.?!-]',
                "sensitive_patterns": [
                    r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"  # Credit card
                ]
            },
            context_window=timedelta(seconds=30)
        )
        self.start_time = time.time()

    def test_01_basic_intent_recognition(self):
        """Validate core intent classification accuracy"""
        test_cases = [
            ("Show my recent transactions", "transaction_query"),
            ("Transfer \$200 to savings", "fund_transfer"),
            ("Enable 2FA on my account", "security_settings")
        ]
        
        for text, expected_intent in test_cases:
            with self.subTest(text=text):
                result = self.classifier.detect_intent(text)
                self.assertEqual(result['intent'], expected_intent)
                self.assertGreaterEqual(result['confidence'], 0.85)

    def test_02_multilingual_support(self):
        """Validate intent detection across supported languages"""
        for case in self.multilingual_cases:
            with self.subTest(lang=case['language']):
                result = self.classifier.detect_intent(
                    text=case['text'],
                    language=case['language']
                )
                self.assertEqual(result['intent'], case['expected_intent'])
                self.assertIn('entities', result)

    def test_03_context_aware_dialogue(self):
        """Validate multi-turn conversation context handling"""
        # First query
        initial = self.classifier.detect_intent("Check account balance")
        self.assertEqual(initial['intent'], 'balance_inquiry')
        
        # Follow-up with context
        follow_up = self.classifier.detect_intent(
            "For my savings account",
            context_id=initial['context_id']
        )
        self.assertEqual(follow_up['entities']['account_type'], 'savings')

    def test_04_context_expiration(self):
        """Validate automatic context expiration"""
        # Create context
        result = self.classifier.detect_intent("View transaction history")
        context_id = result['context_id']
        
        # Simulate time passage
        with patch('time.time', return_value=self.start_time + 45):
            with self.assertRaises(ContextExpiredError):
                self.classifier.detect_intent(
                    "From last month",
                    context_id=context_id
                )

    def test_05_security_policy_enforcement(self):
        """Validate input sanitization and policy checks"""
        test_cases = [
            ("My card is 4111 1111 1111 1111", "sensitive_data_detected"),
            ("A" * 600, "input_length_violation"),
            ("User@123#Password", "invalid_characters")
        ]
        
        for text, expected_reason in test_cases:
            with self.subTest(reason=expected_reason):
                with self.assertRaises(SecurityPolicyViolation) as cm:
                    self.classifier.detect_intent(text)
                self.assertEqual(cm.exception.reason, expected_reason)

    def test_06_adversarial_input_handling(self):
        """Validate detection of security attack patterns"""
        for pattern, attack_type in self.adversarial_patterns:
            with self.subTest(attack=attack_type):
                with self.assertRaises(SecurityPolicyViolation):
                    self.classifier.detect_intent(pattern)

    @patch('brim.nlp.intent_detection.requests.post')
    def test_07_fallback_to_secondary_model(self, mock_post):
        """Validate model failover mechanism"""
        # Primary model failure
        self.mock_model.predict.side_effect = Exception("GPU memory error")
        
        # Mock fallback service
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {
                'intent': 'fallback_response',
                'confidence': 0.78
            }
        )
        
        result = self.classifier.detect_intent("System error 0xFA01")
        self.assertEqual(result['intent'], 'fallback_response')
        self.assertEqual(result['model_source'], 'secondary_api')

    def test_08_confidence_thresholds(self):
        """Validate confidence-based decision making"""
        self.mock_model.predict.return_value = {
            'intent': 'ambiguous_request',
            'confidence': 0.62
        }
        
        with self.assertRaises(IntentClassificationError):
            self.classifier.detect_intent(
                "Do something important",
                min_confidence=0.65
            )

    @patch('brim.nlp.intent_detection.psutil.Process')
    def test_09_resource_usage_monitoring(self, mock_process):
        """Validate memory/compute constraints"""
        # Simulate high memory usage
        mock_process.return_value.memory_info.return_value = Mock(rss=4_294_967_296)  # 4GB
        
        with self.assertRaises(IntentClassificationError) as cm:
            self.classifier.detect_intent("Analyze large dataset")
        self.assertIn("resource_exhausted", str(cm.exception))

    def test_10_audit_log_generation(self):
        """Validate audit trail integrity"""
        test_text = "Initiate wire transfer to account 12345"
        result = self.classifier.detect_intent(test_text)
        
        audit_entry = self.classifier.audit_log[-1]
        self.assertEqual(audit_entry['input_hash'], 
                        self.classifier._hash_input(test_text))
        self.assertEqual(audit_entry['detected_intent'], result['intent'])
        self.assertIsNotNone(audit_entry['timestamp'])

    def test_11_concurrent_processing(self):
        """Validate thread-safety under load"""
        from concurrent.futures import ThreadPoolExecutor
        
        test_requests = ["Check balance"] * 100 + ["Transfer funds"] * 100
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(
                lambda x: self.classifier.detect_intent(x),
                test_requests
            ))
            
        balances = sum(1 for r in results if r['intent'] == 'balance_inquiry')
        transfers = sum(1 for r in results if r['intent'] == 'fund_transfer')
        self.assertEqual(balances, 100)
        self.assertEqual(transfers, 100)

    def test_12_model_version_handling(self):
        """Validate model version compatibility checks"""
        with patch.dict(self.classifier.model_versions, {'primary': 'v2.1.3'}):
            result = self.classifier.detect_intent("What's new in v2?")
            self.assertEqual(result['model_version'], 'v2.1.3')
            self.assertIn('model_version', self.classifier.audit_log[-1])

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

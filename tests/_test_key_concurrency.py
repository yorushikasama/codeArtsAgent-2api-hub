"""Unit tests for per-key concurrency limits (#359)."""
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_settings
import ca_proxy

class KeyConcurrencyTests(unittest.TestCase):
    def test_clean_key_entry_defaults_to_zero(self):
        entry = ca_settings._clean_key_entry({"name": "test", "key": "k-123"})
        self.assertEqual(entry["concurrency_limit"], 0)

        entry2 = ca_settings._clean_key_entry({"name": "test", "key": "k-456", "concurrency_limit": "5"})
        self.assertEqual(entry2["concurrency_limit"], 5)

        entry3 = ca_settings._clean_key_entry({"name": "test", "key": "k-789", "concurrency_limit": "-2"})
        self.assertEqual(entry3["concurrency_limit"], 0)

    def test_acquire_and_release_key_slot(self):
        key = {"id": "key-test-1", "concurrency_limit": 2}
        
        ok1, cur1, lim1 = ca_proxy._acquire_key_slot(key)
        self.assertTrue(ok1)
        self.assertEqual(cur1, 1)

        ok2, cur2, lim2 = ca_proxy._acquire_key_slot(key)
        self.assertTrue(ok2)
        self.assertEqual(cur2, 2)

        ok3, cur3, lim3 = ca_proxy._acquire_key_slot(key)
        self.assertFalse(ok3)

        ca_proxy._release_key_slot(key)
        ok4, cur4, lim4 = ca_proxy._acquire_key_slot(key)
        self.assertTrue(ok4)
        self.assertEqual(cur4, 2)

        ca_proxy._release_key_slot(key)
        ca_proxy._release_key_slot(key)
        self.assertNotIn("key-test-1", ca_proxy._key_active_concurrency)

    def test_unlimited_key_never_blocks(self):
        key = {"id": "key-test-0", "concurrency_limit": 0}
        for _ in range(10):
            ok, cur, lim = ca_proxy._acquire_key_slot(key)
            self.assertTrue(ok)
        ca_proxy._release_key_slot(key)
        self.assertNotIn("key-test-0", ca_proxy._key_active_concurrency)

if __name__ == "__main__":
    unittest.main()

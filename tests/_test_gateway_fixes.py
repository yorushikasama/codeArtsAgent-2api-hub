"""Tests for gateway_hint 413 and GPT max_tokens clamping."""
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_proxy

class GatewayFixesTest(unittest.TestCase):
    def test_gateway_hint_413(self):
        hint = ca_proxy.gateway_hint(413, "payload too large (20375735 bytes > 16777216 limit)")
        self.assertIn("WB_MAX_PAYLOAD_BYTES", hint)
        self.assertIn("raise it and restart", hint)

    def test_gpt_max_tokens_clamping(self):
        # 钳制随 build_upstream_body 退役移植进了 _codearts_max_tokens（活入口）
        self.assertEqual(
            ca_proxy._codearts_max_tokens({"model": "gpt-6-luna", "max_tokens": 1}), 16)
        self.assertEqual(
            ca_proxy._codearts_max_tokens(
                {"model": "deepseek-v4.1-flash", "max_tokens": 1}), 1)
        self.assertEqual(
            ca_proxy._codearts_max_tokens({"model": "gpt-6.1-sol", "max_tokens": 32}), 32)

if __name__ == "__main__":
    unittest.main()

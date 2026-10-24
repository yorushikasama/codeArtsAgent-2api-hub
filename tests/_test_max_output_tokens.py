"""Tests for defaulting max_tokens from model catalog (issue #121)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_proxy as P


class MaxOutputTokensTests(unittest.TestCase):
    def test_responses_to_chat_defaults_max_output_tokens(self):
        # When Codex / Responses API omits max_output_tokens, deepseek-v4.1-flash
        # gets 128000 from the catalog instead of letting upstream truncate at 32k.
        payload = {"model": "deepseek-v4.1-flash", "input": "hello"}
        chat = P.responses_to_chat(payload)
        self.assertEqual(chat.get("max_tokens"), 128000)

    def test_responses_to_chat_honors_explicit_max_output_tokens(self):
        payload = {
            "model": "deepseek-v4.1-flash",
            "input": "hello",
            "max_output_tokens": 4096,
        }
        chat = P.responses_to_chat(payload)
        self.assertEqual(chat.get("max_tokens"), 4096)

    def test_codearts_max_tokens_defaults_to_catalog_limit(self):
        # build_upstream_body 退役后，缺省/别名/钳制的活口径都是
        # _codearts_max_tokens（缺省 = 目录输出上限，deepseek 是 65536）。
        self.assertEqual(
            P._codearts_max_tokens({"model": "deepseek-v4.1-flash"}), 65536)

    def test_codearts_max_tokens_honors_explicit_value(self):
        self.assertEqual(
            P._codearts_max_tokens(
                {"model": "deepseek-v4.1-flash", "max_tokens": 2048}), 2048)

    def test_codearts_max_tokens_honors_max_completion_tokens(self):
        self.assertEqual(
            P._codearts_max_tokens(
                {"model": "deepseek-v4.1-flash",
                 "max_completion_tokens": 8192}), 8192)

    def test_unknown_model_falls_back_to_4096(self):
        # 表里没有的模型不猜目录值，退回 4096 兜底。
        self.assertEqual(
            P._codearts_max_tokens(
                {"model": "unrecognized-custom-model"}), 4096)

    def test_model_default_max_output_tokens_lookup(self):
        self.assertEqual(
            P.model_default_max_output_tokens("deepseek-v4.1-flash"), 128000
        )
        # gpt-6-astra 只在国际版目录里，随该区域一并删除；国内版目录里
        # 的 glm-5.3 仍带同样的默认值，用它继续守住这条查找。
        self.assertEqual(P.model_default_max_output_tokens("glm-5.3"), 48000)
        self.assertIsNone(P.model_default_max_output_tokens("non-existent-model"))


if __name__ == "__main__":
    unittest.main()


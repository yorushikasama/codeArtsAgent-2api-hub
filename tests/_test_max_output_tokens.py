"""Tests for defaulting max_tokens from model catalog (issue #121).

2026-11-03：原先这里有两条断言写的是 ``128000``（deepseek）与 ``48000``
（glm-5.3），那是 WorkBuddy 静态目录 ``ca_catalog.STATIC_MODELS`` 的值 ——
CodeArts 对这两个模型的真实输出上限都是 **65536**（``BUILTIN_MODEL_LIMITS``，
也与上游 AgentCenter 的 ``max_tokens`` 一致）。同一个文件里上一节已经断言
deepseek 是 65536，两条自相矛盾；``ca_catalog`` 删除后统一按码道真值。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_proxy as P


class MaxOutputTokensTests(unittest.TestCase):
    def test_responses_to_chat_defaults_max_output_tokens(self):
        # When Codex / Responses API omits max_output_tokens, deepseek-v4.1-flash
        # gets the CodeArts output cap (65536) instead of letting upstream
        # truncate at its own default.
        payload = {"model": "deepseek-v4.1-flash", "input": "hello"}
        chat = P.responses_to_chat(payload)
        self.assertEqual(chat.get("max_tokens"), 65536)

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
        # 码道真值：这两个模型的输出上限都是 65536（与上游 AgentCenter 一致）。
        self.assertEqual(
            P.model_default_max_output_tokens("deepseek-v4.1-flash"), 65536
        )
        self.assertEqual(P.model_default_max_output_tokens("glm-5.3"), 65536)
        self.assertIsNone(P.model_default_max_output_tokens("non-existent-model"))
        # 非码道模型不再回落到 WorkBuddy 静态目录（ca_catalog 已删）。
        self.assertIsNone(P.model_default_max_output_tokens("hy3"))


if __name__ == "__main__":
    unittest.main()


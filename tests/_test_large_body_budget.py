"""大 body 的建连预算按体积放宽（2026-11-15 线上事故修复的另一半）。

## 事故是什么

21:00–23:00 之间 26 次 502，全部是链路层异常（``write operation timed out``
15 次、``EOF occurred in violation of protocol`` 6 次、nginx 502 五例），上游
一次明确拒绝都没有。同期 body < 100k 字符的小请求 1187 个**零失败**。

失败请求的时间线（线上实测）：

    start +0s -> write timeout +127s -> budget exhausted +231s -> error

一次失败的尝试就吃掉 127 秒 —— 因为 ``urlopen`` 的 socket 全局超时同时管
「写 body」和「等响应头」，上游读超大 body 要 9~21 秒，这些秒数从「等响应
头」的 120 秒里扣，扣到 socket 超时就报 ``write operation timed out``。

而 ``CODEARTS_OPEN_BUDGET`` 是 210 秒（按「一次 0203 要 60 秒」算的：三次
完整尝试）。一次写超时就把预算吃掉大半，**根本来不及试第二轮**。

## 这些用例钉住的行为

  · body < 1MB → 预算就是默认的 210 秒（不改变既有行为）；
  · body ≥ 1MB → 预算按倍数放宽，给大请求第二次机会；
  · 放宽有上限（3 倍），不会让一个卡死的请求无限拖下去；
  · 体积估算对 tools schema 与 tool_calls 参数都算进去（它们都在 body 里）。
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_proxy
import ca_stream


def _messages(content_len):
    return [{"role": "user", "content": "x" * content_len}]


class BodySizeTests(unittest.TestCase):
    def test_estimates_plain_content(self):
        payload = {"model": "glm-5.3"}
        size = ca_proxy._codearts_body_bytes(payload, _messages(1000))
        self.assertGreaterEqual(size, 1000)

    def test_counts_tool_calls_arguments(self):
        """assistant 的 tool_calls 参数在 body 里 —— 一次 write_file 能带
        上百 KB，只数 content 会把请求看成「只有 30K 字符」。"""
        messages = [{"role": "assistant", "content": None,
                     "tool_calls": [{"id": "c1", "type": "function",
                                     "function": {"name": "write_file",
                                                  "arguments": "p" * 50000}}]}]
        size = ca_proxy._codearts_body_bytes({"model": "m"}, messages)
        self.assertGreater(size, 50000)

    def test_counts_tools_schema(self):
        """工具 schema 也在 body 里（66 个 MCP 工具轻松上百 KB）。"""
        tools = [{"type": "function", "function": {"name": "f%d" % i,
                                                   "description": "d" * 2000}}
                 for i in range(10)]
        size = ca_proxy._codearts_body_bytes({"model": "m", "tools": tools},
                                              _messages(100))
        self.assertGreater(size, 20000)

    def test_tolerates_junk(self):
        for messages in (None, [], [None], ["x"], [{}]):
            size = ca_proxy._codearts_body_bytes({"model": "m"}, messages)
            self.assertGreaterEqual(size, 0)


class OpenBudgetTests(unittest.TestCase):
    def test_small_body_keeps_default_budget(self):
        payload = {"model": "glm-5.3"}
        budget, size = ca_proxy._codearts_open_budget_for(
            payload, _messages(1000))
        self.assertEqual(budget, ca_proxy.CODEARTS_OPEN_BUDGET)
        self.assertLess(size, ca_proxy.CODEARTS_LARGE_BODY_BYTES)

    def test_large_body_gets_more_budget(self):
        payload = {"model": "glm-5.3"}
        big = _messages(ca_proxy.CODEARTS_LARGE_BODY_BYTES + 5000)
        budget, size = ca_proxy._codearts_open_budget_for(payload, big)
        self.assertGreater(budget, ca_proxy.CODEARTS_OPEN_BUDGET)
        self.assertGreater(size, ca_proxy.CODEARTS_LARGE_BODY_BYTES)

    def test_budget_multiplier_is_capped(self):
        """再大的 body 也只给 3 倍 —— 不能让一个卡死的请求无限拖下去。"""
        payload = {"model": "glm-5.3"}
        huge = _messages(50 * 1024 * 1024)
        budget, _size = ca_proxy._codearts_open_budget_for(payload, huge)
        self.assertLessEqual(
            budget,
            ca_proxy.CODEARTS_OPEN_BUDGET * ca_proxy.CODEARTS_LARGE_BODY_BUDGET_MULT)

    def test_budget_grows_monotonically(self):
        payload = {"model": "glm-5.3"}
        prev = 0
        for size in (0, 500_000, 1_100_000, 2_200_000, 5_000_000):
            budget, _ = ca_proxy._codearts_open_budget_for(payload,
                                                           _messages(size))
            self.assertGreaterEqual(budget, prev)
            prev = budget

    def test_tools_only_request_still_counts(self):
        """只有工具、没有长文本的请求也要被算成大 body。

        生产上 66 个 MCP 工具的 schema 就有上百 KB，加上工具调用参数，
        body 轻松过 1MB —— 而 message 里的正文可能很短（实测
        chars=576998 / acall=312331 那种形状）。
        """
        tools = [{"type": "function", "function": {"name": "f%d" % i,
                                                   "description": "d" * 20000}}
                 for i in range(66)]
        payload = {"model": "glm-5.3", "tools": tools}
        budget, size = ca_proxy._codearts_open_budget_for(payload,
                                                           _messages(100))
        self.assertGreater(size, ca_proxy.CODEARTS_LARGE_BODY_BYTES)
        self.assertGreater(budget, ca_proxy.CODEARTS_OPEN_BUDGET)


class RetryCostTests(unittest.TestCase):
    """写超时属于「慢失败」—— 下一轮的预估要按满窗口算。"""

    def test_socket_timeout_counts_as_slow(self):
        import socket
        self.assertTrue(ca_stream.slow_failure(None, "", socket.timeout("x")))
        self.assertTrue(ca_stream.slow_failure(None, "",
                                                TimeoutError("x")))


if __name__ == "__main__":
    unittest.main(verbosity=2)

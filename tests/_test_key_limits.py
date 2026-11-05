"""按 key 的使用限制：每分钟请求数 + 累计积分总额度。

两件事要一起钉住：

  1. **RPM 是滑动窗口**，不是「每分钟清零的计数器」——后者在 59 秒发满、
     60 秒再发满，实际是双倍速率。这里用单调时钟，且被拒的那一次也记账。
  2. **积分额度是「一生累计」**，不按天重置。它从 usage.jsonl 增量折出来，
     不复用 analytics 那份（那份只在面板被打开时才往前折，没人看面板就
     永远是冷的，额度判定会一路放行）。
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_settings
import ca_usage
import ca_proxy


class KeyLimitFieldsTests(unittest.TestCase):
    """字段解析：旧配置读回来必须是 0（= 不限），否则升级即封号。"""

    def test_defaults_are_unlimited(self):
        entry = ca_settings._clean_key_entry({"name": "t", "key": "k-1"})
        self.assertEqual(entry["rate_limit_rpm"], 0)
        self.assertEqual(entry["credit_limit"], 0.0)

    def test_values_parsed(self):
        entry = ca_settings._clean_key_entry({
            "name": "t", "key": "k-2",
            "rate_limit_rpm": "60", "credit_limit": "500.5"})
        self.assertEqual(entry["rate_limit_rpm"], 60)
        self.assertAlmostEqual(entry["credit_limit"], 500.5)

    def test_garbage_and_negative_collapse_to_zero(self):
        for raw in ("abc", -5, None, "", []):
            entry = ca_settings._clean_key_entry({
                "name": "t", "key": "k-3",
                "rate_limit_rpm": raw, "credit_limit": raw})
            self.assertEqual(entry["rate_limit_rpm"], 0, raw)
            self.assertEqual(entry["credit_limit"], 0.0, raw)

    def test_bool_is_not_an_int_here(self):
        # bool 是 int 的子类：True 会被 int() 吃成 1，把 key 悄悄限成 1 次/分。
        entry = ca_settings._clean_key_entry({
            "name": "t", "key": "k-4", "rate_limit_rpm": True,
            "credit_limit": True})
        self.assertEqual(entry["rate_limit_rpm"], 0)
        self.assertEqual(entry["credit_limit"], 0.0)

    def test_getters(self):
        self.assertEqual(ca_settings.key_rate_limit({"rate_limit_rpm": 30}), 30)
        self.assertEqual(ca_settings.key_rate_limit({}), 0)
        self.assertEqual(ca_settings.key_credit_limit({"credit_limit": 12.5}), 12.5)
        self.assertEqual(ca_settings.key_credit_limit({}), 0.0)


class KeyRateLimitTests(unittest.TestCase):
    def setUp(self):
        ca_proxy._key_rate_reset()

    def tearDown(self):
        ca_proxy._key_rate_reset()

    def test_zero_means_unlimited(self):
        entry = {"id": "k-nolimit", "rate_limit_rpm": 0}
        for _ in range(200):
            ok, _limit, _retry = ca_proxy._key_rate_reserve(entry)
            self.assertTrue(ok)

    def test_rejects_past_the_limit(self):
        entry = {"id": "k-rpm", "rate_limit_rpm": 3}
        results = [ca_proxy._key_rate_reserve(entry)[0] for _ in range(6)]
        self.assertEqual(results, [True, True, True, False, False, False])

    def test_rejection_carries_retry_after(self):
        entry = {"id": "k-rpm2", "rate_limit_rpm": 1}
        self.assertTrue(ca_proxy._key_rate_reserve(entry)[0])
        ok, limit, retry = ca_proxy._key_rate_reserve(entry)
        self.assertFalse(ok)
        self.assertEqual(limit, 1)
        self.assertGreater(retry, 0.0)
        self.assertLessEqual(retry, ca_proxy.KEY_RATE_WINDOW_SECONDS)

    def test_keys_are_counted_separately(self):
        a = {"id": "k-a", "rate_limit_rpm": 1}
        b = {"id": "k-b", "rate_limit_rpm": 1}
        self.assertTrue(ca_proxy._key_rate_reserve(a)[0])
        self.assertTrue(ca_proxy._key_rate_reserve(b)[0])
        self.assertFalse(ca_proxy._key_rate_reserve(a)[0])
        self.assertFalse(ca_proxy._key_rate_reserve(b)[0])

    def test_sliding_window_releases_after_the_window(self):
        """窗口滑过去之后必须重新放行 —— 否则限额就成了永久的。"""
        entry = {"id": "k-slide", "rate_limit_rpm": 2}
        original = ca_proxy.KEY_RATE_WINDOW_SECONDS
        ca_proxy.KEY_RATE_WINDOW_SECONDS = 0.05
        try:
            self.assertTrue(ca_proxy._key_rate_reserve(entry)[0])
            self.assertTrue(ca_proxy._key_rate_reserve(entry)[0])
            self.assertFalse(ca_proxy._key_rate_reserve(entry)[0])
            import time
            time.sleep(0.12)
            self.assertTrue(ca_proxy._key_rate_reserve(entry)[0])
        finally:
            ca_proxy.KEY_RATE_WINDOW_SECONDS = original

    def test_entry_without_id_is_unthrottled(self):
        # 启动参数来的 key（launcher）没有 settings id，不该被这里挡。
        for _ in range(50):
            self.assertTrue(
                ca_proxy._key_rate_reserve({"rate_limit_rpm": 1})[0])


class KeyCreditTotalTests(unittest.TestCase):
    """累计积分累加器：从 usage.jsonl 增量折，跨行跨 key 分开算。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "usage.jsonl")
        self._orig_log = ca_usage._BINDINGS["usage_log"]
        ca_usage.bind(usage_log=lambda: self.log)
        ca_usage.key_credit_reset()

    def tearDown(self):
        ca_usage.bind(usage_log=self._orig_log)
        ca_usage.key_credit_reset()

    def _write(self, rows):
        with open(self.log, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")

    def _append(self, row):
        with open(self.log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

    @staticmethod
    def _row(key, credit, at=1):
        return {"at": at, "key": key, "credit": credit, "total_tokens": 10,
                "model": "glm-5.3", "account": "acct-1",
                "outcome": "completed"}

    def test_sums_credits_per_key(self):
        self._write([self._row("k1", 5.0), self._row("k1", 2.5),
                     self._row("k2", 9.0), self._row("k1", 0)])
        self.assertAlmostEqual(ca_usage.key_credit_total("k1"), 7.5)
        self.assertAlmostEqual(ca_usage.key_credit_total("k2"), 9.0)
        self.assertAlmostEqual(ca_usage.key_credit_total("never-seen"), 0.0)

    def test_is_incremental(self):
        self._write([self._row("k1", 5.0)])
        self.assertAlmostEqual(ca_usage.key_credit_total("k1"), 5.0)
        self._append(self._row("k1", 1.0, at=2))
        self.assertAlmostEqual(ca_usage.key_credit_total("k1"), 6.0)

    def test_counts_rows_without_an_account(self):
        """失败行可能还没抢到号，但积分照花 —— 额度必须算上它。"""
        self._write([{"at": 1, "key": "k1", "credit": 3.0,
                      "model": "glm-5.3", "outcome": "failed"}])
        self.assertAlmostEqual(ca_usage.key_credit_total("k1"), 3.0)

    def test_rows_without_a_key_are_ignored(self):
        self._write([{"at": 1, "credit": 4.0, "model": "m", "account": "a",
                      "outcome": "completed"}])
        self.assertAlmostEqual(ca_usage.key_credit_total("k1"), 0.0)

    def test_missing_log_is_zero_not_an_error(self):
        self.assertAlmostEqual(ca_usage.key_credit_total("k1"), 0.0)


class KeyCreditQuotaTests(unittest.TestCase):
    """额度判定：超了拒、没超放、读不到放行但要留痕。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "usage.jsonl")
        self._orig_log = ca_usage._BINDINGS["usage_log"]
        ca_usage.bind(usage_log=lambda: self.log)
        ca_usage.key_credit_reset()
        with open(self.log, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": 1, "key": "kq", "credit": 8.0,
                                 "total_tokens": 1, "model": "m",
                                 "account": "a",
                                 "outcome": "completed"}) + "\n")

    def tearDown(self):
        ca_usage.bind(usage_log=self._orig_log)
        ca_usage.key_credit_reset()

    def test_under_quota_passes(self):
        ok, limit, used = ca_proxy._key_credit_check(
            {"id": "kq", "credit_limit": 10.0})
        self.assertTrue(ok)
        self.assertEqual(limit, 10.0)
        self.assertAlmostEqual(used, 8.0)

    def test_over_quota_blocks(self):
        ok, limit, used = ca_proxy._key_credit_check(
            {"id": "kq", "credit_limit": 5.0})
        self.assertFalse(ok)
        self.assertEqual(limit, 5.0)
        self.assertAlmostEqual(used, 8.0)

    def test_exactly_at_quota_blocks(self):
        ok, _limit, _used = ca_proxy._key_credit_check(
            {"id": "kq", "credit_limit": 8.0})
        self.assertFalse(ok)

    def test_zero_quota_is_unlimited(self):
        ok, limit, _used = ca_proxy._key_credit_check(
            {"id": "kq", "credit_limit": 0})
        self.assertTrue(ok)
        self.assertEqual(limit, 0.0)

    def test_unreadable_log_does_not_block(self):
        """读盘失败必须放行：把 I/O 抖动变成「全员停用」是最糟的失败模式。"""
        ca_usage.bind(usage_log=lambda: os.path.join(self.dir, "nope", "x.jsonl"))
        original = ca_usage._key_credit_advance

        def boom():
            return False
        ca_usage._key_credit_advance = boom
        try:
            ok, _limit, _used = ca_proxy._key_credit_check(
                {"id": "kq", "credit_limit": 1.0})
            self.assertTrue(ok)
        finally:
            ca_usage._key_credit_advance = original
            ca_usage.bind(usage_log=lambda: self.log)

    def test_message_states_it_is_a_lifetime_total(self):
        text = ca_proxy._key_credit_message({"name": "小明的Key"}, 100.0, 120.0)
        self.assertIn("小明的Key", text)
        self.assertIn("100.00", text)
        self.assertIn("120.00", text)
        # 说明里必须讲清「不会按天重置」，否则用户会以为是每日额度去等隔天
        self.assertIn("不会按天重置", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)

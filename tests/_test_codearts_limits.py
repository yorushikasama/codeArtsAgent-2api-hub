"""码道账号池的日限额：面板那三条全局护栏必须在 acquire() 上真正生效。

  · 日 token / 日积分是账号级的，按 ``account.label`` 对账 —— record_usage()
    记的是 label，用 id 会对出永远为 0 的用量，护栏静默失效；
  · 按模型限额只停一个模型，同一账号的其它模型照常接单；
  · 读不到用量或读不到设置都算「未知」，fail-open，绝不误封；
  · 所有账号都被限额停住时，池子返回空，调用方据此回 429 而不是 503。

不联网。Run: python tests/_test_codearts_limits.py
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_proxy as P
import ca_settings


def session(label, account_id=None):
    return {
        "accessKey": "AK-" + label,
        "secretKey": "SK-" + label,
        "securitytoken": "TK-" + label,
        # id 故意与 label 不同：护栏必须按 label 对账。
        "account": {"id": account_id or ("id-" + label), "label": label},
        "expires_at": "2099-01-01T00:00:00.000Z",
    }


def limits(token=0, credit=0, model=0):
    return {"daily_token_limit": {"global": token},
            "daily_credit_limit": {"global": credit},
            "model_daily_token_limit": {"global": model}}


def stats(tokens=None, credits=None, models=None):
    return {"tokens": dict(tokens or {}),
            "credits": dict(credits or {}),
            "models": dict(models or {})}


class PoolLimitTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="codearts-limits-")
        self.pool = P._CodeartsAccountPool(state_dir=self.dir)
        self.sessions = [session("a"), session("b")]
        self.pool._usable = lambda: list(self.sessions)
        patcher = mock.patch.object(P, "codearts_concurrency", lambda: 2)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _acquire(self, limit_config, stats_value, model="glm-5.3"):
        """Run one acquire under a fixed settings/stats view; return the label."""
        with mock.patch.object(ca_settings, "limit_values_many",
                               return_value=limit_config), \
             mock.patch.object(P, "daily_usage_stats", return_value=stats_value):
            picked, key = self.pool.acquire(0, model=model)
            if key is not None:
                self.pool.release(key)
            return picked.get("account", {}).get("label") if picked else None

    def test_under_limit_account_is_used(self):
        self.assertEqual(self._acquire(limits(token=1000),
                                       stats(tokens={"a": 999})), "a")

    def test_token_limit_parks_exactly_that_account(self):
        self.assertEqual(self._acquire(limits(token=1000),
                                       stats(tokens={"a": 1000})), "b")

    def test_credit_limit_parks_exactly_that_account(self):
        self.assertEqual(self._acquire(limits(credit=50),
                                       stats(credits={"a": 50})), "b")

    def test_model_limit_parks_only_that_model(self):
        usage = stats(models={"a": {"glm-5.3": 100}})
        self.assertEqual(
            self._acquire(limits(model=100), usage, model="glm-5.3"), "b")
        # 同一个号上的另一个模型不受影响。
        self.assertFalse(self.pool._limit_blocked(
            session("a"), "deepseek-v3", limits(model=100), usage))

    def test_usage_is_keyed_by_label_not_id(self):
        self.assertEqual(self._acquire(
            limits(token=1000),
            stats(tokens={"a": 5000, "id-a": 0})), "b",
            "按 id 对账会读到 0，这个号就永远不被限额停住")

    def test_zero_limit_never_reads_the_usage_log(self):
        with mock.patch.object(ca_settings, "limit_values_many",
                               return_value=limits()), \
             mock.patch.object(P, "daily_usage_stats",
                               side_effect=AssertionError("不该读用量")):
            picked, key = self.pool.acquire(0, model="glm-5.3")
            if key is not None:
                self.pool.release(key)
        self.assertIsNotNone(picked)

    def test_unreadable_usage_fails_open(self):
        self.assertIsNotNone(
            self._acquire(limits(token=1000), None),
            "用量读不出来时按未知处理，不能把所有号都停掉")
        self.assertIsNotNone(self._acquire(limits(token=1000), stats()))

    def test_usage_read_error_fails_open(self):
        with mock.patch.object(ca_settings, "limit_values_many",
                               return_value=limits(token=1000)), \
             mock.patch.object(P, "daily_usage_stats",
                               side_effect=OSError("usage log gone")):
            picked, key = self.pool.acquire(0, model="glm-5.3")
            if key is not None:
                self.pool.release(key)
        self.assertIsNotNone(picked)

    def test_settings_read_error_fails_open(self):
        with mock.patch.object(ca_settings, "limit_values_many",
                               side_effect=OSError("settings gone")):
            picked, key = self.pool.acquire(0, model="glm-5.3")
            if key is not None:
                self.pool.release(key)
        self.assertIsNotNone(picked)

    def test_all_parked_reports_a_limit_429_not_a_busy_429(self):
        over = limits(token=1000)
        both = stats(tokens={"a": 1500, "b": 1500})
        with mock.patch.object(ca_settings, "limit_values_many", return_value=over), \
             mock.patch.object(P, "daily_usage_stats", return_value=both):
            picked, key = self.pool.acquire(0, model="glm-5.3")
            self.assertEqual((picked, key), (None, None))
            self.assertTrue(self.pool.limits_blocked("glm-5.3"))

    def test_label_less_session_is_never_parked(self):
        self.sessions = [session("", account_id="id-none")]
        self.assertEqual(self._acquire(
            limits(token=1), stats(tokens={"": 999})), "",)

    def test_model_guard_without_a_model_is_ignored(self):
        blocked = self.pool._limit_blocked(
            session("a"), None, limits(model=1), stats(models={"a": {"glm": 9}}))
        self.assertFalse(blocked, "没有模型名的请求不该被按模型限额停掉")

    def test_account_guards_apply_once_even_without_a_model(self):
        self.assertTrue(self.pool._limit_blocked(
            session("a"), None, limits(token=10), stats(tokens={"a": 10})))


class _NoPool(object):
    """No slot because every account is parked by the panel's guard."""

    def acquire(self, *args, **kwargs):
        return None, None

    def limits_blocked(self, model=None):
        return True

    def _usable(self):
        return [session("a")]

    def snapshot(self):
        return {}


class _Handler(object):
    headers = {}

    def _client_disconnected(self):
        return False

    def _key_id(self):
        return ""

    def _error(self, status, message, kind=""):
        return status, message, kind


class LimitResponseTests(unittest.TestCase):
    def test_open_lease_answers_429_with_the_limit_message(self):
        payload = {"model": "glm-5.3", "messages": []}
        with mock.patch.object(P, "_CODEARTS_POOL", _NoPool()), \
             mock.patch.object(P, "upstream_timeouts", lambda: (120, 60)), \
             mock.patch.object(ca_settings, "egress_backoff_enabled",
                               lambda _d: False):
            error, lease = P.Handler._codearts_open_lease(
                _Handler(), payload, "glm-5.3", [], 128)
        self.assertIsNone(lease)
        status, message, kind = error
        self.assertEqual(status, 429)
        self.assertEqual(kind, "rate_limit_error")
        self.assertIn("daily limit", message)
        self.assertIn("Settings", message)


if __name__ == "__main__":
    unittest.main(verbosity=2)

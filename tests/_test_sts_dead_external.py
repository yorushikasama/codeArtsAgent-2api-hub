"""1806「外部占用」生命周期的契约：确认一次，之后静默，重登录自愈。

背景（2026-10-25 实测）：官方 IDE 与网关共用账号时，refresh_token 单链被
IDE 每小时轮换推进，网关手里的 token 一次性作废（STS5.1806）。修复前
refresher 每 30 秒替死账号打一次注定失败的续期 —— 一天 2800+ 条 WARN 与
同样数量的上游请求。此套件钉住三件事：

  1. 首次 1806 → 标记「外部占用」，打一次说明日志；
  2. 标记后巡检静默跳过（不再调 refresh_session，不再刷 WARN）；
  3. token 变了（重新登录换新链）→ 自动解除，恢复续期；
     其它错误（网络/5xx）不标记，照常重试。

    python tests/_test_sts_dead_external.py
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolated_dirs import isolated_data_dirs  # noqa: E402

_TMP = isolated_data_dirs("wb-sts-dead-")

import ca_codearts  # noqa: E402
import ca_proxy as P  # noqa: E402

SESS = {
    "accessKey": "AK", "secretKey": "SK", "securitytoken": "ST",
    "refresh_token": "RT-CHAIN-A-000000000000",
    "expires_at": "2026-10-25T03:00:00.000Z",
    "account": {"id": "acct-1", "label": "acct-1"},
}
PREFIX = SESS["refresh_token"][:24]


def _reset():
    P._STS_DEAD_EXTERNALLY.clear()


class DeadExternalTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.logs = []
        collect = self.logs.append
        self.log = mock.patch.object(
            P, "log", side_effect=lambda *a, **k: collect(a[0] if a else ""))
        self.log.start()
        self.addCleanup(self.log.stop)
        self.addCleanup(_reset)

    def test_first_1806_marks_and_logs_once(self):
        with mock.patch.object(
                ca_codearts, "ensure_fresh_session",
                side_effect=ca_codearts.CodeArtsError(
                    "[STS5.1806] the refresh token has been used")):
            P._ensure_fresh(SESS)
        self.assertTrue(P._sts_dead_by_external(SESS))
        warned = [l for l in self.logs if "1806" in l and "外部" in l]
        self.assertEqual(len(warned), 1, warned)

    def test_marked_account_is_silent_on_later_ticks(self):
        P._STS_DEAD_EXTERNALLY["acct-1"] = PREFIX
        with mock.patch.object(
                ca_codearts, "ensure_fresh_session") as fresh:
            out = P._ensure_fresh(SESS)
        fresh.assert_not_called()          # 不再打上游
        self.assertIs(out, SESS)           # 原样交回
        self.assertEqual(self.logs, [])    # 不再刷日志

    def test_relogin_new_token_heals_the_mark(self):
        P._STS_DEAD_EXTERNALLY["acct-1"] = PREFIX
        renewed = dict(SESS, refresh_token="RT-CHAIN-B-999999999999")
        self.assertFalse(P._sts_dead_by_external(renewed))
        # 且解除后真会去续期
        with mock.patch.object(ca_codearts, "ensure_fresh_session",
                               return_value=renewed) as fresh:
            P._ensure_fresh(renewed)
        fresh.assert_called_once()

    def test_transient_errors_do_not_mark(self):
        with mock.patch.object(
                ca_codearts, "ensure_fresh_session",
                side_effect=RuntimeError("connection reset")):
            P._ensure_fresh(SESS)
        self.assertFalse(P._STS_DEAD_EXTERNALLY)
        self.assertTrue(any("STS renew failed" in l for l in self.logs))

    def test_account_view_exposes_the_state(self):
        # 面板字段 sts_dead_external 的来源就是 _sts_dead_by_external：
        # 标记时为真，未标记/自愈后为假（视图组装在 _get_codearts_accounts，
        # 那一层走完整 HTTP，这里钉住判定函数本身的两个象限）。
        P._STS_DEAD_EXTERNALLY["acct-1"] = PREFIX
        self.assertTrue(P._sts_dead_by_external(SESS))
        _reset()
        self.assertFalse(P._sts_dead_by_external(SESS))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""1806「外部占用」生命周期的契约：确认一次、暂停、定期再探、重登录自愈。

背景（2026-10-25 实测）：官方 IDE 与网关共用账号时，refresh_token 单链被
IDE 每小时轮换推进，网关手里的 token 一次性作废（STS5.1806）。修复前
refresher 每 30 秒替死账号打一次注定失败的续期 —— 一天 2800+ 条 WARN 与
同样数量的上游请求。

2026-11-19/22 线上又暴露出两个把账号**永久判死**的缺陷，本套件一并钉住：

  A. 指纹用 ``refresh_token[:24]``。refresh_token 是 JWT，前 24 字符是固定
     头部 ``eyJ0eXAiOiJKV1QiLCJhbGci``，每张新 token 都一样 —— 「token 变了
     就自愈」那条分支永远不可能命中。用户 11-20 09:53 明明重新授权过，
     网关仍把号当死的排除在池外，11-20 16:20 与 11-22 09:27 的 503 全出自
     这里。现在改成整串 sha256。

  B. 换 token 的 read 超时被当成普通网络错误。refresh_token 一次性轮换，
     上游很可能已经受理并作废了旧 token，只是 response 丢了。靠退避重试
     拿同一张旧 token 去换，必然 1806 —— 于是「我们自己超时」被误诊成
     「被 IDE 抢占」，账号被判死 2.5 天。现在 ``indeterminate`` 单独一条路，
     不标记、不暂停续期。

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

#: 和线上一样是 JWT 形状 —— 前 24 字符刻意做成**固定头部**，
#: 这样「拿前缀当指纹」的写法在这里就会露馅（见模块 docstring A）。
_JWT_HEAD = "eyJ0eXAiOiJKV1QiLCJhbGciOK"
SESS = {
    "accessKey": "AK", "secretKey": "SK", "securitytoken": "ST",
    "refresh_token": _JWT_HEAD + "CHAIN-A.payload-a.sig-a",
    "expires_at": "2026-10-25T03:00:00.000Z",
    "account": {"id": "acct-1", "label": "acct-1"},
}
#: 另一张 token，头部完全相同、只有载荷不同（真实 JWT 就是这样）。
OTHER_SESS = dict(SESS, refresh_token=_JWT_HEAD + "CHAIN-B.payload-b.sig-b")


def _mark(sess=SESS, age_seconds=0.0, probes=0):
    """按线上结构打标记：标记表是 (指纹, 标记时刻)，再探次数在独立计数表里。"""
    P._STS_DEAD_EXTERNALLY["acct-1"] = (
        P._token_fingerprint(sess), P.time.time() - age_seconds)
    if probes:
        P._STS_REPROBE_COUNT["acct-1"] = probes
    else:
        P._STS_REPROBE_COUNT.pop("acct-1", None)


def _reset():
    P._STS_DEAD_EXTERNALLY.clear()
    P._STS_REPROBE_COUNT.clear()


class FingerprintTests(unittest.TestCase):
    """缺陷 A：指纹必须区分得开两张真 token。"""

    def test_jwt_prefix_is_identical_but_fingerprints_differ(self):
        # 这条要是挂了，说明指纹又退回到「取前 N 字符」——
        # 而 JWT 头是常量，等于所有 token 同一个指纹。
        self.assertEqual(SESS["refresh_token"][:24],
                         OTHER_SESS["refresh_token"][:24])
        self.assertNotEqual(P._token_fingerprint(SESS),
                            P._token_fingerprint(OTHER_SESS))

    def test_empty_token_has_empty_fingerprint(self):
        self.assertEqual(P._token_fingerprint({}), "")
        self.assertEqual(P._token_fingerprint({"refresh_token": ""}), "")


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
        _mark()
        with mock.patch.object(
                ca_codearts, "ensure_fresh_session") as fresh:
            out = P._ensure_fresh(SESS)
        fresh.assert_not_called()          # 不再打上游
        self.assertIs(out, SESS)           # 原样交回
        self.assertEqual(self.logs, [])    # 不再刷日志

    def test_relogin_new_token_heals_the_mark(self):
        # 缺陷 A 的正面用例：头部相同、载荷不同 = 真的换了 token。
        _mark()
        self.assertFalse(P._sts_dead_by_external(OTHER_SESS))
        with mock.patch.object(ca_codearts, "ensure_fresh_session",
                               return_value=OTHER_SESS) as fresh:
            P._ensure_fresh(OTHER_SESS)
        fresh.assert_called_once()

    def test_reprobe_after_interval_retries_the_renewal(self):
        # 缺陷 B 的兜底：即使 token 没换，隔够久也要再试一次 ——
        # 「1806」未必是真的，可能只是我们自己把那张一次性 token 超时用掉了。
        # probes>=1 表示已经探过一次，此时走长间隔。
        _mark(age_seconds=P._STS_DEAD_REPROBE_SECONDS + 1, probes=1)
        self.assertFalse(P._sts_dead_by_external(SESS))
        with mock.patch.object(ca_codearts, "ensure_fresh_session",
                               return_value=SESS) as fresh:
            P._ensure_fresh(SESS)
        fresh.assert_called_once()
        self.assertTrue(any("再探" in l for l in self.logs), self.logs)

    def test_first_reprobe_is_fast_not_an_hour(self):
        # 2026-11-25 部署事故：新进程拿旧快照续期 → 1806 → 按 3600 秒兜着，
        # 账号整整一小时不可用。首次再探必须短（默认 120 秒），因为刚被判死
        # 时最可能是假死。
        self.assertLess(P._STS_DEAD_FIRST_REPROBE_SECONDS,
                        P._STS_DEAD_REPROBE_SECONDS)
        _mark(age_seconds=P._STS_DEAD_FIRST_REPROBE_SECONDS + 1, probes=0)
        self.assertFalse(P._sts_dead_by_external(SESS))

    def test_marked_silent_then_probe_round_trips(self):
        # 刚标记（probes=0）→ 未到 120 秒 → 静默；过了 → 再探；再失败 → 次数+1
        # 且下一次走长间隔（不再 120 秒后又打一次上游）。
        _mark()
        self.assertTrue(P._sts_dead_by_external(SESS))
        err = ca_codearts.CodeArtsError("[STS5.1806] the refresh token has been used")
        _mark(age_seconds=P._STS_DEAD_FIRST_REPROBE_SECONDS + 1, probes=0)
        with mock.patch.object(ca_codearts, "ensure_fresh_session",
                               side_effect=err):
            P._ensure_fresh(SESS)
        state = P._STS_REPROBE_COUNT.get("acct-1", 0)
        self.assertEqual(state, 1, P._STS_REPROBE_COUNT)   # 再探次数已 +1
        # 刚重新标记、probes=1：即使过了 120 秒也还要等长间隔
        _mark(age_seconds=P._STS_DEAD_FIRST_REPROBE_SECONDS + 1, probes=1)
        self.assertTrue(P._sts_dead_by_external(SESS))

    def test_reprobe_that_fails_again_re_marks(self):
        _mark(age_seconds=P._STS_DEAD_REPROBE_SECONDS + 1, probes=1)
        with mock.patch.object(
                ca_codearts, "ensure_fresh_session",
                side_effect=ca_codearts.CodeArtsError(
                    "[STS5.1806] the refresh token has been used")):
            P._ensure_fresh(SESS)
        # 重新标记 → 接下来的 tick 继续静默，不会每 30 秒打一次上游
        self.assertTrue(P._sts_dead_by_external(SESS))
        with mock.patch.object(
                ca_codearts, "ensure_fresh_session") as fresh:
            P._ensure_fresh(SESS)
        fresh.assert_not_called()

    def test_indeterminate_failure_does_not_mark_or_pause(self):
        # 缺陷 B：read 超时 = 一次性 token 可能已被我们自己用掉。
        # 这跟「被 IDE 抢占」是两码事，不能停掉续期，也不该留 1806 标记。
        exc = ca_codearts.CodeArtsError("请求超时：The read operation timed out")
        exc.indeterminate = True
        with mock.patch.object(ca_codearts, "ensure_fresh_session",
                               side_effect=exc):
            P._ensure_fresh(SESS)
        self.assertFalse(P._STS_DEAD_EXTERNALLY)
        self.assertFalse(P._sts_dead_by_external(SESS))
        logged = " ".join(self.logs)
        self.assertIn("result unknown", logged)
        self.assertNotIn("1806）", logged)   # 没有打「链被外部轮换」那条
        # 下一个 tick 照常续期（不是死号）
        with mock.patch.object(ca_codearts, "ensure_fresh_session",
                               return_value=SESS) as fresh:
            P._ensure_fresh(SESS)
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
        _mark()
        self.assertTrue(P._sts_dead_by_external(SESS))
        _reset()
        self.assertFalse(P._sts_dead_by_external(SESS))

    def _usable_with(self, *sessions):
        with mock.patch.object(ca_codearts, "load_sessions",
                               return_value=list(sessions)):
            return P._CODEARTS_POOL._usable()

    def test_usable_keeps_expired_but_renewable_account(self):
        # 过期但续得上：照旧进池（闲置两小时不能把模型清单打成空）。
        live = dict(SESS, expires_at="2020-01-01T00:00:00.000Z")
        with mock.patch.object(ca_codearts, "summarize",
                               return_value={"sts_expired": True,
                                             "renewable": True,
                                             "sts_remaining_seconds": -10}):
            self.assertEqual(self._usable_with(live), [live])

    def test_usable_drops_dead_external_account(self):
        # 1806 确认续不上的号不能留在池子里：否则每轮挑号都可能选中它，
        # 续期必败、请求带过期凭证打上游换回 APIG.0301（2026-11-02 线上：
        # hw025261 过期 5.9 天仍被选中，冷却 300 秒一到又循环）。
        dead = dict(SESS, expires_at="2020-01-01T00:00:00.000Z")
        _mark()
        with mock.patch.object(ca_codearts, "summarize",
                               return_value={"sts_expired": True,
                                             "renewable": True,
                                             "sts_remaining_seconds": -10}):
            self.assertEqual(self._usable_with(dead), [])

    def test_usable_returns_account_after_relogin(self):
        # 重新登录换出新 token 链 → 标记自愈 → 立即回到池子，不需要重启。
        # 这是缺陷 A 在调度层的表现：以前前缀相同，这条路径永远走不到。
        healed = dict(OTHER_SESS, expires_at="2020-01-01T00:00:00.000Z")
        _mark()
        with mock.patch.object(ca_codearts, "summarize",
                               return_value={"sts_expired": True,
                                             "renewable": True,
                                             "sts_remaining_seconds": -10}):
            self.assertEqual(self._usable_with(healed), [healed])

    def test_relogin_clears_the_mark_immediately(self):
        # 登录成功 / 手动续期会调 codearts_clear_cooldown_for：那一刻就把
        # 1806 标记清掉，而不是等下一次巡检靠指纹比对自愈。
        _mark()
        with mock.patch.object(ca_codearts, "load_sessions",
                               return_value=[SESS]):
            P.codearts_clear_cooldown_for("acct-1")
        self.assertFalse(P._STS_DEAD_EXTERNALLY)
        self.assertTrue(any("解除 1806" in l for l in self.logs), self.logs)


class IndeterminateClassificationTests(unittest.TestCase):
    """``_after_send``：哪些 URLError 才算「请求已发出、结果未知」。"""

    def test_read_timeouts_count_as_after_send(self):
        for reason in ("The read operation timed out",
                       "The write operation timed out",
                       "EOF occurred in violation of protocol (_ssl.c:983)",
                       "Connection reset by peer",
                       "Remote end closed connection without response",
                       "<urlopen error [Errno 104] Connection reset by peer>"):
            self.assertTrue(ca_codearts._after_send(reason), reason)

    def test_connect_failures_are_safe_to_retry(self):
        for reason in ("[Errno 111] Connection refused",
                       "Name or service not known",
                       "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"):
            self.assertFalse(ca_codearts._after_send(reason), reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
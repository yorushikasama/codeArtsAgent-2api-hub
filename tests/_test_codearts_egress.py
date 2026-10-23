"""码道的两条重试环都把瞬时失败记在出口上，而不是账号上。

面板打开「出口级瞬时失败退避」后：
  · 传输异常与 502/503/504 → ca_egress.note_transient()，退避是秒级，并与
    原有重试节奏取较大者（不叠成两段等待）；
  · 500 仍走账号路径，不记出口；
  · 任一成功尝试 → note_success() 清零；
  · 开关关闭时一次都不调，行为与从前一致。

聚合路径与流式建连两条环各钉一遍。不联网。Run:
python tests/_test_codearts_egress.py
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts
import ca_proxy as P
import ca_settings
import ca_upstream_pool


SESSION = {
    "accessKey": "AK", "secretKey": "SK", "securitytoken": "TK",
    "account": {"id": "acct-1", "label": "一号"},
    "expires_at": "2099-01-01T00:00:00.000Z",
}


class _Pool(object):
    def acquire(self, timeout=None, session_key=None, model=None):
        return SESSION, "acct-1"

    def remember(self, *args, **kwargs):
        pass

    def release(self, key):
        pass

    def penalize(self, *args, **kwargs):
        pass

    def limits_blocked(self, model=None):
        return False

    def _usable(self):
        return [SESSION]

    def snapshot(self):
        return {}


class _Resp(object):
    def close(self):
        pass


class _Handler(object):
    headers = {}

    def _client_disconnected(self):
        return False

    def _key_id(self):
        return ""

    def _error(self, status, message, kind=""):
        return status, message, kind

    def _codearts_fail(self, status, code, detail, account, anthropic):
        return status, (code, detail), "upstream_error"


class _Clock(object):
    """A fake ca_proxy clock: records sleeps instead of waiting."""

    def __init__(self):
        self.now = 1_000_000.0
        self.sleeps = []

    def time(self):
        self.now += 0.01
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    # log() timestamps with time.strftime; keep it out of the fake clock.
    def strftime(self, fmt, *args):
        return "00:00:00"


PAYLOAD = {"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}]}
EGRESS_KEY = ca_upstream_pool.egress_key(ca_codearts.CHAT_PATH)


def settings_dir(enabled):
    directory = tempfile.mkdtemp(prefix="codearts-egress-")
    ca_settings.set_egress_backoff_enabled(directory, enabled)
    return directory


def egress_key():
    return EGRESS_KEY


class AggregateEgressTests(unittest.TestCase):
    def _run(self, enabled, responses):
        clock = _Clock()
        seen = {"transient": [], "success": []}
        calls = list(responses)

        def fake_chat_for_model(*args, **kwargs):
            outcome = calls.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with mock.patch.object(P, "ACCOUNTS_DIR", settings_dir(enabled)), \
             mock.patch.object(P, "_CODEARTS_POOL", _Pool()), \
             mock.patch.object(P, "time", clock), \
             mock.patch.object(P, "record_usage", lambda *a, **k: None), \
             mock.patch.object(P, "record_error", lambda *a, **k: None), \
             mock.patch.object(ca_codearts, "heartbeat",
                               lambda *a, **k: (True, "ok")), \
             mock.patch.object(ca_codearts, "chat_for_model",
                               fake_chat_for_model), \
             mock.patch.object(P.ca_egress, "note_transient",
                               lambda key: (seen["transient"].append(key), 2.5)[1]), \
             mock.patch.object(P.ca_egress, "note_success",
                               lambda key: seen["success"].append(key)):
            error, result = P.Handler._codearts_chat_result(
                _Handler(), dict(PAYLOAD))
        return error, result, clock, seen

    def test_transport_error_waits_on_the_egress_then_succeeds(self):
        error, result, clock, seen = self._run(
            True, [OSError("link blip"), (200, "")])
        self.assertIsNone(error)
        self.assertIsNotNone(result)
        self.assertEqual(seen["transient"], [egress_key()])
        self.assertEqual(seen["success"], [egress_key()])
        # 原有重试节奏是 2.0s，出口退避 2.5s：取较大者，不叠加。
        self.assertEqual(clock.sleeps, [2.5])

    def test_502_charges_the_egress_but_500_stays_on_the_account(self):
        error, result, clock, seen = self._run(
            True, [(502, '{"error_code":"BadGateway"}'), (200, "")])
        self.assertIsNone(error)
        self.assertEqual(seen["transient"], [egress_key()])

        error, result, clock, seen = self._run(
            True, [(500, '{"error_code":"InternalError"}'), (200, "")])
        self.assertIsNone(error)
        self.assertEqual(seen["transient"], [], "500 不算出口抖动")
        self.assertEqual(seen["success"], [egress_key()])
        self.assertEqual(clock.sleeps, [2.0], "没有出口退避时只用原节奏")

    def test_switch_off_makes_no_egress_calls(self):
        error, result, clock, seen = self._run(
            False, [OSError("link blip"), (200, "")])
        self.assertIsNone(error)
        self.assertEqual(seen, {"transient": [], "success": []})
        self.assertEqual(clock.sleeps, [2.0])


class OpenLeaseEgressTests(unittest.TestCase):
    def _run(self, enabled, responses):
        clock = _Clock()
        seen = {"transient": [], "success": []}
        calls = list(responses)

        def fake_open_chat(*args, **kwargs):
            outcome = calls.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with mock.patch.object(P, "ACCOUNTS_DIR", settings_dir(enabled)), \
             mock.patch.object(P, "_CODEARTS_POOL", _Pool()), \
             mock.patch.object(P, "time", clock), \
             mock.patch.object(P, "record_error", lambda *a, **k: None), \
             mock.patch.object(ca_codearts, "heartbeat",
                               lambda *a, **k: (True, "ok")), \
             mock.patch.object(ca_codearts, "open_chat", fake_open_chat), \
             mock.patch.object(P.ca_egress, "note_transient",
                               lambda key: (seen["transient"].append(key), 2.5)[1]), \
             mock.patch.object(P.ca_egress, "note_success",
                               lambda key: seen["success"].append(key)):
            error, lease = P.Handler._codearts_open_lease(
                _Handler(), dict(PAYLOAD), "glm-5.3",
                PAYLOAD["messages"], 128)
            if lease is not None:
                lease.close()
        return error, lease, clock, seen

    def test_transport_error_waits_on_the_egress_then_connects(self):
        resp = _Resp()
        error, lease, clock, seen = self._run(
            True, [ConnectionResetError("link blip"), (200, resp, "")])
        self.assertIsNone(error)
        self.assertIsNotNone(lease)
        self.assertEqual(seen["transient"], [egress_key()])
        self.assertEqual(seen["success"], [egress_key()])
        self.assertEqual(clock.sleeps, [2.5])

    def test_502_charges_the_egress_but_500_stays_on_the_account(self):
        error, lease, clock, seen = self._run(
            True, [(502, None, '{"error_code":"BadGateway"}'), (200, _Resp(), "")])
        self.assertIsNone(error)
        self.assertEqual(seen["transient"], [egress_key()])

        error, lease, clock, seen = self._run(
            True, [(500, None, '{"error_code":"InternalError"}'), (200, _Resp(), "")])
        self.assertIsNone(error)
        self.assertEqual(seen["transient"], [])
        self.assertEqual(clock.sleeps, [2.0])

    def test_switch_off_makes_no_egress_calls(self):
        error, lease, clock, seen = self._run(
            False, [ConnectionResetError("link blip"), (200, _Resp(), "")])
        self.assertIsNone(error)
        self.assertEqual(seen, {"transient": [], "success": []})
        self.assertEqual(clock.sleeps, [2.0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

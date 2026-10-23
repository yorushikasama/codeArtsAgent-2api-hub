"""码道两条聊天路径都吃面板的上游超时设置。

聚合路径（_codearts_chat_result）与流式建连（_codearts_open_lease）都必须把
``upstream_timeouts()`` 的 (header, idle) 原样交给 ca_codearts 的请求函数：
漏传任何一个，面板里调小的超时对码道就不生效，客户端首字节预算照样被拖爆。

不联网。Run: python tests/_test_codearts_timeouts.py
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


SESSION = {
    "accessKey": "AK", "secretKey": "SK", "securitytoken": "TK",
    "account": {"id": "acct-1", "label": "一号"},
    "expires_at": "2099-01-01T00:00:00.000Z",
}


class _Pool(object):
    def __init__(self):
        self.released = []

    def acquire(self, timeout=None, session_key=None, model=None):
        return SESSION, "acct-1"

    def remember(self, *args, **kwargs):
        pass

    def release(self, key):
        self.released.append(key)

    def penalize(self, *args, **kwargs):
        pass

    def limits_blocked(self, model=None):
        return False

    def _usable(self):
        return [SESSION]

    def snapshot(self):
        return {}


class _Resp(object):
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


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


def _settings_dir(header=None, idle=None):
    directory = tempfile.mkdtemp(prefix="codearts-timeouts-")
    patch = {}
    if header is not None:
        patch["header_timeout_seconds"] = header
    if idle is not None:
        patch["idle_timeout_seconds"] = idle
    if patch:
        ca_settings.set_upstream_config(directory, patch)
    return directory


PAYLOAD = {"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}]}


class AggregateTimeoutTests(unittest.TestCase):
    def test_chat_for_model_receives_the_panel_timeouts(self):
        directory = _settings_dir(header=45, idle=90)
        seen = []

        def fake_chat_for_model(*args, **kwargs):
            seen.append(kwargs)
            return 200, ""

        with mock.patch.object(P, "ACCOUNTS_DIR", directory), \
             mock.patch.object(P, "_CODEARTS_POOL", _Pool()), \
             mock.patch.object(ca_codearts, "heartbeat",
                               lambda *a, **k: (True, "ok")), \
             mock.patch.object(ca_codearts, "chat_for_model", fake_chat_for_model), \
             mock.patch.object(P, "record_usage", lambda *a, **k: None):
            error, result = P.Handler._codearts_chat_result(
                _Handler(), dict(PAYLOAD))

        self.assertIsNone(error)
        self.assertIsNotNone(result)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["timeout"], 45)
        self.assertEqual(seen[0]["idle_timeout"], 90)

    def test_defaults_reach_chat_for_model_without_any_setting(self):
        directory = _settings_dir()
        seen = []

        def fake_chat_for_model(*args, **kwargs):
            seen.append(kwargs)
            return 200, ""

        with mock.patch.object(P, "ACCOUNTS_DIR", directory), \
             mock.patch.object(P, "_CODEARTS_POOL", _Pool()), \
             mock.patch.object(ca_codearts, "heartbeat",
                               lambda *a, **k: (True, "ok")), \
             mock.patch.object(ca_codearts, "chat_for_model", fake_chat_for_model), \
             mock.patch.object(P, "record_usage", lambda *a, **k: None):
            P.Handler._codearts_chat_result(_Handler(), dict(PAYLOAD))

        self.assertEqual(seen[0]["timeout"], 120.0)
        self.assertEqual(seen[0]["idle_timeout"], 300.0)


class OpenLeaseTimeoutTests(unittest.TestCase):
    def test_open_chat_receives_the_panel_timeouts(self):
        directory = _settings_dir(header=30, idle=75)
        seen = []
        resp = _Resp()

        def fake_open_chat(*args, **kwargs):
            seen.append(kwargs)
            return 200, resp, ""

        with mock.patch.object(P, "ACCOUNTS_DIR", directory), \
             mock.patch.object(P, "_CODEARTS_POOL", _Pool()), \
             mock.patch.object(ca_codearts, "heartbeat",
                               lambda *a, **k: (True, "ok")), \
             mock.patch.object(ca_codearts, "open_chat", fake_open_chat):
            error, lease = P.Handler._codearts_open_lease(
                _Handler(), dict(PAYLOAD), "glm-5.3",
                PAYLOAD["messages"], 128)
            self.assertIsNone(error)
            self.assertIsNotNone(lease)
            lease.close()

        self.assertEqual(seen[0]["timeout"], 30)
        self.assertEqual(seen[0]["idle_timeout"], 75)
        self.assertTrue(resp.closed, "lease.close() 要关掉上游连接")


if __name__ == "__main__":
    unittest.main(verbosity=2)

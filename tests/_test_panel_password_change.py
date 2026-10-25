"""POST /panel/password 的契约：改不动就必须说改不动。

2026-10-22 的线上反馈：用户点「修改密码」一直失败，改完还是旧密码。
服务端日志里是一条 `POST /panel/password 401`。这个接口有两条 401 出路
（没有会话 / 当前密码不对）和一条「200 但其实没变」的出路（新旧密码相同），
三者对用户是完全不同的结论，这里逐条钉住：

  1. 没有面板会话 → 401 panel password required（不能落到「密码不对」上）；
  2. 当前密码不对 → 401，且密码原封不动；
  3. 新旧密码相同 → 400，且密码原封不动（不能假装成功）；
  4. 合法修改 → 200、新密码生效、旧密码失效、旧会话全部作废、.credentials 同步；
  5. 改完后的重启不会再被陈旧的启动参数覆盖（source=panel）。

    python tests/_test_panel_password_change.py
"""
import email
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolated_dirs import isolated_data_dirs  # noqa: E402

_TMP = isolated_data_dirs("wb-panel-password-")

import ca_proxy as proxy  # noqa: E402
import ca_settings  # noqa: E402

OLD = "old-pass"
NEW = "new-pass"
SESSION_LOST = "panel password required"


class PasswordRequest(proxy.Handler):
    """Real do_POST over an in-memory socket."""

    def __init__(self, path, headers=None, body=b""):
        self.path = path
        self.command = "POST"
        self.request_version = "HTTP/1.1"
        self.close_connection = True
        headers = dict(headers or {})
        headers.setdefault("Content-Length", str(len(body)))
        headers.setdefault("Content-Type", "application/json")
        raw = "".join("%s: %s\r\n" % item for item in headers.items())
        self.headers = email.message_from_string(raw)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status = None
        self.client_address = ("127.0.0.1", 0)

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass

    def log_message(self, fmt, *args):
        pass

    def dispatch(self):
        self.do_POST()
        raw = self.wfile.getvalue().decode("utf-8")
        return self.status, (json.loads(raw) if raw else None)


class PanelPasswordChangeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="panel-password-")
        self.addCleanup(self._tmp.cleanup)
        self.directory = os.path.join(self._tmp.name, "accounts")
        self.env_file = os.path.join(self._tmp.name, ".credentials")
        with open(self.env_file, "w", encoding="utf-8") as fh:
            fh.write("API_KEY=sk-test\nPANEL_PASSWORD=%s\n" % OLD)
        self._env = mock.patch.dict(
            os.environ, {"PANEL_PASSWORD_FILE": self.env_file})
        self._env.start()
        self.addCleanup(self._env.stop)
        ca_settings.set_panel_password(self.directory, OLD, source="launcher")

    def post(self, body, token=None):
        headers = {"X-Panel-Token": token} if token else {}
        request = PasswordRequest(
            "/panel/password", headers=headers,
            body=json.dumps(body).encode("utf-8"))
        with mock.patch.multiple(proxy, ACCOUNTS_DIR=self.directory):
            return request.dispatch()

    def login(self, password):
        request = PasswordRequest(
            "/panel/login",
            body=json.dumps({"password": password}).encode("utf-8"))
        with mock.patch.multiple(proxy, ACCOUNTS_DIR=self.directory):
            return request.dispatch()

    def test_change_requires_a_panel_session(self):
        status, payload = self.post({"current": OLD, "new": NEW})
        self.assertEqual(status, 401)
        self.assertIn(SESSION_LOST, payload["error"]["message"])
        self.assertTrue(ca_settings.verify_panel_password(self.directory, OLD))

    def test_wrong_current_password_changes_nothing(self):
        token = self.login(OLD)[1]["token"]
        status, payload = self.post({"current": "not-the-password", "new": NEW}, token)
        self.assertEqual(status, 401)
        self.assertIn("当前密码不正确", payload["error"]["message"])
        self.assertTrue(ca_settings.verify_panel_password(self.directory, OLD))
        self.assertFalse(ca_settings.verify_panel_password(self.directory, NEW))

    def test_identical_password_is_rejected_not_silently_accepted(self):
        token = self.login(OLD)[1]["token"]
        status, payload = self.post({"current": OLD, "new": OLD}, token)
        self.assertEqual(status, 400)
        self.assertIn("不能与当前密码相同", payload["error"]["message"])
        self.assertTrue(ca_settings.verify_panel_password(self.directory, OLD))

    def test_a_real_change_takes_effect_and_survives_a_restart(self):
        token = self.login(OLD)[1]["token"]
        status, payload = self.post({"current": OLD, "new": NEW}, token)
        self.assertEqual(status, 200)
        self.assertTrue(payload["synced_env"])
        # 改密码会吊销所有会话，也不发新令牌：前端据此回到登录页。
        self.assertNotIn("token", payload)
        status, again = self.post({"current": NEW, "new": "another-pass"}, token)
        self.assertEqual(status, 401)
        self.assertIn(SESSION_LOST, again["error"]["message"])

        self.assertEqual(self.login(NEW)[0], 200)
        self.assertEqual(self.login(OLD)[0], 401)
        with open(self.env_file, encoding="utf-8") as fh:
            self.assertIn("PANEL_PASSWORD=%s" % NEW, fh.read())
        self.assertEqual(ca_settings.panel_password_source(self.directory), "panel")

        # 重启时启动参数还是旧值：面板改过的密码必须赢。
        self.assertEqual(
            ca_settings.apply_launcher_password(self.directory, OLD), "kept")
        self.assertTrue(ca_settings.verify_panel_password(self.directory, NEW))

    def test_short_password_is_rejected(self):
        token = self.login(OLD)[1]["token"]
        status, payload = self.post({"current": OLD, "new": "abc"}, token)
        self.assertEqual(status, 400)
        self.assertIn("at least 4", payload["error"]["message"])


class PanelSessionSweepTests(unittest.TestCase):
    """create() 顺手清过期墓碑，会话字典才有界。

    过期条目原本只在本 token 再被验证时清除；浏览器再也不回来的 token 会
    在字典里躺满整个 TTL。登录是唯一新增源，所以清扫挂在 create() 上。
    """

    def test_expired_tokens_are_swept_on_the_next_login(self):
        sessions = ca_settings.PanelSessions(ttl=10 ** 9)
        stale = sessions.create()
        fresh = sessions.create()
        # 把第一个 token 的有效期拨到过去（绕过真实等待）
        sessions._tokens[stale] = 0.0
        sessions.create()
        self.assertNotIn(stale, sessions._tokens)
        self.assertIn(fresh, sessions._tokens)
        self.assertTrue(sessions.valid(fresh))
        self.assertFalse(sessions.valid(stale))


if __name__ == "__main__":
    unittest.main(verbosity=2)

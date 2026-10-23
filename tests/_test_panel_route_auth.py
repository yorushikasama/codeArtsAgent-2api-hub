"""Management routes answer to the panel session, not to an API key.

A management endpoint drawn in the web panel is reached with a panel session.
An API key is the credential for the model APIs; holding one is not a substitute
for the panel password. The two boundaries are separate, and the dispatcher is
where they are enforced - which is exactly why the two halves of one surface can
drift apart. The update-status read used to answer to `_authorized()` while
POST /updates/check was already panel-only, so a caller holding nothing but a
key could read the running version and the release status.

This suite drives the real do_GET/do_POST over an in-memory socket, so what it
pins is the dispatcher's behaviour rather than any handler's internals, and it
covers the management surface as a whole rather than the one route that was
fixed. Every route in the tables below must give the same four answers: an
anonymous caller is refused, an API key alone is refused, a wrong panel token
is refused, and a real panel session gets through.

The pricing table is the other half of that story: its writes were always
panel-only while the read answered to `_authorized()`, so an API key alone
could read the estimate and the resolved project-local file paths behind it.
The read is on the panel boundary now, and it is covered below like the rest.

No network: the model listing and the release checker are both injected.

    python tests/_test_panel_route_auth.py
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

from _isolated_dirs import isolated_data_dirs  # noqa: E402  (its own data root)

_TMP = isolated_data_dirs("wb-panel-route-auth-")

import ca_proxy as proxy  # noqa: E402
import ca_settings  # noqa: E402

KEY = "panel-route-key"
PANEL_ONLY_MESSAGE = "panel password required"
MODEL_ID = "injected-panel-route-model"
LATEST = "1.6.18"


def injected_catalog():
    """The model listing, without walking anything upstream.

    WorkBuddy 池删除后清单只来自码道目录，所以桩换成了 codearts_catalog。
    """
    return {"models": [{"id": MODEL_ID, "name": "Injected", "group": "builtin",
                        "supportsImages": False, "supportsReasoning": True,
                        "supportsToolCall": True}],
            "errors": {}}


class StubUpdates(object):
    """Stands in for the release checker: the boundary is what is under test."""

    def __init__(self):
        self.manual_checks = 0
        self.last = {"current_version": proxy.running_version(),
                     "latest_version": None, "update_available": False}

    def check(self, manual=False):
        self.manual_checks += 1
        self.last = {"current_version": proxy.running_version(),
                     "latest_version": LATEST, "update_available": True}
        return dict(self.last)

    def status(self):
        return dict(self.last)


class DispatchRequest(proxy.Handler):
    """A real Handler driven over an in-memory socket.

    Which boundary refuses a management route is a property of the dispatcher,
    not of the endpoint method, so the request has to go through the real
    do_GET/do_POST for the test to mean anything.
    """

    def __init__(self, path, headers=None, command="GET", body=b""):
        self.path = path
        self.command = command
        self.request_version = "HTTP/1.1"
        self.close_connection = True
        raw = "".join("%s: %s\r\n" % item for item in (headers or {}).items())
        self.headers = email.message_from_string(raw)
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status = None
        # 内存 socket 的对端就是回环；一键配置的可用性判定读的正是这个地址
        # （issue #246），远程那一侧在 RemoteAgentsTests 里改写它。
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
        """Run the real dispatcher and hand back status, JSON body, raw body."""
        getattr(self, "do_" + self.command)()
        raw = self.wfile.getvalue().decode("utf-8")
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = None      # the log export is plain text, not a document
        return self.status, payload, raw


class BoundaryCase(unittest.TestCase):
    """One management surface, one isolated settings directory per test."""

    # Management reads the panel draws, none of which is a model API.
    PANEL_ONLY_GET = ("/settings", "/updates", "/logs",
                      "/usage", "/pricing", "/activity/history")
    # The same boundary on a reply that is a file rather than a document.
    PANEL_ONLY_DOWNLOAD = ("/logs/export",)
    # The management writes, each guarded by its own panel check in do_POST.
    # /updates/check is the half of the update pair that was already correct;
    # the two pricing writes are the ones the panel's own buttons post to.
    PANEL_ONLY_POST = ("/updates/check", "/pricing/refresh",
                       "/pricing/mapping", "/settings/save")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="panel-route-")
        self.addCleanup(self._tmp.cleanup)
        self.directory = self._tmp.name
        ca_settings.set_api_keys(self.directory, [
            {"id": "k1", "name": "k", "key": KEY, "enabled": True}])
        self.updates = StubUpdates()

    def dispatch(self, path, headers=None, command="GET", body=b""):
        request = DispatchRequest(path, headers=headers, command=command, body=body)
        with mock.patch.multiple(proxy, ACCOUNTS_DIR=self.directory, API_KEY=None,
                                 PRICING=None, UPDATES=self.updates,
                                 codearts_catalog=injected_catalog,
                                 codearts_deployed=lambda: True,
                                 model_aliases=lambda: {}):
            return request.dispatch()

    def assert_refused(self, path, headers, command="GET", body=b""):
        status, payload, _raw = self.dispatch(path, headers, command, body)
        self.assertEqual(status, 401, "%s %s answered %s" % (command, path, status))
        self.assertIn(PANEL_ONLY_MESSAGE, payload["error"]["message"])
        # The refusal is the whole reply: nothing the route would have reported
        # may ride along with it.
        self.assertEqual(list(payload), ["error"],
                         "%s %s leaked a payload with its refusal" % (command, path))
        return payload

    def assert_reached(self, path, command="GET", body=b""):
        status, payload, raw = self.dispatch(path, self.session(), command, body)
        self.assertEqual(status, 200, "%s %s answered %s" % (command, path, status))
        self.assertNotIn(PANEL_ONLY_MESSAGE, raw)
        if payload is not None:
            self.assertNotIn("error", payload)
        return payload

    def session(self):
        return {"X-Panel-Token": proxy.PANEL.create()}

    def key_only(self):
        return {"Authorization": "Bearer " + KEY}


class PanelOnlyGetTests(BoundaryCase):
    """Every management read is closed to everything but a panel session."""

    def test_an_anonymous_caller_is_refused(self):
        for path in self.PANEL_ONLY_GET:
            with self.subTest(path=path):
                self.assert_refused(path, {})

    def test_an_api_key_alone_is_refused(self):
        for path in self.PANEL_ONLY_GET:
            with self.subTest(path=path):
                self.assert_refused(path, self.key_only())

    def test_a_wrong_panel_token_is_refused(self):
        for path in self.PANEL_ONLY_GET:
            with self.subTest(path=path):
                self.assert_refused(path, {"X-Panel-Token": "not-a-session"})

    def test_a_panel_session_reaches_every_route(self):
        for path in self.PANEL_ONLY_GET:
            with self.subTest(path=path):
                self.assert_reached(path)

    def test_the_log_export_is_on_the_same_boundary(self):
        # A reply that is a file rather than a document still carries the same
        # four answers.
        path = self.PANEL_ONLY_DOWNLOAD[0]
        self.assert_refused(path, {})
        self.assert_refused(path, self.key_only())
        self.assert_refused(path, {"X-Panel-Token": "not-a-session"})
        self.assert_reached(path)

    def test_the_update_status_is_not_readable_with_a_key(self):
        # The incident this contract comes from, asserted on the payload rather
        # than the code: the release status must not appear in a refusal.
        payload = self.assert_refused("/updates", self.key_only())
        self.assertNotIn("current_version", json.dumps(payload))
        body = self.assert_reached("/updates")
        self.assertEqual(body["current_version"], proxy.running_version())


class PanelOnlyPostTests(BoundaryCase):
    """The management writes are on the same boundary, not a special case."""

    def test_an_anonymous_caller_is_refused(self):
        for path in self.PANEL_ONLY_POST:
            with self.subTest(path=path):
                self.assert_refused(path, {}, command="POST", body=b"{}")

    def test_an_api_key_alone_is_refused(self):
        for path in self.PANEL_ONLY_POST:
            with self.subTest(path=path):
                self.assert_refused(path, self.key_only(), command="POST", body=b"{}")

    def test_a_wrong_panel_token_is_refused(self):
        for path in self.PANEL_ONLY_POST:
            with self.subTest(path=path):
                self.assert_refused(path, {"X-Panel-Token": "not-a-session"},
                                    command="POST", body=b"{}")

    def test_a_panel_session_reaches_every_route(self):
        for path in self.PANEL_ONLY_POST:
            with self.subTest(path=path):
                self.assert_reached(path, command="POST", body=b"{}")

    def test_the_manual_update_check_is_panel_only_too(self):
        # The other half of the update pair. It takes no body, so it is also the
        # case that proves the refusal happens before any body is read.
        self.assert_refused("/updates/check", self.key_only(), command="POST")
        body = self.assert_reached("/updates/check", command="POST")
        self.assertIs(body["ok"], True)
        self.assertEqual(body["latest_version"], LATEST)
        self.assertEqual(self.updates.manual_checks, 1,
                         "only the session may spend the check")


class ApiKeySurfaceTests(BoundaryCase):
    """The key boundary is unchanged, and it is a different check."""

    def test_an_api_key_still_reaches_the_model_listing(self):
        status, body, _raw = self.dispatch("/v1/models", self.key_only())
        self.assertEqual(status, 200)
        self.assertEqual([m["id"] for m in body["data"]], [MODEL_ID])

    def test_an_anonymous_api_call_is_refused_as_a_key_problem(self):
        # Not the panel message: the model APIs never moved onto the session
        # boundary, and a caller who forgot a key must be told that.
        status, body, _raw = self.dispatch("/v1/models")
        self.assertEqual(status, 401)
        self.assertIn("invalid api key", body["error"]["message"])
        self.assertNotIn(PANEL_ONLY_MESSAGE, body["error"]["message"])

    def test_a_panel_session_also_satisfies_the_key_check(self):
        # Why the panel boundary cannot be `_authorized()`: a session passes that
        # check too, so it cannot tell a session from a key. This is the property
        # that made the update-status mistake possible, and it is documented
        # behaviour rather than something this suite introduces.
        status, _body, _raw = self.dispatch("/v1/models", self.session())
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)

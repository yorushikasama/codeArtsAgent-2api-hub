"""写请求体与等响应头拆成两个超时预算（2026-11-15 线上事故修复）。

## 事故是什么

22 次 502，**全部**是链路层异常（``write operation timed out`` 15 次、
``EOF occurred in violation of protocol`` 6 次、nginx 502 一例），上游一次
明确拒绝都没有。同期 <100k 字符的小请求 1187 个**零失败**。

根因：``urllib.request.urlopen(req, timeout=t)`` 的 t 是 **socket 全局
超时**，``h.request()``（写 body）与 ``h.getresponse()``（读响应头）共用它。
上游读超大 body 本身要 9~21 秒（线上实测），这些秒数从「等响应头」的
120 秒里扣；扣光了就报 ``write operation timed out`` —— 上游一个字节都没
拒绝，是网关自己把预算用完了。

## 这些用例钉住的行为

  · 写 body 的超时**不受**响应头超时影响（两者不再共用一份预算）；
  · HTTP 错误状态仍然抛 ``urllib.error.HTTPError``（429 排队协议依赖
    ``exc.code`` / ``exc.headers`` / ``exc.read()``）；
  · socket 层错误仍然包成 ``URLError``（上层按它归类「瞬时、可重试」）；
  · 写超时的预算随 body 体积增长。
"""
import http.server
import os
import socket
import sys
import threading
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_codearts


class _Handler(http.server.BaseHTTPRequestHandler):
    """回显型服务：把收到的 body 长度记下来。"""

    protocol_version = "HTTP/1.1"
    received = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _Handler.received = len(body)
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _SlowReadServer(http.server.BaseHTTPRequestHandler):
    """读完 body 之后，拖 N 秒才回响应头 —— 用来逼出「写预算 vs 读预算」。"""

    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        import time
        time.sleep(_SlowReadServer.delay)
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def _start_server(handler_cls):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, srv.server_address[1]


class WriteTimeoutBudgetTests(unittest.TestCase):
    def test_write_timeout_grows_with_body(self):
        small = ca_codearts._write_timeout_for(1024)
        big = ca_codearts._write_timeout_for(2 * 1024 * 1024)
        self.assertLess(small, big)
        # 上限不超过配置值
        self.assertLessEqual(big, ca_codearts.CHAT_WRITE_TIMEOUT)
        # 下限不为 0
        self.assertGreaterEqual(small, 1.0)

    def test_write_timeout_tolerates_junk(self):
        for raw in (None, "", "abc", -5):
            self.assertGreater(ca_codearts._write_timeout_for(raw), 0)

    def test_small_body_still_gets_a_real_budget(self):
        # 不能因为「body 小」就给 0 或极小的值 —— socket 写不出去时立刻
        # 报错，不会白等到超时。
        self.assertGreaterEqual(ca_codearts._write_timeout_for(10),
                                ca_codearts.CHAT_WRITE_TIMEOUT * 0.5)


class SplitSendTests(unittest.TestCase):
    """``_send_chat_post`` 的行为契约。"""

    def setUp(self):
        self.srv, self.port = _start_server(_Handler)
        self.url = "http://127.0.0.1:%d/x" % self.port

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_posts_body_and_reads_response(self):
        body = b"hello world"
        resp = ca_codearts._send_chat_post(self.url, body,
                                             {"Content-Type": "application/json"},
                                             write_timeout=10, read_timeout=10)
        try:
            self.assertEqual(resp.status, 200)
            self.assertEqual(_Handler.received, len(body))
        finally:
            resp.close()

    def test_http_error_becomes_urllib_http_error(self):
        """429 排队协议依赖 HTTPError.code / .headers / .read()。"""
        class _Err(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                payload = b'{"error":"busy"}'
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("queue-status", "queued")
                self.send_header("trace-id", "t-123")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        srv, port = _start_server(_Err)
        try:
            url = "http://127.0.0.1:%d/x" % port
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                ca_codearts._send_chat_post(url, b"{}", {}, 10, 10)
            exc = ctx.exception
            self.assertEqual(exc.code, 429)
            self.assertEqual(exc.headers.get("queue-status"), "queued")
            self.assertIn(b"busy", exc.read())
        finally:
            srv.shutdown()
            srv.server_close()

    def test_connection_refused_becomes_url_error(self):
        # 端口 1 基本没人听 —— 连不上必须是 URLError（上层按它归类
        # 「瞬时链路故障、可重试」）。
        with self.assertRaises(urllib.error.URLError):
            ca_codearts._send_chat_post("http://127.0.0.1:1/x", b"{}", {},
                                         5, 5)

    def test_read_timeout_is_separate_from_write_timeout(self):
        """服务端读完 body 后拖一会儿才回响应头。

        拖 1.5 秒，读超时给 5 秒 —— 必须成功。这条钉住「等响应头」用的是
        读超时而不是写超时：反过来（读超时比写超时短）时，用 body 大到
        需要长写预算的请求就会被误杀。
        """
        _SlowReadServer.delay = 1.5
        srv, port = _start_server(_SlowReadServer)
        try:
            url = "http://127.0.0.1:%d/x" % port
            resp = ca_codearts._send_chat_post(url, b"x" * 1024, {},
                                                 write_timeout=30,
                                                 read_timeout=5)
            try:
                self.assertEqual(resp.status, 200)
            finally:
                resp.close()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_read_timeout_still_fires(self):
        """读超时不能被写预算顶掉 —— 否则慢上游会永远挂着。"""
        _SlowReadServer.delay = 2.5
        srv, port = _start_server(_SlowReadServer)
        try:
            url = "http://127.0.0.1:%d/x" % port
            with self.assertRaises(urllib.error.URLError):
                ca_codearts._send_chat_post(url, b"x", {}, write_timeout=30,
                                             read_timeout=0.5)
        finally:
            srv.shutdown()
            srv.server_close()


class HeaderFidelityTests(unittest.TestCase):
    """自己重写 urllib 的发送，头必须发得一模一样。

    2026-11-22 线上 A/B 实测踩到的坑：``http.client.putrequest`` 的
    ``skip_accept_encoding=True`` 会让它**什么都不加**，而 urllib 发的是
    ``Accept-Encoding: identity``。少了这一个头，上游网关直接回 nginx 风格
    的 400 Bad Request —— 不是上游的业务错误，是请求根本没进门。

    这条用例把「实际发出的头」钉住：比对着 urllib 在本地 server 上抓一份
    真实的头，两边必须一致。
    """

    def setUp(self):
        self.srv, self.port = _start_server(_Handler)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _capture_with_urllib(self):
        import http.server
        seen = {}

        class _Cap(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                seen["h"] = {k.lower(): v for k, v in self.headers.items()}
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                p = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(p)))
                self.end_headers()
                self.wfile.write(p)

            def log_message(self, *args):
                pass

        srv, port = _start_server(_Cap)
        try:
            import urllib.request
            urllib.request.urlopen(
                urllib.request.Request("http://127.0.0.1:%d/x" % port,
                                       data=b"hello",
                                       headers={"Content-Type": "application/json"},
                                       method="POST"),
                timeout=10).close()
        finally:
            srv.shutdown()
            srv.server_close()
        return seen.get("h") or {}

    def _capture_with_split(self):
        import http.server
        seen = {}

        class _Cap(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                seen["h"] = {k.lower(): v for k, v in self.headers.items()}
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                p = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(p)))
                self.end_headers()
                self.wfile.write(p)

            def log_message(self, *args):
                pass

        srv, port = _start_server(_Cap)
        try:
            url = "http://127.0.0.1:%d/x" % port
            resp = ca_codearts._send_chat_post(url, b"hello",
                                                 {"Content-Type": "application/json"},
                                                 write_timeout=10, read_timeout=10)
            resp.close()
        finally:
            srv.shutdown()
            srv.server_close()
        return seen.get("h") or {}

    def test_same_headers_as_urllib(self):
        urllib_headers = self._capture_with_urllib()
        split_headers = self._capture_with_split()
        self.assertTrue(urllib_headers, "urllib 那次没抓到头")
        self.assertTrue(split_headers, "自己发的那次没抓到头")
        for name in ("accept-encoding", "content-type", "content-length",
                     "connection"):
            self.assertIn(name, urllib_headers)
            self.assertEqual(split_headers.get(name), urllib_headers.get(name),
                             "头 %s 与 urllib 不一致：urllib=%r ours=%r"
                             % (name, urllib_headers.get(name),
                                split_headers.get(name)))

    def test_accept_encoding_identity_is_present(self):
        """少这个头就是 400 —— 单独钉一条，免得被当成无关细节。"""
        headers = self._capture_with_split()
        self.assertEqual(headers.get("accept-encoding"), "identity")


class OpenChatBudgetTests(unittest.TestCase):
    """``open_chat`` 走的是分阶段发送，且两段预算不同。"""

    def test_open_chat_uses_split_send(self):
        captured = {}
        orig = ca_codearts._send_chat_post

        def fake(url, body, headers, write_timeout, read_timeout):
            captured["url"] = url
            captured["len"] = len(body)
            captured["write_timeout"] = write_timeout
            captured["read_timeout"] = read_timeout
            raise RuntimeError("stop here")

        ca_codearts._send_chat_post = fake
        try:
            with self.assertRaises(RuntimeError):
                ca_codearts.open_chat("ak", "sk", "st", "glm-5.3",
                                      [{"role": "user", "content": "x"}],
                                      max_tokens=100, timeout=120.0)
        finally:
            ca_codearts._send_chat_post = orig
        self.assertEqual(captured["read_timeout"], 120.0)
        self.assertGreater(captured["write_timeout"], captured["read_timeout"],
                           "写 body 的预算必须比等响应头宽裕，否则大 body "
                           "会被自己掐掉")

    def test_write_budget_exceeds_header_budget_for_big_body(self):
        big = ca_codearts._write_timeout_for(1_200_000)
        self.assertGreater(big, 120.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""码道上游「断流」的回归测试。

2026-10-22 线上事故：上游 chunked 流不发终止块直接关连接，``iter_sse`` 里的
``read1`` 抛 ``http.client.IncompleteRead``，而三类协议入口都没接 —— 异常一路
冒到 ``socketserver.process_request_thread``，客户端拿到的是「200 + 半截 delta，
然后连接凭空消失」：既没有 ``finish_reason`` 也没有 ``[DONE]``。前端表现就是
用户说的「直接断流」。

这里钉住四件事：
1. 读侧把网络中断翻译成 ``UpstreamBroken``，并带上已收字节数；
2. 首帧之前断流 → 回干净的错误码（而不是已经 200 了再无声消失），且会换号重开；
3. 已经吐过内容再断 → 补 finish + [DONE] 收尾，不换号；
4. 重开成功时，客户端只看到一份完整回答（不会出现两个 role 开场帧）。

不联网。
"""

import http.client
import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C  # noqa: E402
import ca_proxy as P     # noqa: E402

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def section(name):
    print("\n" + name)


# ---------------------------------------------------------------------------
# 1. 读侧：IncompleteRead → UpstreamBroken
# ---------------------------------------------------------------------------

section("1. iter_sse 把上游断流翻译成 UpstreamBroken")


class _Resp:
    """最小 HTTPResponse 替身：先给若干块，然后按给定异常失败。"""

    def __init__(self, pieces, exc=None):
        self._pieces = list(pieces)
        self._exc = exc

    def read1(self, _n):
        if self._pieces:
            return self._pieces.pop(0)
        if self._exc is None:
            return b""                 # 正常 EOF
        raise self._exc


_chunk = b'data: {"choices":[{"delta":{"content":"\xe4\xbd\xa0"}}]}\n\n'
_lines, _stats = [], {}
try:
    for _line in C.iter_sse(_Resp([_chunk], http.client.IncompleteRead(b"")),
                            stats=_stats):
        _lines.append(_line)
    check("断流要抛 UpstreamBroken（不能静默当 EOF）", False)
except C.UpstreamBroken as _exc:
    check("断流抛 UpstreamBroken", True)
    check("已读到的整行照常吐出", "".join(_lines) == _chunk.decode("utf-8"), _lines)
    check("received 记录已收字节数", _exc.received == len(_chunk), _exc.received)
    check("stats 标记 truncated", _stats.get("truncated") is True, _stats)

# 正常 EOF（读到空块）绝不能算断流 —— 那是每条流都走的路
_lines = []
try:
    _lines = list(C.iter_sse(_Resp([_chunk], None)))
    check("正常 EOF 不抛", True)
except Exception as _exc:                     # noqa: BLE001
    check("正常 EOF 不抛", False, _exc)

check("正常 EOF 仍吐出全部行", "".join(_lines) == _chunk.decode("utf-8"), _lines)

# 连接被重置（不是 IncompleteRead，是 OSError 家族）也要收敛
_lines = []
try:
    list(C.iter_sse(_Resp([], ConnectionResetError("peer reset"))))
    check("ConnectionResetError 也翻译成 UpstreamBroken", False)
except C.UpstreamBroken:
    check("ConnectionResetError 也翻译成 UpstreamBroken", True)


# ---------------------------------------------------------------------------
# 2. 协议层：三种断流位置的收尾
# ---------------------------------------------------------------------------

section("2. chat 流式在三种断流位置的行为")


class _Handler(P.Handler):
    def __init__(self):
        self.path = "/v1/chat/completions"
        self.wfile = io.BytesIO()
        self.status = None
        self.payload = None
        self.open_calls = 0

    def _client_disconnected(self):
        return False

    def _json(self, code, obj):
        self.status = code
        self.payload = obj
        return code, obj

    def _handle_expect_continue(self):
        pass

    def _discard_body(self):
        pass

    def send_response(self, code):
        self.status = code

    def send_header(self, _k, _v):
        pass

    def end_headers(self):
        pass

    def _key_id(self):
        return "test-key"


class _Lease:
    account_label = "stub-label"
    account_key = "stub-key"

    def __init__(self, lines, broken_after=None):
        self._lines = list(lines)
        self._broken_after = broken_after
        self.started_at = time.time()
        self.closed = False

    def lines(self, _abort_check=None, _stats=None):
        for i, line in enumerate(self._lines):
            if self._broken_after is not None and i >= self._broken_after:
                raise C.UpstreamBroken("upstream closed early", 0)
            yield line
        if self._broken_after is not None:
            raise C.UpstreamBroken("upstream closed early", 0)

    def byte_lines(self, _abort_check=None, _stats=None):
        for line in self.lines(_abort_check, _stats):
            yield line.encode("utf-8")

    def close(self):
        self.closed = True


def _run(leases):
    """依次把 leases 发给 handler，返回 handler 与解码后的 SSE 文本。"""
    h = _Handler()
    seq = list(leases)

    def _open(*_a, **_k):
        h.open_calls += 1
        return None, (seq.pop(0) if seq else _Lease([], 0))

    h._codearts_open_lease = _open
    h._handle_codearts_chat_stream({
        "model": "glm-5.3", "stream": True,
        "messages": [{"role": "user", "content": "hi"}]})
    return h, h.wfile.getvalue().decode("utf-8")


# 2a. 一帧都没来就断：头不能发，要回真错误码，并且换号重开一次
_h, _sse = _run([_Lease([], 0), _Lease([], 0)])
check("首帧前断流回 502（不是 200 + 空连接）", _h.status == 502, _h.status)
check("首帧前断流不写任何 SSE 帧", _sse == "", _sse[:120])
check("首帧前断流会换号重开一次", _h.open_calls == 2, _h.open_calls)

# 2b. 重开成功：客户端只看到一份完整回答
_role = 'data: {"choices":[{"delta":{"content":"你"}}]}\n\n'
_tail = 'data: {"choices":[{"delta":{"content":"好"},"finish_reason":"stop"}]}\n\n'
_h, _sse = _run([_Lease([], 0), _Lease([_role, _tail], None)])
check("重开后正常收尾为 200", _h.status == 200, _h.status)
check("重开后内容完整", "你" in _sse and "好" in _sse, _sse[-200:])
check("重开不会让客户端看到两个 role 开场帧",
      _sse.count('"role": "assistant"') == 1, _sse.count('"role": "assistant"'))
check("重开后以 [DONE] 收尾", _sse.endswith("data: [DONE]\n\n"), _sse[-40:])

# 2c. 已经吐过内容再断：发 error 帧收尾，绝不重开、也绝不补 stop
_h, _sse = _run([_Lease([_role], 1), _Lease([_tail], None)])
check("出过内容后断流仍是 200", _h.status == 200, _h.status)
check("出过内容后断流不重开", _h.open_calls == 1, _h.open_calls)
check("断流不伪装成正常结束（不补 finish_reason=stop）",
      '"finish_reason": "stop"' not in _sse, _sse[-200:])
check("断流发明确的 error 帧", '"upstream_error"' in _sse, _sse[-300:])
check("断点补 [DONE]", _sse.endswith("data: [DONE]\n\n"), _sse[-40:])

# 2d. 上游在流里回错误帧（不是断流）：首帧前仍能回真错误码，
#     而且状态码要按错误码映射 —— 1041 是「等会儿重试」的 429，不是 502。
_err_frame = ('data: {"error_code":"TM.00001041",'
              '"error_msg":"\\u5e76\\u53d1\\u4e0a\\u9650"}\n\n')
_h, _sse = _run([_Lease([_err_frame], None), _Lease([_err_frame], None)])
check("首帧即 1041 → 429（限流语义）", _h.status == 429, _h.status)
check("首帧即错误帧 → 不写 SSE", _sse == "", _sse[:120])

_param_err = ('data: {"error_code":"InferHub.001001005.400",'
              '"error_msg":"The request param is invalid"}\n\n')
_h, _sse = _run([_Lease([_param_err], None), _Lease([_param_err], None)])
check("首帧即参数错 → 400（不诱导重试）", _h.status == 400, _h.status)


# ---------------------------------------------------------------------------
# 3. Responses / Messages 也要有断流收尾
# ---------------------------------------------------------------------------

section("3. 另外两个入口的断流收尾")


class _AnthropicError(Exception):
    pass


_h = _Handler()
_h.path = "/v1/messages"
_h._codearts_open_lease = lambda *_a, **_k: (None, _Lease([_role], 1))
_h._messages_codearts_stream(
    {"model": "glm-5.3", "stream": True,
     "messages": [{"role": "user", "content": "hi"}]},
    lambda code, msg, _t=None: _h._json(code, {"error": msg}))
_sse = _h.wfile.getvalue().decode("utf-8")
check("messages 断流后发 event: error", "event: error" in _sse, _sse[-300:])
check("messages 断流前的内容已下发", "你" in _sse, _sse[-300:])

_h = _Handler()
_h.path = "/v1/responses"
_h._codearts_open_lease = lambda *_a, **_k: (None, _Lease([_role], 1))
_h._responses_codearts(
    {"model": "glm-5.3", "stream": True,
     "messages": [{"role": "user", "content": "hi"}]},
    True, set(), {"tools": []}, None)
_sse = _h.wfile.getvalue().decode("utf-8")
check("responses 断流后发 response.failed", "response.failed" in _sse, _sse[-400:])
check("responses 断流仍以 [DONE] 收尾",
      _sse.rstrip().endswith("[DONE]"), _sse[-80:])


# ---------------------------------------------------------------------------
# 4. 会话名额：busy 登记 / idle 注销（2026-10-22 上游并发闸的真相）
# ---------------------------------------------------------------------------

section("4. 会话名额心跳")

check("new_session_id 是 32 位十六进制", len(C.new_session_id()) == 32
      and all(ch in "0123456789abcdef" for ch in C.new_session_id()),
      C.new_session_id())

_hdr = C.chat_headers("AK", "SK", "TK", "0" * 64, stream=True,
                      session_id="abc123")
check("聊天请求头带 user-session-id",
      _hdr.get("user-session-id") == "abc123", list(_hdr)[:8])
check("user-session-id 参与签名",
      "user-session-id" in _hdr.get("Authorization", ""), _hdr.get("Authorization"))

_calls = []
_saved_hb = C.heartbeat
C.heartbeat = lambda *a, **k: (_calls.append(a[3:]), (True, "ok"))[1]
try:
    _l = P._CodeartsLease(None, "lbl", time.time(), "k",
                          session_id="sid", session_cred=("AK", "SK", "TK"))
    _l.resp = type("R", (), {"close": lambda self: None})()
    _l.close()
    _l.close()                       # 幂等：不能重复 idle
    check("租约关闭时注销会话（idle 恰好一次）",
          [c[0] for c in _calls] == ["sid"], _calls)
    check("idle 状态传对了", _calls and _calls[0][1] == "idle", _calls)

    # 续期：间隔内不发，过了间隔才发
    _calls.clear()
    _l2 = P._CodeartsLease(None, "lbl", time.time(), "k",
                           session_id="sid2", session_cred=("AK", "SK", "TK"))
    _l2.resp = type("R", (), {"close": lambda self: None})()
    check("同一间隔内不重复续期", _l2.keepalive() is False, _calls)
    _l2._last_ping -= (P.CODEARTS_SESSION_PING + 1)
    check("超过间隔后续期一次 busy", _l2.keepalive() is True, _calls)
    check("续期发的是 busy", _calls and _calls[-1][1] == "busy", _calls)
    _l2.close()
finally:
    C.heartbeat = _saved_hb


# ---------------------------------------------------------------------------
# 5. 错误语义映射（照 CodeArts2API-Go 的 apierr 表）
# ---------------------------------------------------------------------------

section("5. 上游错误 → 对外状态码")

_spec = P._codearts_fail_spec
check("并发会话满（HTTP 400 + TM.00001041）→ 429 而不是 502",
      _spec(400, "TM.00001041", "并发会话数已达上限(3个)")[0] == 429,
      _spec(400, "TM.00001041", ""))
check("TPM 限流（429）→ 429", _spec(429, "", "")[0] == 429)
check("max_tokens 超限（001001005）→ 400（重试同样的请求没用）",
      _spec(400, "InferHub.001001005.400", "The request param is invalid")[0] == 400)
check("模型未注册（002002009）→ 404",
      _spec(404, "InferHub.002002009", "model is not registered")[0] == 404)
check("鉴权失败（401）→ 502 + credentials_error",
      _spec(401, "APIG.0301", "access key not found")
      == (502, "credentials_error"), _spec(401, "APIG.0301", ""))
check("Anthropic 那边同一情况用 authentication_error",
      _spec(401, "APIG.0301", "", anthropic=True)[1] == "authentication_error")
check("STS 续期票被用过（STS5.1806）→ credentials_error",
      _spec(400, "STS5.1806", "the refresh token has been used")[1]
      == "credentials_error")
check("上游 5xx → 502 upstream_error", _spec(503, "", "") == (502, "upstream_error"))

# 429 必须带 Retry-After，否则客户端只能盲猜
_h = _Handler()
_h.path = "/v1/chat/completions"
_ret = _h._codearts_fail(400, "TM.00001041", "并发会话数已达上限", "acct")
check("限流响应返回「已响应」哨兵（二元组才不会继续往下走）",
      _ret is P.RESPONDED, _ret)
check("限流响应状态是 429", _h.status == 429, _h.status)
print("    (Retry-After 由 send_header 发出，_Handler 桩不记录)")


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

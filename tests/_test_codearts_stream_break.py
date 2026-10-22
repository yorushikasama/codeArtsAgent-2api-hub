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
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C  # noqa: E402
import ca_settings as S   # noqa: E402
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
check("福利渠道没权益（4004.200 benefit not found）→ 404（重试无用）",
      _spec(502, "InferHub.4004.200", "benefit not found")[0] == 404,
      _spec(502, "InferHub.4004.200", "benefit not found"))

# 没有权益的模型要在一段时间内从清单里消失（否则广告一个必错的模型）
P.mark_benefit_missing("gemini-x")
check("记下无权益模型", P.benefit_missing("gemini-x") is True, None)
check("没记过的模型不受影响", P.benefit_missing("other") is False, None)

# 429 必须带 Retry-After，否则客户端只能盲猜
_h = _Handler()
_h.path = "/v1/chat/completions"
_ret = _h._codearts_fail(400, "TM.00001041", "并发会话数已达上限", "acct")
check("限流响应返回「已响应」哨兵（二元组才不会继续往下走）",
      _ret is P.RESPONDED, _ret)
check("限流响应状态是 429", _h.status == 429, _h.status)
print("    (Retry-After 由 send_header 发出，_Handler 桩不记录)")


# ---------------------------------------------------------------------------
# 6. 上游静默 → 给客户端发心跳（而不是让中间层把连接掐了）
# ---------------------------------------------------------------------------

section("6. 上游静默的空关心跳")


class _Sock:
    """记录「有没有人改过它的读超时」—— 这是 2026-10-22 线上事故的回归护栏。"""

    def __init__(self, timeout=300.0):
        self.timeout = timeout
        self.set_calls = []

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.set_calls.append(value)
        self.timeout = value

    def fileno(self):
        return 3

    def pending(self):
        return 0


class _Raw:
    def __init__(self, sock):
        self._sock = sock


class _FP:
    def __init__(self, sock):
        self.raw = _Raw(sock)


class _DataResp:
    """read1 按剧本吐字节；空闲改由 _wait_readable 的脚本控制。"""

    def __init__(self, script, sock):
        self.script = list(script)
        self.closed = False
        self.fp = _FP(sock) if sock is not None else None

    def read1(self, _n):
        item = self.script.pop(0) if self.script else b""
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


_wait_script = []


def _fake_wait(_sock, _timeout):
    return _wait_script.pop(0) if _wait_script else True


_saved_wait = C._wait_readable
C._wait_readable = _fake_wait
try:
    # 第 1 条：静默一次 → 吐 KEEPALIVE，然后照常读同一根连接
    _sock = _Sock()
    _resp = _DataResp(
        [b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n', b""], _sock)
    _wait_script[:] = [False, True]
    _seen = list(C.iter_sse(_resp, idle_timeout=15))
    check("静默时吐 KEEPALIVE 哨兵", any(x is C.KEEPALIVE for x in _seen), _seen)
    check("静默之后照常读出后续行",
          any(isinstance(x, str) and x.startswith("data:") for x in _seen), _seen)
    check("KEEPALIVE 不是字符串（不能混进 SSE 正文）",
          all(not isinstance(x, str) for x in _seen if x is C.KEEPALIVE), _seen)
    # 事故根因：以前把 socket 读超时压到 15s，超时后 SocketIO 被标记
    # timed_out，之后每次 read 都抛 "cannot read from timed out object"，
    # 好好的流被自己弄断。心跳只能用 select 看 fd，绝不能碰超时。
    check("心跳路径绝不改 socket 读超时", _sock.set_calls == [], _sock.set_calls)

    # 第 2 条：连续静默到上限 → UpstreamBroken，而不是永远挂着
    _wait_script[:] = [False] * 10
    _broken = None
    try:
        list(C.iter_sse(_DataResp([b""], _Sock()), idle_timeout=15, max_idle=3))
    except C.UpstreamBroken as exc:
        _broken = exc
    check("连续静默超过上限 → UpstreamBroken", _broken is not None, _broken)

    # 第 3 条：拿不到 socket（假对象 / 老版本 http.client）→ 不发心跳，
    # 此时真撞上读超时说明连接已经废了，按断流处理
    _wait_script[:] = []
    _broken2 = None
    try:
        list(C.iter_sse(_DataResp([TimeoutError("timed out"), b""], None),
                        idle_timeout=15))
    except C.UpstreamBroken as exc:
        _broken2 = exc
    check("拿不到 socket 时不假装心跳，超时按断流处理",
          _broken2 is not None, _broken2)

    # 第 4 条：select 不可用（返回 None）时退回阻塞读，不能把好流弄断
    _wait_script[:] = [None]
    _fallback = _DataResp([b"data: ok\n\n", b""], _Sock())
    check("等不了的时候照样把流读完",
          "".join(list(C.iter_sse(_fallback, idle_timeout=15))) == "data: ok\n\n",
          None)
finally:
    C._wait_readable = _saved_wait

# 第 5 条：真实的 _wait_readable —— socketpair 验「有数据 / 没数据」
import socket as _socket

_left, _right = _socket.socketpair()
try:
    check("没数据 → 超时返回 False", C._wait_readable(_left, 0.05) is False, None)
    _right.sendall(b"x")
    check("有数据 → 返回 True", C._wait_readable(_left, 0.5) is True, None)
finally:
    _left.close()
    _right.close()


class _PendingSock:
    def pending(self):
        return 3

    def fileno(self):
        raise AssertionError("pending()>0 时不该再去 select")


check("TLS 已解密未交付的字节算「可读」",
      C._wait_readable(_PendingSock(), 0.01) is True, None)
check("拿不到 fileno 的对象 → None（调用方退回阻塞读）",
      C._wait_readable(object(), 0.05) is None, None)

# 哨兵在 _tap_codearts_sse 里翻成 SSE 注释行
_tapped = list(P._tap_codearts_sse([C.KEEPALIVE, b'data: {"usage":{"total_tokens":7}}\n\n'], {}))
check("哨兵翻成 SSE 注释行", _tapped[0] == b": keepalive\n\n", _tapped[:1])


# ---------------------------------------------------------------------------
# 7. 模型名归一（大小写无关）—— 上游 id 大小写是混的，客户端习惯小写
# ---------------------------------------------------------------------------

section("7. 模型名归一")

check("小写 glm-5.2 解析成上游真名 GLM-5.2", C.resolve_model("glm-5.2") == "GLM-5.2",
      C.resolve_model("glm-5.2"))
check("大写 GLM-5.3 解析成小写真名 glm-5.3", C.resolve_model("GLM-5.3") == "glm-5.3",
      C.resolve_model("GLM-5.3"))
check("混合大小写 Qwen3-VL-235B 也认",
      C.resolve_model("qwen3-vl-235b") == "Qwen3-VL-235B",
      C.resolve_model("qwen3-vl-235b"))
check("认不出的名字原样返回（不编近似名）", C.resolve_model("gpt-4o") == "gpt-4o",
      C.resolve_model("gpt-4o"))
check("空值不炸", C.resolve_model(None) == "" and C.resolve_model("") == "",
      (C.resolve_model(None), C.resolve_model("")))

check("小写的福利模型判对分组（否则不带 maas_type → 002002009）",
      C.model_group("DeepSeek-V4.1-Flash") == C.GROUP_BENEFIT,
      C.model_group("DeepSeek-V4.1-Flash"))
check("小写的内置模型仍是内置", C.model_group("GLM-5.3") == C.GROUP_BUILTIN,
      C.model_group("GLM-5.3"))

check("小写模型名也夹得住 max_tokens（否则 128000 原样上去 → 001001005）",
      C.clamp_max_tokens("glm-5.2", 128000) == (65536, True),
      C.clamp_max_tokens("glm-5.2", 128000))
check("表里没有的模型不夹", C.clamp_max_tokens("gpt-4o", 128000) == (128000, False),
      C.clamp_max_tokens("gpt-4o", 128000))

check("小写模型名判为码道模型（否则掉进 WorkBuddy 空池 → 503）",
      P.is_codearts_model("glm-5.2") is True, P.is_codearts_model("glm-5.2"))
check("真·外部模型不算码道", P.is_codearts_model("gpt-4o") is False,
      P.is_codearts_model("gpt-4o"))

_norm = {"model": "glm-5.2", "messages": []}
P.canonicalize_model(_norm)
check("canonicalize_model 就地改成真名", _norm["model"] == "GLM-5.2", _norm["model"])
_norm2 = {"model": "gpt-4o"}
P.canonicalize_model(_norm2)
check("canonicalize_model 不动认不出的名字", _norm2["model"] == "gpt-4o", _norm2["model"])


# ---------------------------------------------------------------------------
# 8. 会话粘性：同一条对话的多轮落在同一个账号上
# ---------------------------------------------------------------------------

section("8. 会话粘性")

_k = P.codearts_session_key({"X-Conversation-Id": "conv-1"},
                            {"messages": [{"role": "user", "content": "x" * 60}]})
check("显式会话头优先于消息指纹", _k == "k:conv-1", _k)

_k2 = P.codearts_session_key({}, {"metadata": {"conversation_id": "conv-2"},
                                  "messages": [{"role": "user", "content": "x" * 60}]})
check("metadata.conversation_id 也算显式", _k2 == "k:conv-2", _k2)

_k3 = P.codearts_session_key({}, {"user": "alice",
                                  "messages": [{"role": "user", "content": "x" * 60}]})
check("user 字段次之", _k3 == "u:alice", _k3)

_long = "帮我修一下这个 Python 脚本里读文件的编码问题，它总是报 UnicodeDecodeError"
_k4 = P.codearts_session_key({}, {"messages": [
    {"role": "system", "content": "sys"},
    {"role": "user", "content": _long},
    {"role": "assistant", "content": "好的"},
    {"role": "user", "content": "继续"}]})
_k5 = P.codearts_session_key({}, {"messages": [
    {"role": "system", "content": "sys"},
    {"role": "user", "content": _long},
    {"role": "assistant", "content": "好的"},
    {"role": "user", "content": "再改一处"},
    {"role": "assistant", "content": "ok"},
    {"role": "user", "content": "谢谢"}]})
check("同一对话的后续轮次指纹不变（首条 user 消息稳定）", _k4 == _k5, (_k4, _k5))
check("指纹是 p: 前缀 + 16 位", _k4.startswith("p:") and len(_k4) == 18, _k4)

_short = P.codearts_session_key({}, {"messages": [{"role": "user", "content": "hi"}]})
check("太短的消息不当指纹（'hi' 会撞车）", _short is None, _short)
check("什么都没有就返回 None（不猜）", P.codearts_session_key(None, {}) is None,
      P.codearts_session_key(None, {}))

# 池子：remember 之后，同一条对话优先回到那个号
class _StubPool(P._CodeartsAccountPool):
    def __init__(self, keys, state_dir=None):
        # 默认用临时目录：粘性现在会落盘，绝不能写进仓库的 accounts/。
        P._CodeartsAccountPool.__init__(
            self, state_dir=state_dir or tempfile.mkdtemp(prefix="affinity-"))
        self._keys = keys

    def _usable(self):
        return [{"account": {"id": k}} for k in self._keys]


_pool = _StubPool(["acct-a", "acct-b"])
_session, _key = _pool.acquire(0, session_key="k:conv-9")
_pool.remember("k:conv-9", "acct-b")
_seen = []
for _i in range(6):
    _sess, _k = _pool.acquire(0, session_key="k:conv-9")
    _seen.append(_k)
    _pool.release(_k)
check("绑定后每一轮都落回同一个号", set(_seen) == {"acct-b"}, _seen)
_rot = []
for _i in range(6):
    _sess_r, _key_r = _pool.acquire(0)
    _rot.append(_key_r)
    _pool.release(_key_r)
check("不粘的对话仍会轮转（粘性不冻结负载）", set(_rot) == {"acct-a", "acct-b"},
      _rot)

# 绑定过期：不该再钉住
_pool.remember("k:old", "acct-a", now=time.time() - P.CODEARTS_AFFINITY_TTL - 5)
check("粘性过期后不再生效", _pool._sticky("k:old") is None, _pool._sticky("k:old"))

# 绑定的号不可用（不在池里）时不能卡住
_pool.remember("k:gone", "acct-z")
_sess2, _key2 = _pool.acquire(0, session_key="k:gone")
check("绑定的号不在池里时正常换号", _key2 in ("acct-a", "acct-b"), _key2)


# ---------------------------------------------------------------------------
# 9. 模型别名：客户端自己的模型名 → 码道真名
# ---------------------------------------------------------------------------

section("9. 模型别名映射")

import json as _json
import os as _os
import shutil as _shutil
import tempfile as _tempfile

_alias_dir = _tempfile.mkdtemp(prefix="aliases-")
_saved_dir = P.ACCOUNTS_DIR
P.ACCOUNTS_DIR = _alias_dir
P._MODEL_ALIASES.update({"mtime": -2.0, "map": {}})
try:
    _alias_path = _os.path.join(_alias_dir, P.MODEL_ALIASES_FILE)

    check("没有别名文件时是空表", P.model_aliases() == {}, P.model_aliases())

    with open(_alias_path, "w", encoding="utf-8") as _fh:
        _json.dump({
            "claude-sonnet-4-5-20250929": "glm-5.3",
            "claude-opus-4-1": "GLM-5.2",
            "gpt-5-codex": "glm-5.2",
            "": "ignored",
            "broken": 42,
        }, _fh)
    _os.utime(_alias_path, (_os.path.getatime(_alias_path), _os.path.getmtime(_alias_path) + 1))

    _map = P.model_aliases()
    check("读到别名表（键统一小写）",
          _map.get("claude-sonnet-4-5-20250929") == "glm-5.3", _map)
    check("空键与非字符串值被丢掉", "" not in _map and "broken" not in _map, _map)

    check("alias_target 查得到", P.alias_target("claude-sonnet-4-5-20250929") == "glm-5.3",
          P.alias_target("claude-sonnet-4-5-20250929"))
    check("alias_target 大小写无关",
          P.alias_target("Claude-Sonnet-4-5-20250929") == "glm-5.3", None)
    check("alias_target 查不到返回空串", P.alias_target("nope") == "", None)

    _p1 = {"model": "claude-sonnet-4-5-20250929"}
    P.canonicalize_model(_p1)
    check("Claude Code 的模型名被映射到真名", _p1["model"] == "glm-5.3", _p1["model"])

    _p2 = {"model": "claude-opus-4-1"}
    P.canonicalize_model(_p2)
    check("别名指向大写真名时原样用 GLM-5.2", _p2["model"] == "GLM-5.2", _p2["model"])

    _p3 = {"model": "gpt-5-codex"}
    P.canonicalize_model(_p3)
    check("别名目标写小写时再归一成上游真名", _p3["model"] == "GLM-5.2", _p3["model"])

    # 改文件 → 下一个请求生效（mtime 变了要重读，不能一直吃缓存）
    with open(_alias_path, "w", encoding="utf-8") as _fh:
        _json.dump({"claude-sonnet-4-5-20250929": "glm-5.2"}, _fh)
    _stamp = _os.path.getmtime(_alias_path)
    _os.utime(_alias_path, (_stamp + 2, _stamp + 2))
    _p4 = {"model": "claude-sonnet-4-5-20250929"}
    P.canonicalize_model(_p4)
    check("改完别名文件立即生效", _p4["model"] == "GLM-5.2", _p4["model"])

    # 坏文件不能把请求打死
    with open(_alias_path, "w", encoding="utf-8") as _fh:
        _fh.write("{ not json")
    _os.utime(_alias_path, (_os.path.getmtime(_alias_path) + 3,
                            _os.path.getmtime(_alias_path) + 3))
    check("坏别名文件当作没有", P.model_aliases() == {}, P.model_aliases())
    _p5 = {"model": "glm-5.3"}
    P.canonicalize_model(_p5)
    check("坏别名文件不影响真名归一", _p5["model"] == "glm-5.3", _p5["model"])
finally:
    P.ACCOUNTS_DIR = _saved_dir
    P._MODEL_ALIASES.update({"mtime": -2.0, "map": {}})
    _shutil.rmtree(_alias_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 10. 采样参数透传 / 形状拒绝 / 模型级冷却（口径都来自 2026-10-22 的实测）
# ---------------------------------------------------------------------------

section("10. 上游认的采样参数与形状拒绝")

_s = C.sampling_extra_from({"temperature": 0, "top_p": 0.9, "seed": 42,
                            "presence_penalty": 0.5, "frequency_penalty": -0.5,
                            "stop": "END"})
check("数值参数原样带上", _s.get("temperature") == 0.0 and _s.get("top_p") == 0.9, _s)
check("seed 取整", _s.get("seed") == 42 and isinstance(_s.get("seed"), int), _s)
check("字符串 stop 包成单元素数组（上游只收数组）", _s.get("stop") == ["END"], _s)
check("两个 penalty 都带上", _s.get("presence_penalty") == 0.5
      and _s.get("frequency_penalty") == -0.5, _s)

_s2 = C.sampling_extra_from({"stop": ["a", "b", "c", "d", "e", "f"]})
check("stop 超过 4 条裁掉", _s2 == {"stop": ["a", "b", "c", "d"]}, _s2)

_s3 = C.sampling_extra_from({"temperature": "abc", "top_p": [1], "seed": True,
                             "stop": 3, "n": 2})
check("坏类型就地丢掉，绝不发上去换 400", _s3 is None, _s3)
check("空请求体不炸", C.sampling_extra_from(None) is None
      and C.sampling_extra_from({}) is None, None)

_m = P._codearts_extra({"temperature": 0,
                        "thinking": {"type": "enabled", "budget_tokens": 1024}})
check("思考参数与采样参数合到一份 extra",
      _m.get("temperature") == 0.0
      and _m.get("thinking", {}).get("budget_tokens") == 1024, _m)
check("两者都没有时返回 None", P._codearts_extra({}) is None,
      P._codearts_extra({}))

_spec2 = P._codearts_fail_spec
check("图片发给纯文本模型（001001020.406）→ 400，不是 502",
      _spec2(200, "InferHub.001001020.406",
             "The request model is not multimodal")
      == (400, "invalid_request_error"),
      _spec2(200, "InferHub.001001020.406", "not multimodal"))
check("帧内映射同样走这张表",
      P._codearts_frame_status("InferHub.001001020.406 not multimodal")[0] == 400,
      P._codearts_frame_status("InferHub.001001020.406"))

check("n=2 被明确拒绝",
      "n=2" in (P._codearts_choice_count_error({"n": 2}) or ""),
      P._codearts_choice_count_error({"n": 2}))
check("n=1 / 缺省不拦", P._codearts_choice_count_error({"n": 1}) is None
      and P._codearts_choice_count_error({}) is None, None)
check("response_format=json_object 明确拒绝",
      "not supported" in (P._codearts_response_format_error(
          {"response_format": {"type": "json_object"}}) or ""), None)
check("response_format=text 放行",
      P._codearts_response_format_error(
          {"response_format": {"type": "text"}}) is None, None)

# 模型级冷却（TPM 是按模型的，不该连带停掉同账号的其它模型）
_pool_m = _StubPool(["acct-a", "acct-b"])
_pool_m.penalize("acct-a", 30, model="glm-5.3")
_seen_m = []
for _i in range(6):
    _sess_m, _k_m = _pool_m.acquire(0, model="glm-5.3")
    _seen_m.append(_k_m)
    _pool_m.release(_k_m)
check("模型级冷却只跳过这个模型", set(_seen_m) == {"acct-b"}, _seen_m)

_seen_o = []
for _i in range(6):
    _sess_o, _k_o = _pool_m.acquire(0, model="deepseek-v4.1-flash")
    _seen_o.append(_k_o)
    _pool_m.release(_k_o)
check("同账号的其它模型照常可用", set(_seen_o) == {"acct-a", "acct-b"}, _seen_o)

_pool_solo = _StubPool(["solo"])
_pool_solo.penalize("solo", 30, model="glm-5.3")
_sess_s, _k_s = _pool_solo.acquire(0, model="glm-5.3")
check("全在模型冷却时仍落到唯一的号（不为偏好把请求排死）", _k_s == "solo", _k_s)
_snap = _pool_solo.snapshot()
check("快照里能看到模型级冷却",
      _snap["solo"]["model_cooling_s"].get("glm-5.3", 0) > 0, _snap)

_pool_acct = _StubPool(["acct-a"])
_pool_acct.penalize("acct-a", 30)
_snap2 = _pool_acct.snapshot()
check("账号级冷却记在 cooling_s（1041/凭据失效用）",
      _snap2["acct-a"]["cooling_s"] > 0, _snap2)


# ---------------------------------------------------------------------------
# 11. 粘性落盘：重启后同一条对话仍回到同一个账号
# ---------------------------------------------------------------------------

section("11. 粘性持久化")

_d1 = tempfile.mkdtemp(prefix="affinity-")
try:
    _pa = _StubPool(["acct-a", "acct-b"], _d1)
    _pa.remember("k:persist", "acct-b")
    _file = os.path.join(_d1, P.CODEARTS_AFFINITY_FILE)
    check("粘性写盘了", os.path.exists(_file), _d1)
    check("没有残留 .tmp（原子替换）", not os.path.exists(_file + ".tmp"), None)

    _pb = _StubPool(["acct-a", "acct-b"], _d1)
    check("新实例读回粘性", _pb._sticky("k:persist") == "acct-b",
          _pb._sticky("k:persist"))
    _keys_p = set()
    for _i in range(4):
        _sess_p, _k_p = _pb.acquire(0, session_key="k:persist")
        _keys_p.add(_k_p)
        _pb.release(_k_p)
    check("重启后同一对话仍落回同一个号", _keys_p == {"acct-b"}, _keys_p)

    # 过期的绑定不该被加载
    with open(_file, "w", encoding="utf-8") as _fh:
        json.dump({"k:old": ["acct-a",
                             time.time() - P.CODEARTS_AFFINITY_TTL - 60]}, _fh)
    _pc = _StubPool(["acct-a"], _d1)
    check("过期绑定不加载", _pc._sticky("k:old") is None, _pc._sticky("k:old"))

    # 坏文件不能把请求打死
    with open(_file, "w", encoding="utf-8") as _fh:
        _fh.write("{ broken")
    _pd = _StubPool(["acct-a"], _d1)
    check("坏粘性文件当作没有", _pd._sticky("k:any") is None, None)

    # 目标目录不存在也不抛（最坏只是丢粘性）
    _pe = _StubPool(["acct-a"], os.path.join(_d1, "missing", "dir"))
    try:
        _pe.remember("k:x", "acct-a")
        _bad_dir_ok = True
    except Exception as _exc:                    # noqa: BLE001
        _bad_dir_ok = _exc
    check("落盘失败不影响请求", _bad_dir_ok is True, _bad_dir_ok)

    # 节流：10 秒内第二次 remember 不重复写盘（mtime 不变）
    _pf = _StubPool(["acct-a"], _d1)
    _pf.remember("k:one", "acct-a")
    _stamp1 = os.path.getmtime(_file)
    time.sleep(0.02)
    _pf.remember("k:two", "acct-a")
    check("写盘按间隔节流", os.path.getmtime(_file) == _stamp1, None)
finally:
    import shutil as _shutil2
    _shutil2.rmtree(_d1, ignore_errors=True)


# ---------------------------------------------------------------------------
# 12. 面板可调的码道参数（并发 / 续期 / 冷却）
# ---------------------------------------------------------------------------

section("12. 码道调参")

_tmp12 = tempfile.mkdtemp(prefix="tuning-")
try:
    _defaults = S.codearts_config(_tmp12)
    check("没有配置时用内置默认", _defaults == S.CODEARTS_DEFAULTS, _defaults)

    _ok = S.validate_codearts_patch({"concurrency": 3, "tpm_cooldown": 45})
    check("合法补丁原样收下", _ok == {"concurrency": 3, "tpm_cooldown": 45}, _ok)

    for _bad, _why in (({"concurrency": 0}, "下限"),
                       ({"concurrency": 9}, "上限"),
                       ({"concurrency": True}, "布尔"),
                       ({"concurrency": 2.5}, "小数"),
                       ({"nope": 1}, "未知键")):
        try:
            S.validate_codearts_patch(_bad)
            _rejected = False
        except ValueError:
            _rejected = True
        check("拒绝非法值（%s）" % _why, _rejected, _bad)

    S.set_codearts_config(_tmp12, {"concurrency": 3, "session_ping": 45})
    _stored = S.codearts_config(_tmp12)
    check("保存后读回", _stored["concurrency"] == 3
          and _stored["session_ping"] == 45, _stored)
    check("没动的项保持默认", _stored["tpm_cooldown"]
          == S.CODEARTS_DEFAULTS["tpm_cooldown"], _stored)

    # 手改坏了 settings.json 也不能把网关配成不可用：坏值退回默认
    _path = os.path.join(_tmp12, "settings.json")
    with open(_path, "w", encoding="utf-8") as _fh:
        json.dump({"codearts": {"concurrency": 99, "session_ping": "x"}}, _fh)
    _broken = S.codearts_config(_tmp12)
    check("落盘的坏值退回默认",
          _broken["concurrency"] == S.CODEARTS_DEFAULTS["concurrency"]
          and _broken["session_ping"] == S.CODEARTS_DEFAULTS["session_ping"],
          _broken)

    # 运行时读取：改完清缓存就生效
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    _saved_dir = P.ACCOUNTS_DIR
    P.ACCOUNTS_DIR = _tmp12
    try:
        S.set_codearts_config(_tmp12, {"tpm_cooldown": 77})
        P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
        check("运行时读到新值", P._codearts_seconds("tpm_cooldown", 20) == 77.0,
              P._codearts_seconds("tpm_cooldown", 20))
        check("未知键退回内置默认",
              P._codearts_seconds("nope", 12) == 12.0,
              P._codearts_seconds("nope", 12))
    finally:
        P.ACCOUNTS_DIR = _saved_dir
        P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
finally:
    import shutil as _shutil3
    _shutil3.rmtree(_tmp12, ignore_errors=True)


# ---------------------------------------------------------------------------
# 13. 纯函数层（ca_protocol）：协议转换的第一刀
# ---------------------------------------------------------------------------

section("13. 纯函数层 ca_protocol")

import ca_protocol as Q  # noqa: E402

_f = Q.anthropic_sse_frame("content_block_delta",
                           {"index": 0, "delta": {"type": "text_delta",
                                                  "text": "你"}})
check("帧形如 event: x + data: {...}",
      _f.startswith(b"event: content_block_delta\ndata: {") and _f.endswith(b"}\n\n"),
      _f[:40])
check("payload 的 type 被 event 覆盖", b'"type":"content_block_delta"' in _f, _f)
check("中文不转义（客户端直读）", "你".encode("utf-8") in _f, _f)
check("空 payload 也能出帧",
      Q.anthropic_sse_frame("ping", None) == b'event: ping\ndata: {"type":"ping"}\n\n',
      Q.anthropic_sse_frame("ping", None))
check("length → max_tokens", Q.anthropic_stop_reason("length") == "max_tokens", None)
check("tool_calls → tool_use", Q.anthropic_stop_reason("tool_calls") == "tool_use", None)
check("content_filter → refusal",
      Q.anthropic_stop_reason("content_filter") == "refusal", None)
check("未知值兜底 end_turn",
      Q.anthropic_stop_reason("whatever") == "end_turn", None)
check("这一层不 import socket（真的纯）",
      "import socket" not in open(Q.__file__, encoding="utf-8").read(), None)
check("ca_proxy 用的是同一函数对象（接线生效）",
      P.anthropic_sse_frame is Q.anthropic_sse_frame
      and P._anthropic_stop_reason is Q.anthropic_stop_reason, None)


_obj = {"function_call": {}, "tool_calls": [], "keep": 1}
check("空 function_call / 空 tool_calls 被剔掉",
      Q.strip_empty_function_calls(_obj) is True
      and _obj == {"keep": 1}, _obj)
_obj2 = {"function_call": {"name": "f", "arguments": "{}"}}
check("有内容的 function_call 保留",
      Q.strip_empty_function_calls(_obj2) is False
      and _obj2["function_call"]["name"] == "f", _obj2)

_frame = b'event: x\ndata: {"function_call": {}}\n\n'
_fixed = Q.clean_responses_frame(_frame)
check("Responses 帧里的空占位被清掉", b'"function_call"' not in _fixed, _fixed)
check("[DONE] 与坏 JSON 原样返回",
      Q.clean_responses_frame(b"data: [DONE]\n\n") == b"data: [DONE]\n\n"
      and Q.clean_responses_frame(b"data: {bad\n\n") == b"data: {bad\n\n", None)

check("developer → system（Codex/新 SDK 的写法）",
      Q.normalize_roles([{"role": "developer", "content": "x"}])
      == [{"role": "system", "content": "x"}], None)
check("原有角色不动（连对象都是同一个）",
      (lambda _m: Q.normalize_roles(_m)[0] is _m[0])(
          [{"role": "user", "content": "y"}]), None)
check("非 dict 条目原样保留",
      Q.normalize_roles(["junk"]) == ["junk"], None)

_txt = Q.anthropic_text(None), Q.anthropic_text("ab"), Q.anthropic_text(3)
check("文本归一：None→空串、原样、非串转串", _txt == ("", "ab", "3"), _txt)
_u = Q.anthropic_usage({"prompt_tokens": 10, "completion_tokens": 2})
check("用量映射字段齐全", _u["input_tokens"] == 10 and _u["output_tokens"] == 2
      and _u["cache_read_input_tokens"] == 0, _u)
_u2 = Q.anthropic_usage({"prompt_tokens": 100, "completion_tokens": 5,
                         "prompt_cache_hit_tokens": 40})
check("缓存命中进 cache_read_input_tokens", _u2["cache_read_input_tokens"] == 40, _u2)
check("非 dict 用量给全零", Q.anthropic_usage(None)["input_tokens"] == 0, None)

print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

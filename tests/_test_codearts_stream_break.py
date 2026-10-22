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
    def __init__(self, timeout=None):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value


class _Raw:
    def __init__(self, sock):
        self._sock = sock


class _FP:
    def __init__(self, sock):
        self.raw = _Raw(sock)


class _IdleResp:
    """read1 按剧本演：抛 TimeoutError 就是「上游静默」，b"" 是正常结束。"""

    def __init__(self, script, sock=True):
        self.script = list(script)
        self.closed = False
        self.fp = _FP(_Sock(180.0)) if sock else None

    def read1(self, _n):
        item = self.script.pop(0) if self.script else b""
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


_script = [TimeoutError("timed out"), b'data: {"choices":[{"delta":{"content":"a"}}]}\n\n', b""]
_seen = list(C.iter_sse(_IdleResp(_script), idle_timeout=15))
check("静默时吐 KEEPALIVE 哨兵", any(x is C.KEEPALIVE for x in _seen), _seen)
check("静默之后照常读出后续行",
      any(isinstance(x, str) and x.startswith("data:") for x in _seen), _seen)
check("KEEPALIVE 不是字符串（不能混进 SSE 正文）",
      all(not isinstance(x, str) for x in _seen if x is C.KEEPALIVE), _seen)

# 心跳期间 socket 超时被压短，读完恢复原值（不然下一次读又变成 180s）
_probe = _IdleResp([TimeoutError("t"), b"", b""])
_sock = _probe.fp.raw._sock
list(C.iter_sse(_probe, idle_timeout=15))
check("读完恢复原来的 socket 超时", _sock.timeout == 180.0, _sock.timeout)

# 连续静默到上限：判上游卡死，抛 UpstreamBroken 而不是永远挂着
_stuck = _IdleResp([TimeoutError("t")] * 10)
_broken = None
try:
    list(C.iter_sse(_stuck, idle_timeout=15, max_idle=3))
except C.UpstreamBroken as exc:
    _broken = exc
check("连续静默超过上限 → UpstreamBroken", _broken is not None, _broken)

# 拿不到 socket（假对象 / 老版本）时不能误发心跳：超时按真断流处理
_nosock = _IdleResp([TimeoutError("t")] * 3, sock=False)
_broken2 = None
try:
    list(C.iter_sse(_nosock, idle_timeout=15))
except C.UpstreamBroken:
    _broken2 = True
check("拿不到 socket 时不假装心跳", _broken2 is True, _broken2)

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
    def __init__(self, keys):
        P._CodeartsAccountPool.__init__(self)
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


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

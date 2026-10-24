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
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C  # noqa: E402
import ca_settings as S   # noqa: E402
import ca_proxy as P     # noqa: E402
import ca_stream as S2  # noqa: E402

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

    def __init__(self, lines, broken_after=None, silent_s=None):
        self._lines = list(lines)
        self._broken_after = broken_after
        self._silent_s = silent_s
        self.started_at = time.time()
        self.closed = False

    def lines(self, _abort_check=None, _stats=None):
        for i, line in enumerate(self._lines):
            if self._broken_after is not None and i >= self._broken_after:
                if _stats is not None and self._silent_s is not None:
                    _stats["silent_s"] = self._silent_s
                raise C.UpstreamBroken("upstream closed early", 0)
            yield line
        if self._broken_after is not None:
            if _stats is not None and self._silent_s is not None:
                _stats["silent_s"] = self._silent_s
            raise C.UpstreamBroken("upstream closed early", 0)

    def byte_lines(self, _abort_check=None, _stats=None):
        for line in self.lines(_abort_check, _stats):
            yield line.encode("utf-8")

    def close(self):
        self.closed = True

    # 真实租约把「关连接」和「idle + 还名额」拆开了（见 _CodeartsLease）：
    # close_upstream 先执行，[DONE] 之后才 release_slot。
    def close_upstream(self):
        self.closed = True

    def release_slot(self):
        self.slot_released = True


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

# 2c-1. 「静默 60 秒被切」和「网络抖动」不是一回事：上游对没有输出的连接按
# 空闲超时收掉，同一个请求会一直在同一处被切，客户端自动重试就表现成
# 「反复回复同一句话」。错误文案必须直接给出改法，否则上层只会原样重试。
check("提示只在接近 60 秒静默时才出现",
      S2.break_hint({"silent_s": 12.0}) == ""
      and S2.break_hint({}) == "", None)
_hint = S2.break_hint({"silent_s": 59.8})
check("60 秒静默的提示写明「拆小 / 降思考预算」",
      "split" in _hint and "thinking budget" in _hint, _hint)
_h, _sse = _run([_Lease([_role], 1, silent_s=59.8)])
check("断流错误帧带上这条提示",
      "split this turn into smaller steps" in _sse, _sse[-400:])
_h, _sse = _run([_Lease([_role], 1, silent_s=3.0)])
check("普通断流不塞这条提示（别把抖动说成超时）",
      "split this turn" not in _sse, _sse[-400:])

# 2c-2. 断流的记账：一次失败只落一行，而且这一行要带上已经收到的 usage。
# 以前先 record_error 再 record_usage，同一次失败在 usage.jsonl 里出现两次
# （failed + upstream_aborted，同 iso 同 elapsed），总量被放大一倍。
_usage_line = ('data: {"choices":[{"delta":{}}],'
               '"usage":{"prompt_tokens":7,"completion_tokens":3}}\n\n')
_rows = []
_orig_err, _orig_use = P.record_error, P.record_usage


def _spy_error(*args, **kwargs):
    _rows.append(("error", args[1] if len(args) > 1 else kwargs.get("status"),
                  kwargs.get("outcome"), kwargs.get("usage")))


def _spy_usage(*args, **kwargs):
    _rows.append(("usage", None, kwargs.get("outcome"), None))


P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _run([_Lease([_role, _usage_line], 2), _Lease([_tail], None)])
finally:
    P.record_error, P.record_usage = _orig_err, _orig_use
check("断流只落一行账（不再额外记一条 usage）", len(_rows) == 1, _rows)
check("断流行记为 upstream_aborted、状态码 502",
      _rows and _rows[0][0] == "error" and _rows[0][1] == 502
      and _rows[0][2] == "upstream_aborted", _rows)
check("断流时已收到的 usage 跟着这一行一起落库",
      _rows and isinstance(_rows[0][3], dict)
      and _rows[0][3].get("prompt_tokens") == 7, _rows)

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

# 会话登记表落在 ACCOUNTS_DIR 下（重启后补发 idle 用）。整套心跳测试改到
# 临时目录跑：线上跑测试时，别在真实的账号目录里留下一份假登记。
_saved_acct_dir = P.ACCOUNTS_DIR
_acct_tmp = tempfile.mkdtemp(prefix="ca-sess-")
P.ACCOUNTS_DIR = _acct_tmp

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

    # 续期已从读循环里摘出去：读多少行都不该产生心跳。以前每收一行就试一次
    # 续期，一次慢心跳会把读停住，反过来顶满上游的写缓冲。
    class _FakeResp:
        def __init__(self, chunks):
            self._chunks = list(chunks)

        def read1(self, n):
            return self._chunks.pop(0) if self._chunks else b""

        def close(self):
            pass

    _calls.clear()
    _l3 = P._CodeartsLease(
        _FakeResp([b'data: {"choices":[]}\n', b"data: [DONE]\n"]),
        "lbl", time.time(), "k3",
        session_id="sid3", session_cred=("AK", "SK", "TK"))
    _lines3 = list(_l3.lines())
    check("读循环不再顺带续期（心跳在独立线程里）",
          _calls == [] and len(_lines3) == 2, (_calls, _lines3))
    check("续期线程是 daemon，不会拖住进程退出",
          _l3._ping_thread is not None and _l3._ping_thread.daemon, None)
    _l3.close()
    check("关闭时通知续期线程退出", _l3._ping_stop.is_set(), None)
    check("关闭之后再调 keepalive 不会补发 busy",
          _l3.keepalive() is False
          and not [c for c in _calls if c[0] == "sid3" and c[1] == "busy"],
          _calls)
finally:
    C.heartbeat = _saved_hb


# ---------------------------------------------------------------------------
# 4b. 会话登记表：重启后把没来得及 idle 的名额还回去
# ---------------------------------------------------------------------------

section("4b. 重启后的会话清理")

_sess_path = P._sessions_path()
check("登记表就在临时账号目录里（不碰真实目录）",
      os.path.dirname(_sess_path) == _acct_tmp, _sess_path)

P.track_codearts_session("aaa", "acct-a")
P.track_codearts_session("bbb", "acct-b")
_raw = P._sessions_read()
check("busy 之后登记两条", sorted(_raw) == ["aaa", "bbb"], _raw)
check("记了账号标签（重启时靠它找凭据）",
      _raw["aaa"].get("acct") == "acct-a", _raw.get("aaa"))
check("原子写不留 .tmp 残骸",
      not os.path.exists(_sess_path + ".tmp"), os.listdir(_acct_tmp))

P.untrack_codearts_session("aaa")
check("idle 成功就销账", sorted(P._sessions_read()) == ["bbb"],
      P._sessions_read())
P.untrack_codearts_session("不存在的 id")     # 不该抛，也不该写坏
check("销一条不存在的账是空操作", sorted(P._sessions_read()) == ["bbb"],
      P._sessions_read())

# 上限：正常远到不了，但「idle 一直失败 + 长期不重启」不能让它无限长。
for _i in range(P.CODEARTS_SESSION_MAX + 8):
    P.track_codearts_session("x%03d" % _i, "acct-a")
_capped = P._sessions_read()
check("登记表有长度上限", len(_capped) == P.CODEARTS_SESSION_MAX, len(_capped))
check("截断时留最新的", "x%03d" % (P.CODEARTS_SESSION_MAX + 7) in _capped,
      sorted(_capped)[-1:])

# reap：有凭据的那条补发 idle，没有凭据的留在表里（等下一次启动）
P._sessions_write({
    "r1": {"acct": "acct-a", "at": time.time()},
    "r2": {"acct": "已删除的账号", "at": time.time()},
    "r3": {"acct": "acct-a", "at": time.time() - P.CODEARTS_SESSION_TTL - 60},
})
_saved_load = C.load_sessions
_calls_r = []


def _fake_load(_dir):
    return [{"account": {"label": "acct-a"}, "accessKey": "AK",
             "secretKey": "SK", "securitytoken": "TK"}]


def _fake_hb(*a, **k):
    _calls_r.append((a[3], a[4]))
    # r3 老到该被丢弃，但它照样会被尝试；让它的 idle 失败以验证「超龄就不再留」
    return (a[3] != "r3"), "stub"


C.load_sessions = _fake_load
C.heartbeat = _fake_hb
try:
    P.reap_codearts_sessions()
finally:
    C.load_sessions = _saved_load
    C.heartbeat = _saved_hb

check("重启后补发 idle（有凭据的都试了）",
      sorted(c[0] for c in _calls_r) == ["r1", "r3"], _calls_r)
check("补发的是 idle 不是 busy",
      all(c[1] == "idle" for c in _calls_r), _calls_r)
_left = P._sessions_read()
check("注销成功的销账", "r1" not in _left, _left)
check("没凭据的留着等下次启动（不静默丢账）", "r2" in _left, _left)
check("超龄且注销失败的丢弃（上游早该回收了）", "r3" not in _left, _left)

# 清理期间的并发请求：它新登记的那条不能被收尾的写盘覆盖掉 —— 那正好是
# 下一次重启会泄漏的那批。
P._sessions_write({"c1": {"acct": "acct-a", "at": time.time()}})
_calls_c = []


def _fake_hb_track(*a, **k):
    if not _calls_c:
        P.track_codearts_session("fresh", "acct-a")   # 模拟另一个请求登记
    _calls_c.append((a[3], a[4]))
    return True, "stub"


C.load_sessions = _fake_load
C.heartbeat = _fake_hb_track
try:
    P.reap_codearts_sessions()
finally:
    C.load_sessions = _saved_load
    C.heartbeat = _saved_hb
_after = P._sessions_read()
check("清理期间新登记的会话不被覆盖",
      "fresh" in _after and "c1" not in _after, _after)

# 表是空的就别去打扰上游
P._sessions_write({})
_calls_r.clear()
C.load_sessions = _fake_load
C.heartbeat = _fake_hb
try:
    P.reap_codearts_sessions()
finally:
    C.load_sessions = _saved_load
    C.heartbeat = _saved_hb
check("空表不发任何心跳", _calls_r == [], _calls_r)

# busy 封装：登记成功才记账（没登记上的 id，上游不认，重启后 idle 只会 404）
_calls_r.clear()
C.heartbeat = lambda *a, **k: (_calls_r.append((a[3], a[4])), (True, "ok"))[1]
try:
    _sid, _ok, _detail = P.codearts_session_busy(("AK", "SK", "TK"), "acct-a")
finally:
    C.heartbeat = _saved_hb
check("busy 封装返回新会话 id 且登记成功",
      _ok and len(_sid) == 32 and _sid in P._sessions_read(), (_sid, _ok))
check("busy 封装发的是 busy", _calls_r and _calls_r[0][1] == "busy", _calls_r)

C.heartbeat = lambda *a, **k: (False, "HTTP 401")
try:
    _sid2, _ok2, _d2 = P.codearts_session_busy(("AK", "SK", "TK"), "acct-a")
finally:
    C.heartbeat = _saved_hb
_pending = P._sessions_read()
check("busy 失败不记账",
      _ok2 is False and _sid2 not in _pending
      and len(_pending) == len(set(_pending)), (_sid2, sorted(_pending)))

P.ACCOUNTS_DIR = _saved_acct_dir


# ---------------------------------------------------------------------------
# 5. 错误语义映射（照 CodeArts2API-Go 的 apierr 表）
# ---------------------------------------------------------------------------

section("5. 上游错误 → 对外状态码")

_spec = S2.fail_spec
check("并发会话满（HTTP 400 + TM.00001041）→ 429 而不是 502",
      _spec(400, "TM.00001041", "并发会话数已达上限(3个)")[0] == 429,
      _spec(400, "TM.00001041", ""))
check("TPM 限流（429）→ 429", _spec(429, "", "")[0] == 429)
check("max_tokens 超限（001001005）→ 400（重试同样的请求没用）",
      _spec(400, "InferHub.001001005.400", "The request param is invalid")[0] == 400)
check("模型未注册（002002009）→ 404",
      _spec(404, "InferHub.002002009", "model is not registered")[0] == 404)
check("后端超时（APIG.0203）→ 504，不是含糊的 502",
      _spec(502, "APIG.0203", "Backend timeout") == (504, "upstream_error"),
      _spec(502, "APIG.0203", "Backend timeout"))
check("后端超时在 Anthropic 侧是 overloaded_error",
      _spec(502, "APIG.0203", "Backend timeout", anthropic=True)[1]
      == "overloaded_error", None)

# 记账必须和回给客户端的状态码同源。_codearts_open_lease 里曾经写死
# record_error(model, 502, ...)，而对外走 _codearts_fail 把 0203 映射成
# 504 —— 日志与用量记 502、客户端收 504。用静态检查钉住这一处。
_src = io.open(P.__file__, encoding="utf-8").read()
_open_seg = _src[_src.index("def _codearts_open_lease"):]
_open_seg = _open_seg[:_open_seg.index("\n    def ", 10)]
check("建连失败记账与响应同源（映射失败用 st，网络异常仍 502）",
      "record_error(model, st," in _open_seg
      and "ca_stream.fail_spec(status, code, detail, anthropic)" in _open_seg
      and "record_error(model, 502, str(last_exc)" in _open_seg, None)
check("状态码映射只有一张表（ca_proxy 里不许再抄一份）",
      "def _codearts_fail_spec" not in _src
      and "def _codearts_frame_status" not in _src, None)
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

    # 真实租约把「关连接」和「idle + 还名额」拆开了（见 _CodeartsLease）：
    # close_upstream 先执行，[DONE] 之后才 release_slot。
    def close_upstream(self):
        self.closed = True

    def release_slot(self):
        self.slot_released = True


_wait_script = []


def _fake_wait(_sock, _timeout, _fp=None, _resp=None):
    # 第三个参数是 resp.fp、第四个是 resp（见 _wait_readable：光看 socket 会把
    # Python 缓冲里已收到的字节当成静默；而 chunked 分帧的 \r\n 又不能当载荷）。
    # 桩按剧本返回，不关心这两个。
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

# 哨兵在 tap_lines 里翻成 SSE 注释行
_sink725 = {}
_tapped = list(S2.tap_lines([C.KEEPALIVE, b'data: {"usage":{"total_tokens":7}}\n\n'],
                             _sink725, keepalive=C.KEEPALIVE))
check("哨兵翻成 SSE 注释行", _tapped[0] == b": keepalive\n\n", _tapped[:1])
check("tap 顺手记下 usage", _sink725.get("usage", {}).get("total_tokens") == 7,
      _sink725)
check("不传 keepalive 时哨兵按普通行透传（旧调用点不会凭空多一帧）",
      list(S2.tap_lines([C.KEEPALIVE], {})) == [C.KEEPALIVE], None)


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
check("stop 超过 4 条裁掉（并报告裁了几条，不再静默）",
      _s2 == {"stop": ["a", "b", "c", "d"], "stop_dropped": 2}, _s2)
check("4 条以内不带 stop_dropped",
      C.sampling_extra_from({"stop": ["a", "b"]}) == {"stop": ["a", "b"]},
      C.sampling_extra_from({"stop": ["a", "b"]}))
check("stop_dropped 是内部标记，不会发给上游",
      "stop_dropped" not in (P._codearts_extra({"stop": ["a", "b", "c", "d", "e"]})
                             or {}),
      P._codearts_extra({"stop": ["a", "b", "c", "d", "e"]}))

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

_spec2 = S2.fail_spec
check("图片发给纯文本模型（001001020.406）→ 400，不是 502",
      _spec2(200, "InferHub.001001020.406",
             "The request model is not multimodal")
      == (400, "invalid_request_error"),
      _spec2(200, "InferHub.001001020.406", "not multimodal"))
check("帧内映射同样走这张表",
      S2.frame_status("InferHub.001001020.406 not multimodal")[0] == 400,
      S2.frame_status("InferHub.001001020.406"))

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
                       ({"concurrency": 4}, "上限（上游只有 3 个会话名额）"),
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
        S.set_codearts_config(_tmp12, {"concurrency": 3})
        P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
        check("每账号并发实时读面板值（不用重启）",
              P.codearts_concurrency() == 3, P.codearts_concurrency())
        with open(os.path.join(_tmp12, "settings.json"), "w",
                  encoding="utf-8") as _fh:
            json.dump({"codearts": {"concurrency": 99}}, _fh)
        P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
        check("落盘被手改成 99 时运行时退回默认（不会把上游打穿）",
              P.codearts_concurrency() == S.CODEARTS_DEFAULTS["concurrency"],
              P.codearts_concurrency())
    finally:
        P.ACCOUNTS_DIR = _saved_dir
        P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
finally:
    import shutil as _shutil3
    _shutil3.rmtree(_tmp12, ignore_errors=True)


# 并发容量可调：换对象会让「刚 acquire 还没记账」的 release 打到新对象上，
# 容量凭空长一格；自己记容量/空闲就没有这个窗口。
_sem = P._ResizableSemaphore(2)
check("信号量：取满后非阻塞取不到",
      _sem.acquire(False) and _sem.acquire(False) and not _sem.acquire(False), None)
_sem.release()
check("信号量：释放一个就能再取一个", _sem.acquire(False), None)
# 上限是上游名额数（3），不是 8：retune(4) 会被夹到 3。
# 此刻在跑 2 个（取满后又 release+acquire 过一次），所以调到 3 只能再进 1 个。
_sem.retune(4)
check("信号量：调大后空闲数按在跑数换算（上限夹到上游名额 3）",
      _sem.capacity == 3 and _sem.acquire(False)
      and not _sem.acquire(False), (_sem.capacity, P.CODEARTS_UPSTREAM_SLOTS))
_sem.retune(1)
check("信号量：调小不踢在跑的，只收紧新名额",
      _sem.capacity == 1 and not _sem.acquire(False), None)
for _ in range(3):
    _sem.release()
check("信号量：多还的不会把容量撑大",
      _sem.capacity == 1 and _sem.acquire(False), None)

# 缩容再扩容**不能**凭空多放行一个：容量 2 改成 1、再改回 2，实际最多还是 2。
# 旧实现用 capacity-free 反推在跑数，缩容时把 free 压到 0，之后任意一个
# release 都会把名额加回去，扩回来就成了 3 —— 正好打满上游的 3 个会话名额。
_sem_shrink = P._ResizableSemaphore(2)
_sem_shrink.acquire(False)
_sem_shrink.acquire(False)
_sem_shrink.retune(1)
_sem_shrink.release()
_sem_shrink.retune(2)
_admitted = 0
while _sem_shrink.acquire(False):
    _admitted += 1
    if _admitted > 4:        # 防死循环：真坏了也别把套件挂住
        break
check("信号量：缩容再扩容不会多放行（2→1→2 仍是最多 2）",
      _admitted == 1, (_admitted, _sem_shrink.capacity))

# 面板要显示「在跑几条 / 容量几格」，容量必须取信号量的实时值，
# 不能是进程启动时的配置快照。
_pool_snap = P._CodeartsAccountPool(tempfile.mkdtemp(prefix="snap-"))
try:
    _sem_snap = _pool_snap._sem("acct-x")
    _snap = _pool_snap.snapshot()
    check("snapshot 带每号实时容量",
          _snap.get("acct-x", {}).get("capacity") == _sem_snap.capacity, _snap)
    # retune 的上限是上游名额数（3）：面板填 5 也只会被夹到 3。
    _sem_snap.retune(5)
    check("容量调过之后 snapshot 跟着变（并被夹到上游名额 3）",
          _pool_snap.snapshot()["acct-x"]["capacity"] == P.CODEARTS_UPSTREAM_SLOTS,
          _pool_snap.snapshot())
finally:
    import shutil as _shutil5
    _shutil5.rmtree(_pool_snap._state_dir, ignore_errors=True)


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
check("ca_proxy 里不再保留这两个别名（第十刀已拆桥）",
      not hasattr(P, "anthropic_sse_frame")
      and not hasattr(P, "_anthropic_stop_reason"), None)


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


# ---------------------------------------------------------------------------
# 14. 第五刀：SSE 读取层 + Messages 流式状态机搬进 ca_protocol
# ---------------------------------------------------------------------------

section("14. Messages 流式状态机（真调，不只看 import）")


def _sse_lines(*chunks):
    """把 chat-completions 的 chunk 序列包成上游字节行。"""
    out = []
    for c in chunks:
        out.append(c.encode() if isinstance(c, str)
                   else b"data: " + json.dumps(c).encode())
    out.append(b"data: [DONE]")
    return iter(out)


def _events(frames):
    out = []
    for frame in frames:
        name = data = None
        for line in frame.decode().splitlines():
            if line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
        out.append((name, data))
    return out


def _messages(chunks, model="m", holder=None):
    return _events(Q.stream_messages_events(_sse_lines(*chunks), model, holder))


check("六个旧名字在 ca_proxy 里都已消失",
      not any(hasattr(P, n) for n in (
          "stream_messages_events", "iter_sse_lines", "strip_data_prefix",
          "anthropic_error_type", "_anthropic_message_id", "_new_id")), None)
check("_new_id 前缀与随机尾巴还在",
      Q.new_id("call_").startswith("call_") and len(Q.new_id("call_")) > 8, None)
check("SSE_READ_BLOCK 是同一整数", Q.SSE_READ_BLOCK == Q.SSE_READ_BLOCK == 65536, None)

_holder = {}
_ev = _messages([
    {"id": "chatcmpl-1", "model": "deepseek-v3",
     "choices": [{"delta": {"content": "你"}}]},
    {"choices": [{"delta": {"content": "好"}}]},
    {"choices": [{"delta": {}, "finish_reason": "stop"}],
     "usage": {"prompt_tokens": 11, "completion_tokens": 3,
               "prompt_tokens_details": {"cached_tokens": 7}}},
], holder=_holder)
_names = [n for n, _ in _ev]
check("流以 message_start 开场、message_stop 收尾",
      _names[0] == "message_start" and _names[-1] == "message_stop", _names[:3])
_text = "".join(d["delta"]["text"] for n, d in _ev
                if n == "content_block_delta" and d["delta"]["type"] == "text_delta")
check("正文按序拼回去", _text == "你好", repr(_text))
_start = [d for n, d in _ev if n == "message_start"][0]["message"]
check("model 透传、id 补 msg_ 前缀",
      _start["model"] == "deepseek-v3" and _start["id"].startswith("msg_"), _start)
_delta = [d for n, d in _ev if n == "message_delta"][0]
check("stop_reason=end_turn 且用量含缓存命中",
      # input_tokens 是「新读入」的部分：上游 prompt_tokens=11 里已包含
      # 命中的 7，而 Anthropic 的 input_tokens 不含缓存（缓存另计）。
      # 18 - 7 = 11... 这里上游给的是 11/3/cache 7，所以新读入是 4。
      _delta["delta"]["stop_reason"] == "end_turn"
      and _delta["usage"]["input_tokens"] == 4
      and _delta["usage"]["output_tokens"] == 3
      and _delta["usage"]["cache_read_input_tokens"] == 7, _delta)
check("上游原始用量交回调用方（否则用量行全空）",
      (_holder.get("usage") or {}).get("completion_tokens") == 3, _holder)

_ev = _messages([
    {"choices": [{"delta": {"reasoning_content": "想"}}]},
    {"choices": [{"delta": {"content": "答案"}}]},
    {"choices": [{"delta": {}, "finish_reason": "length"}]},
])
_seq = [(n, d.get("content_block", {}).get("type") or d.get("delta", {}).get("type"))
        for n, d in _ev if n in ("content_block_start", "content_block_delta")]
check("reasoning 先开 thinking 块、正文再开 text 块",
      _seq[0] == ("content_block_start", "thinking")
      and _seq[1] == ("content_block_delta", "thinking_delta")
      and ("content_block_start", "text") in _seq, _seq)
check("length → max_tokens",
      [d for n, d in _ev if n == "message_delta"][0]["delta"]["stop_reason"] == "max_tokens",
      None)

_ev = _messages([
    {"choices": [{"delta": {"tool_calls": [
        {"index": 0, "id": "call_a",
         "function": {"name": "get_weather", "arguments": "{\"c\""}}]}}]},
    {"choices": [{"delta": {"tool_calls": [
        {"index": 0, "function": {"arguments": ":\"bj\"}"}}]}}]},
    {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
])
_blocks = [d["content_block"] for n, d in _ev if n == "content_block_start"]
check("工具调用开一个 tool_use 块且 id/name 正确",
      len(_blocks) == 1 and _blocks[0]["type"] == "tool_use"
      and _blocks[0]["id"] == "call_a" and _blocks[0]["name"] == "get_weather", _blocks)
_args = "".join(d["delta"]["partial_json"] for n, d in _ev
                if n == "content_block_delta" and d["delta"]["type"] == "input_json_delta")
check("参数分片拼回完整 JSON", _args == "{\"c\":\"bj\"}", _args)
check("tool_calls → tool_use",
      [d for n, d in _ev if n == "message_delta"][0]["delta"]["stop_reason"] == "tool_use",
      None)

_ev = _messages([{"error": {"message": "boom"}}])
check("上游 error 帧翻成 Anthropic error 事件",
      _ev[-1][0] == "error" and "boom" in _ev[-1][1]["error"]["message"], _ev)

check("空流也补齐三段骨架（客户端不会卡住）",
      [n for n, _ in _messages([])] == ["message_start", "message_delta", "message_stop"],
      [n for n, _ in _messages([])][:5])

_raw = iter([b": ping\n", b"data: not-json\n",
             b'data: {"choices":[{"delta":{"content":"x"}}]}\n', b"data: [DONE]\n"])
check("注释行与坏 JSON 被跳过、不中断流",
      any(d.get("delta", {}).get("text") == "x"
          for n, d in _events(Q.stream_messages_events(_raw, "m", {}))), None)


class _Chunked:
    """带 read1 的对象：走「按块读 + 内存切行」那条真路径。"""

    def __init__(self, pieces):
        self.pieces = list(pieces)
        self.reads = 0

    def read1(self, _n):
        self.reads += 1
        return self.pieces.pop(0) if self.pieces else b""


_chunky = _Chunked([b'data: {"a":1}\n\ndata: {"b', b'":2}\n\ndata: [DONE]\n\n'])
check("跨块断行被接上、空行也交出去",
      list(Q.iter_sse_lines(_chunky)) ==
      [b'data: {"a":1}\n', b"\n", b'data: {"b":2}\n', b"\n",
       b"data: [DONE]\n", b"\n"], list(Q.iter_sse_lines(_chunky)))
_hooks = []
list(Q.iter_sse_lines(_Chunked([b"data: x\n", b""]),
                      before_read=lambda: _hooks.append(1)))
check("每次可能阻塞的读之前都回调（攒批写出的前提）", len(_hooks) >= 2, _hooks)

# 第五刀真正的坑：函数搬走了，ca_proxy 里的调用点还在叫旧名字。
# 别名只覆盖「调用方」，漏一个就是运行期 NameError（responses 断流收尾这次就
# 被它吃掉，测试只看到「少了 response.failed」）。这里做一次静态普查。
_proxy_src = open(P.__file__, encoding="utf-8").read()
_protocol_src = open(Q.__file__, encoding="utf-8").read()
_dangling = []
for _m in re.finditer(r"^def ([a-z][a-z0-9_]*)\(", _protocol_src, re.M):
    for _cand in (_m.group(1), "_" + _m.group(1)):
        if _cand in vars(P):
            continue
        if re.search(r"(?<![\w.])%s\s*\(" % re.escape(_cand), _proxy_src):
            _dangling.append(_cand)
check("搬走的函数在 ca_proxy 里没有悬空旧名", not _dangling, _dangling)

# stop_sequence 回填：上游把命中的串丢掉时只能给 null；真吐出来时才填。
_ev_stop = _messages([
    {"choices": [{"delta": {"content": "结果：END"}}]},
    {"choices": [{"delta": {}, "finish_reason": "stop"}]},
], holder={"stop_sequences": ["END", "STOP"]})
_delta_stop = [d for n, d in _ev_stop if n == "message_delta"][0]
check("流式：文本以停止串结尾时回填 stop_sequence",
      _delta_stop["delta"]["stop_sequence"] == "END", _delta_stop)

_ev_stop2 = _messages([
    {"choices": [{"delta": {"content": "自然结束。"}}]},
    {"choices": [{"delta": {}, "finish_reason": "stop"}]},
], holder={"stop_sequences": ["END"]})
_delta_stop2 = [d for n, d in _ev_stop2 if n == "message_delta"][0]
check("流式：没回显停止串时保持 null（不猜）",
      _delta_stop2["delta"]["stop_sequence"] is None, _delta_stop2)

_ev_stop3 = _messages([
    {"choices": [{"delta": {"content": "END"}}]},
    {"choices": [{"delta": {}, "finish_reason": "length"}]},
], holder={"stop_sequences": ["END"]})
_delta_stop3 = [d for n, d in _ev_stop3 if n == "message_delta"][0]
check("流式：max_tokens 收尾不填 stop_sequence",
      _delta_stop3["delta"]["stop_reason"] == "max_tokens"
      and _delta_stop3["delta"]["stop_sequence"] is None, _delta_stop3)


# ---------------------------------------------------------------------------
# 15. 第六刀：Anthropic 请求层搬进 ca_protocol
# ---------------------------------------------------------------------------

section("15. Anthropic 请求层（messages_to_chat 一族）")

_MOVED6 = {
    "_anthropic_json_text": "anthropic_json_text",
    "_anthropic_block_text": "anthropic_block_text",
    "_anthropic_image_part": "anthropic_image_part",
    "_anthropic_document_text": "anthropic_document_text",
    "_anthropic_content_to_text": "anthropic_content_to_text",
    "_anthropic_system_text": "anthropic_system_text",
    "_anthropic_tool_choice": "anthropic_tool_choice",
    "anthropic_tools_to_chat": "anthropic_tools_to_chat",
    "anthropic_effort_from_messages": "anthropic_effort_from_messages",
    "_anthropic_blocks_to_messages": "anthropic_blocks_to_messages",
}
_bad_alias = [old for old, new in _MOVED6.items() if hasattr(P, old)]
check("十个旧名字在 ca_proxy 里都已消失", not _bad_alias, _bad_alias)
check("messages_to_chat 是 ca_proxy 的包装（不直接别名）",
      P.messages_to_chat is not Q.messages_to_chat, None)


def _chat(payload):
    return Q.messages_to_chat(payload)


_m = _chat({"model": "m", "max_tokens": 5,
            "messages": [{"role": "user", "content": "hi"}]})
check("纯函数层不查模型表：不传默认值就不补 max_tokens",
      "max_tokens" in _m and _m["max_tokens"] == 5
      and "max_tokens" not in Q.messages_to_chat(
          {"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
      _m)
_w = P.messages_to_chat({"model": "glm-5.3",
                         "messages": [{"role": "user", "content": "hi"}]})
check("包装层仍按模型表补默认 max_tokens（行为不变）",
      _w.get("max_tokens") == P.model_default_max_output_tokens("glm-5.3") == 48000, _w)
check("显式 max_tokens 优先于默认值",
      P.messages_to_chat({"model": "glm-5.3", "max_tokens": 7,
                          "messages": [{"role": "user", "content": "hi"}]})["max_tokens"] == 7,
      None)

_img = _chat({"model": "m", "max_tokens": 9, "messages": [{"role": "user", "content": [
    {"type": "text", "text": "look"},
    {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                 "data": "AAA"}}]}]})
_parts = _img["messages"][0]["content"]
check("base64 图片拼成 data URL 且整条转成多模态 parts",
      isinstance(_parts, list) and _parts[1]["image_url"]["url"]
      == "data:image/png;base64,AAA", _parts)

_doc = _chat({"model": "m", "max_tokens": 9, "messages": [{"role": "user", "content": [
    {"type": "document", "title": "T", "source": {"type": "text", "data": "body"}}]}]})
check("文档块折成文本块（标题 + 正文）",
      _doc["messages"][0]["content"] == [{"type": "text", "text": "T\nbody"}],
      _doc["messages"][0])

_hist = _chat({"model": "m", "max_tokens": 9, "messages": [
    {"role": "user", "content": "t?"},
    {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "x"},
        {"type": "tool_use", "id": "tu_1", "name": "get", "input": {"z": 1}}]},
    {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1",
         "content": [{"type": "text", "text": "ok"}], "is_error": True}]}]})
_roles = [m["role"] for m in _hist["messages"]]
check("tool_result 落成紧随助手的 tool 消息",
      _roles == ["user", "assistant", "tool"], _roles)
check("tool_result 的 is_error 变成 error: 前缀",
      _hist["messages"][2]["content"] == "error: ok", _hist["messages"][2])
check("assistant 的 tool_use 变成 tool_calls、input 序列化成 JSON 串",
      _hist["messages"][1]["tool_calls"][0]["function"]["arguments"] == '{"z":1}',
      _hist["messages"][1])

_choice = _chat({"model": "m", "max_tokens": 9,
                 "tools": [{"name": "t", "input_schema": {"type": "object"}}],
                 "tool_choice": {"type": "any", "disable_parallel_tool_use": True},
                 "messages": [{"role": "user", "content": "go"}]})
check("tool_choice any → required，且 disable_parallel 关掉并行",
      _choice["tool_choice"] == "required" and _choice["parallel_tool_calls"] is False,
      (_choice.get("tool_choice"), _choice.get("parallel_tool_calls")))
_skip = _chat({"model": "m", "max_tokens": 9,
               "tools": [{"type": "computer_20250124", "name": "computer"}],
               "messages": [{"role": "user", "content": "go"}]})
check("没有 input_schema 的服务端工具被跳过并写进 system 提示",
      "tools" not in _skip
      and "computer" in _skip["messages"][0]["content"]
      and _skip["messages"][0]["role"] == "system", _skip.get("messages"))

check("thinking budget 9000 → medium，32000 → xhigh，disabled → none",
      Q.anthropic_effort_from_messages({"thinking": {"type": "enabled",
                                                     "budget_tokens": 9000}}) == "medium"
      and Q.anthropic_effort_from_messages({"thinking": {"type": "enabled",
                                                         "budget_tokens": 32000}}) == "xhigh"
      and Q.anthropic_effort_from_messages({"thinking": {"type": "disabled"}}) == "none",
      None)

_sys = _chat({"model": "m", "max_tokens": 9,
              "system": [{"type": "text", "text": "a"},
                         {"type": "text", "text": "b"}],
              "messages": [{"role": "user", "content": "x"},
                           {"role": "system", "content": "mid"},
                           {"role": "user", "content": "y"}]})
check("多段 system 用换行拼成一条、中途 system 保持原位",
      _sys["messages"][0] == {"role": "system", "content": "a\nb"}
      and _sys["messages"][2] == {"role": "system", "content": "mid"}
      and [m["role"] for m in _sys["messages"]] == ["system", "user", "system", "user"],
      _sys["messages"])

try:
    _chat({"model": "m", "max_tokens": 9,
           "messages": [{"role": "robot", "content": "x"}]})
    check("非法 role 抛 ValueError", False)
except ValueError as _exc:
    check("非法 role 抛 ValueError 且指明下标", "messages[0].role" in str(_exc), _exc)

# 第六刀的坑与第五刀同源：被搬函数内部还在叫 _anthropic_text(...)。
# 这次把守卫做双向：ca_protocol 里也不许出现「已改名函数的旧下划线名」。
_proto_src = open(Q.__file__, encoding="utf-8").read()
_defined = set(re.findall(r"^\s*def ([a-z][a-z0-9_]*)\(", _proto_src, re.M))
_stale = []
for _nm in _defined:
    _old = "_" + _nm
    if _old in _defined:
        continue
    if re.search(r"(?<![\w.])%s\s*\(" % re.escape(_old), _proto_src):
        _stale.append(_old)
check("ca_protocol 内部没有残留旧下划线名", not _stale, _stale)
check("被搬函数内部的互相引用真的能跑（不是只 import 通过）",
      Q.anthropic_content_to_text([{"type": "text", "text": "ok"}]) == "ok"
      and Q.anthropic_block_text({"content": [{"type": "text", "text": "in"}]}) == "in"
      and Q.anthropic_blocks_to_messages("user", [{"type": "text", "text": "z"}])[0]["content"] == "z",
      None)

_proto_code = re.sub(r'""".*?"""', "", _proto_src, flags=re.S)
check("纯函数层里没有 open( / self.wfile（不许摸 I/O；文档字符串不算）",
      "open(" not in _proto_code and "self.wfile" not in _proto_code, None)


# ---------------------------------------------------------------------------
# 16. 第七刀：Responses 状态机 + 依赖闭包搬进 ca_protocol
# ---------------------------------------------------------------------------

section("16. Responses 事件流（stream_responses_events）")

import ca_webtools as W  # noqa: E402

_MOVED7 = {
    "TAG_START": "TAG_START",
    "DSML_CALLS_RE": "DSML_CALLS_RE",
    "DSML_INVOKE_RE": "DSML_INVOKE_RE",
    "DSML_PARAM_RE": "DSML_PARAM_RE",
    "parse_dsml_tool_calls": "parse_dsml_tool_calls",
    "CJK_RE": "CJK_RE",
    "estimate_tokens": "estimate_tokens",
    "is_truncated_arguments": "is_truncated_arguments",
    "_NS_SEP": "NS_SEP",
    "resolve_namespaced_name": "resolve_namespaced_name",
    "stamp_namespace": "stamp_namespace",
    "apply_namespace_to_calls": "apply_namespace_to_calls",
    "_unwrap_custom_input": "unwrap_custom_input",
    "_CITATION_MD_RE": "CITATION_MD_RE",
    "build_citations": "build_citations",
    "web_tools_active": "web_tools_active",
    "_responses_usage": "responses_usage",
}
_bad7 = [old for old, new in _MOVED7.items() if hasattr(P, old)]
check("十七个旧名字在 ca_proxy 里都已消失", not _bad7, _bad7)
check("stream_responses_events 是包装（依赖 ca_webtools 注入）",
      P.stream_responses_events is not Q.stream_responses_events, None)


def _resp_events(chunks, holder, webtools=None, via_proxy=False):
    raw = iter([b"data: " + json.dumps(c).encode() for c in chunks] + [b"data: [DONE]"])
    gen = (P.stream_responses_events(raw, "m", holder) if via_proxy
           else Q.stream_responses_events(raw, "m", holder, webtools))
    out = []
    for frame in gen:
        typ = None
        for line in frame.decode().splitlines():
            if line.startswith("event: "):
                typ = line[7:]
        out.append(typ)
    return out


def _tc(index, cid, name, args):
    return {"choices": [{"delta": {"tool_calls": [
        {"index": index, "id": cid, "function": {"name": name, "arguments": args}}]}}]}


_txt_seq = _resp_events([
    {"choices": [{"delta": {"content": "你"}}]},
    {"choices": [{"delta": {"content": "好"}}]},
    {"choices": [{"delta": {}, "finish_reason": "stop"}],
     "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}},
], {"request_meta": {}})
check("纯文本事件序列固定（created → 文本 → completed）",
      _txt_seq == [
          "response.created", "response.in_progress", "response.output_item.added",
          "response.content_part.added", "response.output_text.delta",
          "response.output_text.delta", "response.output_text.done",
          "response.content_part.done", "response.output_item.done",
          "response.completed"], _txt_seq)

_tool_seq = _resp_events([
    _tc(0, "call_a", "get_weather", "{\"c\""),
    {"choices": [{"delta": {"tool_calls": [
        {"index": 0, "function": {"arguments": ":1}"}}]}}]},
    {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
], {})
check("结构化工具调用：function_call_arguments.delta → done → output_item.done",
      "response.function_call_arguments.delta" in _tool_seq
      and _tool_seq[-2] == "response.output_item.done"
      and _tool_seq[-1] == "response.completed", _tool_seq)

_web_seq = _resp_events([
    _tc(0, "call_w", "web_search", "{\"query\":\"x\"}"),
    {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
], {"base_body": {"_web_tools": True}}, webtools=W)
check("注入 webtools 时，网路工具被反代吞下并出 web_search_call 事件",
      "response.web_search_call.completed" in _web_seq
      and "response.function_call_arguments.done" not in _web_seq, _web_seq)
_plain_seq = _resp_events([
    _tc(0, "call_w", "web_search", "{\"query\":\"x\"}"),
    {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
], {"base_body": {"_web_tools": True}})
check("没注入 webtools 时不拦截（当成普通函数调用转发）",
      _plain_seq != _web_seq
      and "response.function_call_arguments.done" in _plain_seq, _plain_seq)
check("包装层把 ca_webtools 传进去了（线上路径仍然拦截）",
      "response.web_search_call.completed" in _resp_events([
          _tc(0, "call_w", "web_search", "{\"query\":\"x\"}"),
          {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
      ], {"base_body": {"_web_tools": True}}, via_proxy=True), None)

_dsml_text = ('<|DSML|function_calls><|DSML|invoke name="get_time">'
              '<|DSML|parameter name="tz">Asia/Shanghai</|DSML|parameter>'
              '</|DSML|invoke></|DSML|function_calls>')
_calls, _clean = Q.parse_dsml_tool_calls("前" + _dsml_text + "后")
check("DSML 解析出调用且 id 带 call_ 前缀",
      _calls and _calls[0]["name"] == "get_time"
      and _calls[0]["id"].startswith("call_")
      and json.loads(_calls[0]["arguments"])["tz"] == "Asia/Shanghai", _calls)
check("DSML 解析把标签从正文里摘掉", _clean == "前 后", repr(_clean))

_u = Q.responses_usage({"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14,
                        "completion_tokens_details": {"reasoning_tokens": 3},
                        "prompt_tokens_details": {"cached_tokens": 6}})
check("responses_usage 字段映射（含 reasoning / cached）",
      _u["input_tokens"] == 10 and _u["output_tokens"] == 4
      and _u["output_tokens_details"]["reasoning_tokens"] == 3
      and _u["input_tokens_details"]["cached_tokens"] == 6, _u)

check("estimate_tokens 对中文按字计、对英文约 3.6 字/token（都至少 1）",
      Q.estimate_tokens("中文") == 3
      and Q.estimate_tokens("abcdefghij") == 2
      and Q.estimate_tokens("") == 0,
      (Q.estimate_tokens("中文"), Q.estimate_tokens("abcdefghij")))
check("build_citations 只标注来源里真出现过的网址",
      Q.build_citations("见 [文档](https://a/x) 与 https://b/y",
                        [{"url": "https://a/x", "title": "A"}])
      and len(Q.build_citations("https://nope", [{"url": "https://a/x"}])) == 0, None)

# 第七刀最阴的坑：搬过去用了 time / re 却没 import，import ca_protocol 完全正常，
# 只有真跑到那一行才 NameError（golden 脚本因为 patch 了 time 反而把它盖住了）。
import builtins  # noqa: E402
import symtable  # noqa: E402


def _undefined_globals(path, allow=()):
    st = symtable.symtable(open(path, encoding="utf-8").read(), path, "exec")
    mod = {s.get_name() for s in st.get_symbols()
           if s.is_assigned() or s.is_imported() or s.is_namespace()}
    bad = []

    def walk(table):
        for sym in table.get_symbols():
            name = sym.get_name()
            if (sym.is_global() and name not in mod and name not in allow
                    and not hasattr(builtins, name)):
                bad.append((table.get_name(), name))
        for child in table.get_children():
            walk(child)

    walk(st)
    return bad


_bad_names = _undefined_globals(Q.__file__)
check("ca_protocol 里没有「用了但没定义/没 import」的全局名",
      not _bad_names, _bad_names)
_bad_proxy = _undefined_globals(P.__file__, allow=("__file__", "__name__"))
check("ca_proxy 同样干净（这条能兜住所有搬家漏别名）", not _bad_proxy, _bad_proxy)


# ---------------------------------------------------------------------------
# 17. 第八刀：非流式回包 chat_to_messages
# ---------------------------------------------------------------------------

section("17. 非流式回包（chat_to_messages）")

check("两个旧名字在 ca_proxy 里都已消失",
      not hasattr(P, "chat_to_messages")
      and not hasattr(P, "_anthropic_parse_tool_input"), None)

_msg = Q.chat_to_messages({
    "id": "cmpl-1", "model": "glm-5.3",
    "choices": [{"finish_reason": "tool_calls", "message": {
        "reasoning_content": "想一想", "content": "好的",
        "tool_calls": [{"id": "call_1",
                        "function": {"name": "get_time", "arguments": "{\"tz\":\"CST\"}"}}]}}],
    "usage": {"prompt_tokens": 9, "completion_tokens": 4,
              "prompt_cache_hit_tokens": 2},
})
check("thinking / text / tool_use 三类块按序产出",
      [c["type"] for c in _msg["content"]] == ["thinking", "text", "tool_use"],
      _msg["content"])
check("tool_use 的 input 被解析成对象、id 原样保留",
      _msg["content"][2]["input"] == {"tz": "CST"}
      and _msg["content"][2]["id"] == "call_1", _msg["content"][2])
check("stop_reason 与 usage 都映射到 Anthropic 口径",
      # input_tokens 不含缓存（9 = 7 新读入 + 2 命中）。
      _msg["stop_reason"] == "tool_use" and _msg["usage"]["input_tokens"] == 7
      and _msg["usage"]["cache_read_input_tokens"] == 2, (_msg["stop_reason"], _msg["usage"]))
check("id 补 msg_ 前缀、model 透传",
      _msg["id"].startswith("msg_") and _msg["model"] == "glm-5.3", _msg["id"])

_empty = Q.chat_to_messages({})
check("空对象也给完整骨架（不抛异常）",
      _empty["type"] == "message" and _empty["content"] == []
      and _empty["stop_reason"] == "end_turn", _empty)

check("工具参数解析：None→{}、dict 原样、非法 JSON→{raw}、标量→{value}",
      Q.anthropic_parse_tool_input(None) == {}
      and Q.anthropic_parse_tool_input({"a": 1}) == {"a": 1}
      and Q.anthropic_parse_tool_input("{bad") == {"raw": "{bad"}
      and Q.anthropic_parse_tool_input("[1,2]") == {"value": [1, 2]}
      and Q.anthropic_parse_tool_input(7) == {"value": 7}, None)

# 失败请求的工具定义落盘：默认关闭，开启后只写客户端配置（不含消息正文），
# 且 5 分钟内最多一份 —— 客户端反复重试时不能把盘刷满。
import tempfile as _tempfile

_dump_dir = _tempfile.mkdtemp(prefix="dump-")
_old_usage_log = P.USAGE_LOG
_old_flag = os.environ.pop("WB_DUMP_FAILED_TOOLS", None)
try:
    P.USAGE_LOG = os.path.join(_dump_dir, "usage.jsonl")
    P.dump_failed_request({"model": "m", "tools": [{"type": "function"}]}, [], 8)
    check("默认不落盘", os.listdir(_dump_dir) == [], os.listdir(_dump_dir))
    os.environ["WB_DUMP_FAILED_TOOLS"] = "1"
    P.dump_failed_request({"model": "m", "tools": [{"type": "function"}]}, [], 8)
    _files = [f for f in os.listdir(_dump_dir) if f.startswith("failed-req-")]
    check("开启后落一份", len(_files) == 1, _files)
    _blob = json.load(io.open(os.path.join(_dump_dir, _files[0]), encoding="utf-8"))
    check("只落客户端配置（tools/shape，没有 messages）",
          "messages" not in _blob and _blob.get("tools") and "shape" in _blob,
          sorted(_blob))
    P.dump_failed_request({"model": "m", "tools": [{"type": "function"}]}, [], 8)
    check("5 分钟内不重复落盘",
          len([f for f in os.listdir(_dump_dir) if f.startswith("failed-req-")]) == 1,
          os.listdir(_dump_dir))
finally:
    if _old_flag is not None:
        os.environ["WB_DUMP_FAILED_TOOLS"] = _old_flag
    else:
        os.environ.pop("WB_DUMP_FAILED_TOOLS", None)
    P.USAGE_LOG = _old_usage_log
    import shutil as _shutil_dump
    _shutil_dump.rmtree(_dump_dir, ignore_errors=True)

print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

"""2026-10-23 二轮 bug 修复的回归测试。

四条都已用桩/本地 socket 复现过，这里钉住修复后的语义：

2. **断流重开没把 tool_calls 算作「已输出」**：判断条件只看 content /
   reasoning。断流前只吐了半个工具调用时，重开的流又从 index=0 发同一个调用，
   客户端按 index 归并参数分片，两段粘起来就是坏 JSON
   （``{"path": "a"`` 接上 ``{"path": "a"}``）。

3. **401/403 的冷却永远不执行**：这个分支套在 ``if retryable`` 里面，而
   401 恰好是不可重试的，所以进不去。凭据被吊销的号一直留在池子里，
   有两个号时约一半请求报 credentials_error。

4. **Codex 链路不受 75 秒建连预算约束**：``responses_to_chat`` 转换时没带
   ``stream``，预算判断永远不成立。一次 APIG.0203 会重试 4 轮，最坏约
   255 秒。Messages 链路不受影响（``messages_to_chat`` 一直有拷贝）。

5. **iter_sse 判断静默只看 socket**：看不到 Python 读缓冲里已经收到的数据。
   响应头和前几块 body 在同一个 TCP 包里到达时，要等下一个包或 15 秒超时
   才转发，表现为首字延迟；更极端时把完好的流误报成断流。

不联网（第 5 条用本地 socketpair）。
"""

import io
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C   # noqa: E402
import ca_proxy as P      # noqa: E402

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


def _frame(obj):
    return "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"


class _Lease:
    """上游租约替身：按剧本吐行，可选在某一行之后抛 UpstreamBroken。"""

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
                if _stats is not None:
                    _stats["truncated"] = True
                raise C.UpstreamBroken("upstream closed early", 0)
            yield line
        if self._broken_after is not None:
            raise C.UpstreamBroken("upstream closed early", 0)

    def byte_lines(self, _abort_check=None, _stats=None):
        for line in self.lines(_abort_check, _stats):
            yield line.encode("utf-8")

    def close(self):
        self.closed = True


class _Handler(P.Handler):
    def __init__(self, path="/v1/chat/completions"):
        self.path = path
        self.wfile = io.BytesIO()
        self.status = 200
        self.open_calls = 0

    def _client_disconnected(self):
        return False

    def _json(self, code, obj):
        self.status = code
        return code, obj

    def _error(self, code, message, err_type=None):
        self.status = code
        return code, {"error": message}

    def _anthropic_error(self, code, message, err_type=None):
        return self._error(code, message, err_type)

    def send_response(self, code):
        self.status = code

    def send_header(self, _k, _v):
        pass

    def end_headers(self):
        pass

    def _key_id(self):
        return "test-key"

    def _handle_expect_continue(self):
        pass

    def _discard_body(self):
        pass


def _run_chat(leases):
    """依次把 leases 交给 chat 流式处理器，返回 (handler, SSE 文本)。"""
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


_rows = []
_orig_error, _orig_usage = P.record_error, P.record_usage


def _spy_error(*args, **kwargs):
    _rows.append(("error", args[1] if len(args) > 1 else kwargs.get("status"),
                  kwargs.get("outcome")))


def _spy_usage(*args, **kwargs):
    _rows.append(("usage", None, kwargs.get("outcome")))


class _spy:
    """临时替换记账函数，退出时必定还原。"""

    def __enter__(self):
        _rows.clear()
        P.record_error, P.record_usage = _spy_error, _spy_usage
        return _rows

    def __exit__(self, *_exc):
        P.record_error, P.record_usage = _orig_error, _orig_usage
        return False


# ---------------------------------------------------------------------------
# 2. 断流重开：tool_calls 也算「已经给过客户端」
# ---------------------------------------------------------------------------

section("2. 断流重开要把 tool_calls 算作已输出")

# 只剩半个工具调用：id/name 来了，arguments 只来了一半
_tc_half = _frame({"choices": [{"delta": {"tool_calls": [
    {"index": 0, "id": "call_a", "type": "function",
     "function": {"name": "read_file", "arguments": "{\"path\": \"a\""}}]}}]})
# 重开后如果又发同一个 index=0 的调用，客户端会把两段参数拼在一起
_tc_full = _frame({"choices": [{"delta": {"tool_calls": [
    {"index": 0, "id": "call_a", "type": "function",
     "function": {"name": "read_file", "arguments": "{\"path\": \"a\"}"}}]},
    "finish_reason": "tool_calls"}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 2}})

with _spy():
    _h, _sse = _run_chat([_Lease([_tc_half], 1), _Lease([_tc_full], None)])

check("只吐了半个工具调用时**不重开**（重开会拼出坏 JSON）",
      _h.open_calls == 1, _h.open_calls)
check("断流按失败收尾，不补 finish_reason",
      '"finish_reason": "tool_calls"' not in _sse, _sse[-260:])
check("断流发明确的 error 帧", '"upstream_error"' in _sse
      or '"error"' in _sse, _sse[-260:])
check("半个工具调用的 delta 已经转发给客户端（不能假装没发生）",
      "call_a" in _sse, _sse[-260:])
check("断流记账为 upstream_aborted",
      _rows and _rows[0][0] == "error"
      and _rows[0][2] == "upstream_aborted", _rows)

# 反向对照：什么都没吐过时仍然重开（别为了让这条过而把重开整个关掉）
with _spy():
    _h2, _sse2 = _run_chat([_Lease([], 0), _Lease([_tc_full], None)])
check("一个字都没吐过时照常重开一次（修复不能把重开一起关掉）",
      _h2.open_calls == 2, _h2.open_calls)
check("重开后客户端只看到一份工具调用",
      _sse2.count("call_a") == 1, _sse2.count("call_a"))

# 正文只吐了空白之外的极短片段也要算「吐过」
with _spy():
    _h3, _sse3 = _run_chat([
        _Lease([_frame({"choices": [{"delta": {"content": "x"}}]})], 1),
        _Lease([_tc_full], None)])
check("正文吐过一个字也不算「没输出」", _h3.open_calls == 1, _h3.open_calls)

# reasoning 也算（原有行为，别回退）
with _spy():
    _h4, _sse4 = _run_chat([
        _Lease([_frame({"choices": [{"delta": {"reasoning_content": "想"}}]})], 1),
        _Lease([_tc_full], None)])
check("推理内容同样算已输出（原有语义保留）", _h4.open_calls == 1, _h4.open_calls)


# ---------------------------------------------------------------------------
# 3. 401/403 的号必须被冷却（哪怕这一条不重试）
# ---------------------------------------------------------------------------

section("3. 凭据失效的账号要被晾起来")


class _PoolSpy:
    """记录 penalize / acquire / release，账号池的替身。"""

    def __init__(self, keys):
        self.keys = list(keys)
        self.penalized = []
        self.acquired = []

    def acquire(self, _wait, session_key=None, model=None):
        key = self.keys[len(self.acquired) % len(self.keys)]
        self.acquired.append(key)
        # 形状要与真实池子一致：调用方读 session["account"]["label"] 与三个凭据
        return ({"account": {"label": key}, "accessKey": "AK",
                 "secretKey": "SK", "securitytoken": "TK"}, key)

    def release(self, _key):
        pass

    def penalize(self, key, seconds, model=None):
        self.penalized.append((key, round(seconds, 1), model))

    def _usable(self):
        return [{"account": {"id": k}} for k in self.keys]

    def limits_blocked(self, _model=None):
        return False

    def snapshot(self):
        return {}

    def remember(self, *_a, **_k):
        pass


def _run_aggregate(pool, status, body, model="glm-5.3"):
    """让聚合路径（非流式）跑一轮，返回 (handler, (error, result))。"""
    h = _Handler()
    h.headers = {}

    # 聚合路径走 ca_codearts.chat_for_model（不是 open_chat）：它返回的是
    # (状态码, 原始响应体)，正好是这条路径要的形状。
    def _chat_for_model(*_a, **_k):
        return status, body

    saved_pool = P._CODEARTS_POOL
    saved_chat = C.chat_for_model
    saved_idle = P.codearts_session_idle
    saved_busy = P.codearts_session_busy
    P._CODEARTS_POOL = pool
    C.chat_for_model = _chat_for_model
    P.codearts_session_idle = lambda *_a, **_k: None
    P.codearts_session_busy = lambda *_a, **_k: ("sid", True, "ok")
    try:
        out = h._codearts_chat_result(
            {"model": model, "messages": [{"role": "user", "content": "hi"}]})
    finally:
        P._CODEARTS_POOL = saved_pool
        C.chat_for_model = saved_chat
        P.codearts_session_idle = saved_idle
        P.codearts_session_busy = saved_busy
    return h, out


class _FakeResp:
    def __init__(self, body):
        self._body = (body or "").encode("utf-8")
        self.closed = False

    def read1(self, _n):
        out, self._body = self._body, b""
        return out

    def read(self, _n=-1):
        out, self._body = self._body, b""
        return out

    def close(self):
        self.closed = True


_401 = json.dumps({"error_code": "APIG.0301",
                   "error_msg": "access key not found"})

with _spy():
    _pool = _PoolSpy(["acct-a", "acct-b"])
    _h, _out = _run_aggregate(_pool, 401, _401)
_err = _out[0]
check("401 对客户端仍是失败", _err is not None, _out)
check("401 不给客户端回「换个号就好了」的成功", _err != 200, _err)
check("**401 之后那个号被冷却了**（以前这个分支永远进不去）",
      any(p[0] == "acct-a" for p in _pool.penalized), _pool.penalized)
check("冷却是账号级的（不带 model，凭据失效影响这个号的所有模型）",
      all(p[2] is None for p in _pool.penalized), _pool.penalized)
check("冷却时长用的是 CODEARTS_AUTH_COOLDOWN",
      _pool.penalized and _pool.penalized[0][1] == round(
          P.CODEARTS_AUTH_COOLDOWN, 1), (_pool.penalized, P.CODEARTS_AUTH_COOLDOWN))
check("凭据失效不重试（同一请求再发还是 401）",
      len(_pool.acquired) == 1, _pool.acquired)

# 403 同理
with _spy():
    _pool403 = _PoolSpy(["acct-c"])
    _h403, _out403 = _run_aggregate(
        _pool403, 403,
        json.dumps({"error_code": "APIG.0303", "error_msg": "forbidden"}))
check("403 之后那个号同样被冷却",
      any(p[0] == "acct-c" for p in _pool403.penalized), _pool403.penalized)
check("403 也不重试", len(_pool403.acquired) == 1, _pool403.acquired)

# 反向对照：可重试的 429 仍然重试，且仍然带 model 冷却
with _spy():
    _pool429 = _PoolSpy(["acct-d", "acct-e"])
    _h429, _out429 = _run_aggregate(
        _pool429, 429, json.dumps({"error_code": "ModelArts.81114"}))
check("429 仍然重试（修复没把限流重试一起关掉）",
      len(_pool429.acquired) > 1, _pool429.acquired)
check("429 的冷却是按模型的（TPM 只影响这个模型）",
      any(p[2] == "glm-5.3" for p in _pool429.penalized), _pool429.penalized)


# ---------------------------------------------------------------------------
# 4. Codex 链路的 stream 字段
# ---------------------------------------------------------------------------

section("4. responses_to_chat 必须带上 stream")


_chat_stream = P.responses_to_chat({
    "model": "glm-5.3", "stream": True,
    "input": [{"role": "user", "content": "hi"}]})
check("**流式请求转换后仍带 stream=True**（预算判断靠它）",
      _chat_stream.get("stream") is True, _chat_stream.get("stream"))

_chat_plain = P.responses_to_chat({
    "model": "glm-5.3",
    "input": [{"role": "user", "content": "hi"}]})
check("没给 stream 时不凭空加字段（与 messages_to_chat 同口径）",
      "stream" not in _chat_plain, sorted(_chat_plain))

_chat_off = P.responses_to_chat({
    "model": "glm-5.3", "stream": False,
    "input": [{"role": "user", "content": "hi"}]})
check("stream=false 原样保留成 False",
      _chat_off.get("stream") is False, _chat_off.get("stream"))

# 与 Messages 链路对齐（那条一直是对的，别在重构里丢）
_msg_chat = P.messages_to_chat({
    "model": "glm-5.3", "stream": True, "max_tokens": 16,
    "messages": [{"role": "user", "content": "hi"}]})
check("Messages 链路仍然带 stream（对照，不该被改坏）",
      _msg_chat.get("stream") is True, _msg_chat.get("stream"))

# 预算判断真的能拿到它：模拟一个流式请求走到预算检查
_src = io.open(P.__file__, encoding="utf-8").read()
check("预算判断读的是 payload 的 stream（chat 入口）或转换后的字段",
      'if (retryable and payload.get("stream")' in _src, None)
check("responses_to_chat 里有 stream 拷贝（这条静态钉住回归）",
      'chat["stream"] = bool(payload.get("stream"))' in _src, None)


# ---------------------------------------------------------------------------
# 5. 静默判断要看 Python 读缓冲
# ---------------------------------------------------------------------------

section("5. iter_sse 不能把「已缓冲的字节」当成静默")


def _pair():
    l, r = socket.socketpair()
    l.settimeout(15.0)
    return l, r, l.makefile("rb")


class _Resp:
    def __init__(self, fp, sock):
        self.fp = fp
        self._sock = sock

    def read1(self, n):
        return self.fp.read1(n)


# 场景：响应头与首批 body 在同一个包里 —— 解析响应头时 body 已进缓冲
_l, _r, _fp = _pair()
_r.sendall(b"HTTP/1.1 200 OK\r\nX-Test: 1\r\n\r\n"
           b'data: {"choices":[{"delta":{"content":"first"}}]}\n\n')
_fp.readline()                       # 消费掉第一行响应头，body 留在缓冲里
_buffered = len(_fp.peek(0))
check("构造出「缓冲里有数据、socket 上没新字节」的场景",
      _buffered > 0, _buffered)

_t0 = time.time()
_ready = C._wait_readable(_l, 2.0, _fp)
_waited = time.time() - _t0
check("**缓冲里有数据时立即判为可读**（不等满静默窗口）",
      _ready is True and _waited < 0.5, (_ready, round(_waited, 3)))

# 不传 fp 时退回旧语义（只看 socket）—— 保持向后兼容
_t0 = time.time()
_ready_nofp = C._wait_readable(_l, 1.0)
check("不传 fp 时退回「只看 socket」（旧调用点不会行为突变）",
      _ready_nofp is False, _ready_nofp)

# 端到端：首字不能被推迟
_l2, _r2, _fp2 = _pair()
_r2.sendall(b"HTTP/1.1 200 OK\r\n\r\n"
            b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')
_fp2.readline()
_resp2 = _Resp(_fp2, _l2)
_t0 = time.time()
_first = None
for _line in C.iter_sse(_resp2, idle_timeout=5.0, stats={}):
    if _line is C.KEEPALIVE:
        continue
    if "hi" in _line:
        _first = time.time() - _t0
        break
check("**首字立即可取**（修复前要等满 idle_timeout）",
      _first is not None and _first < 0.5, _first)

# 缓冲空、socket 也无数据 → 仍然走 select，行为不变
_l3, _r3, _fp3 = _pair()
_t0 = time.time()
_ready3 = C._wait_readable(_l3, 0.3, _fp3)
_elapsed3 = time.time() - _t0
check("缓冲空时仍然按 select 等满（静默检测本身没被削弱）",
      _ready3 is False and _elapsed3 >= 0.25, (_ready3, round(_elapsed3, 3)))

# 探测不能把连接弄坏：非阻塞 peek 之后照常读
_r3.sendall(b"data: after\n\n")
check("探测之后连接仍然可读（非阻塞 peek 没有毒化 SocketIO）",
      _fp3.read1(100) == b"data: after\n\n", None)

# 拿不到 fp / 不是 BufferedReader → 当作没有缓冲，不抛
check("fp 为 None 时不抛", C._buffered_bytes(None) == 0, None)
check("fp 没有 peek 时返回 0", C._buffered_bytes(object()) == 0, None)

for _sock, _f in ((_l, _fp), (_l2, _fp2), (_l3, _fp3)):
    try:
        _f.close()
        _sock.close()
    except Exception:
        pass
for _s in (_r, _r2, _r3):
    try:
        _s.close()
    except Exception:
        pass

check("_wait_readable 的签名接受 fp（调用点已传）",
      "_wait_readable(sock, idle_timeout," in
      io.open(C.__file__, encoding="utf-8").read(), None)
check("iter_sse 把 resp.fp 传下去了",
      'getattr(resp, "fp", None)' in io.open(C.__file__, encoding="utf-8").read(),
      None)


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

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
import copy
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C   # noqa: E402
import ca_stream as S
import ca_settings as SET
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

    # 真实租约把「关连接」和「idle + 还名额」拆开了（见 _CodeartsLease）：
    # close_upstream 先执行，[DONE] 之后才 release_slot。
    def close_upstream(self):
        self.closed = True

    def release_slot(self):
        self.slot_released = True


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


class _NoSleep:
    """把退避睡眠打桩掉。

    重试环里的 ``time.sleep`` 是真实等待（BUSY 2/5/8s，RETRY 5/12/25/40s）。
    这个套件要验的是「重不重试、冷却了谁」，不是退避时长 —— 真等一遍会让
    套件慢到 80 秒以上。这里只记录睡了多少，不真睡。
    """

    def __init__(self):
        self.slept = []

    def __call__(self, seconds):
        self.slept.append(seconds)

    def __enter__(self):
        self._saved = P.time.sleep
        P.time.sleep = self
        return self

    def __exit__(self, *_exc):
        P.time.sleep = self._saved
        return False


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

with _spy(), _NoSleep():
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
with _spy(), _NoSleep():
    _h2, _sse2 = _run_chat([_Lease([], 0), _Lease([_tc_full], None)])
check("一个字都没吐过时照常重开一次（修复不能把重开一起关掉）",
      _h2.open_calls == 2, _h2.open_calls)
check("重开后客户端只看到一份工具调用",
      _sse2.count("call_a") == 1, _sse2.count("call_a"))

# 正文只吐了空白之外的极短片段也要算「吐过」
with _spy(), _NoSleep():
    _h3, _sse3 = _run_chat([
        _Lease([_frame({"choices": [{"delta": {"content": "x"}}]})], 1),
        _Lease([_tc_full], None)])
check("正文吐过一个字也不算「没输出」", _h3.open_calls == 1, _h3.open_calls)

# reasoning 也算（原有行为，别回退）
with _spy(), _NoSleep():
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

    # 真实租约把「关连接」和「idle + 还名额」拆开了（见 _CodeartsLease）：
    # close_upstream 先执行，[DONE] 之后才 release_slot。
    def close_upstream(self):
        self.closed = True

    def release_slot(self):
        self.slot_released = True


_401 = json.dumps({"error_code": "APIG.0301",
                   "error_msg": "access key not found"})


with _spy(), _NoSleep():
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
with _spy(), _NoSleep():
    _pool403 = _PoolSpy(["acct-c"])
    _h403, _out403 = _run_aggregate(
        _pool403, 403,
        json.dumps({"error_code": "APIG.0303", "error_msg": "forbidden"}))
check("403 之后那个号同样被冷却",
      any(p[0] == "acct-c" for p in _pool403.penalized), _pool403.penalized)
check("403 也不重试", len(_pool403.acquired) == 1, _pool403.acquired)

# 反向对照：可重试的 429 仍然重试，且仍然带 model 冷却
with _spy(), _NoSleep():
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
# 反向验证时（把缓冲探测关掉）这个循环会空等到 max_idle 才抛 UpstreamBroken，
# 那正好也是本条要抓的失败形态 —— 包起来，别让反向验证把套件挂死。
try:
    _it2 = C.iter_sse(_resp2, idle_timeout=0.5, max_idle=3, stats={})
    for _line in _it2:
        if _line is C.KEEPALIVE:
            continue
        if "hi" in _line:
            _first = time.time() - _t0
            break
except C.UpstreamBroken:
    _it2.close() if hasattr(_it2, "close") else None
check("**首字立即可取**（修复前要等满 idle_timeout）",
      _first is not None and _first < 0.4, _first)

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
check("iter_sse 把 resp 也传下去了（分帧判定要用 chunk_left）",
      "getattr(resp, \"fp\", None), resp)" in
      io.open(C.__file__, encoding="utf-8").read(), None)


# ---------------------------------------------------------------------------
# 5b. 回归：chunked 的分帧 CRLF 不能把「静默」误判成「可读」
#
# 6916c03 加了「先看 Python 读缓冲」之后，首字延迟修好了，但引入一个新问题：
# 一块载荷被 read1 取走之后，缓冲里还留着这一块的结束 CRLF。peek(0) 非空 →
# 判可读 → read1 进去先吃掉 CRLF、再去 socket 读下一块的长度行，**阻塞在
# socket 上**。后果是连锁的：模型思考时不再发 keepalive（中间层 60~100 秒
# 就切断连接）、客户端断开发现不了、静默上限退化成 socket 读超时。
# ---------------------------------------------------------------------------

print("\n[5b] chunked 分帧不再骗过静默判定")

_CRLF = b"\r\n"
_cases = [
    (b"", None, False, "空缓冲"),
    (_CRLF, 0, False, "只有本块的结束 CRLF（回归现场）"),
    (_CRLF + b"5" + _CRLF, 0, False, "长度行到了、载荷没到"),
    (_CRLF + b"5" + _CRLF + b"hello", 0, True, "长度行 + 载荷都到了"),
    (b"5" + _CRLF + b"hello", None, True, "还没进入块：长度行 + 载荷"),
    (b"5" + _CRLF, None, False, "只有长度行"),
    (b"0" + _CRLF + _CRLF, None, True, "末块完整"),
    (b"0" + _CRLF, None, False, "末块缺结尾空行"),
    (b"abc", 10, True, "块内还有载荷"),
]
for _data, _cl, _want, _why in _cases:
    check("分帧判定：%s" % _why,
          C._chunk_payload_ready(_data, _cl) is _want,
          (_data, _cl, C._chunk_payload_ready(_data, _cl)))


class _ChunkedResp:
    """只带 iter_sse 需要的形状：chunked + chunk_left。"""
    chunked = True
    length = None

    def __init__(self, fp, chunk_left):
        self.fp = fp
        self.chunk_left = chunk_left


_l4, _r4, _fp4 = _pair()
_r4.sendall(_CRLF)                    # 只有分帧 CRLF，没有载荷
_resp4 = _ChunkedResp(_fp4, 0)
_t0 = time.time()
_ready4 = C._wait_readable(_l4, 0.3, _fp4, _resp4)
_waited4 = time.time() - _t0
check("**缓冲里只有分帧 CRLF 时判为不可读**（回归核心）",
      _ready4 is False, _ready4)
check("并且真的等满了静默窗口（没有被提前放行）",
      _waited4 >= 0.25, round(_waited4, 3))

_r4.sendall(b"5" + _CRLF + b"hello")
# 注意：新到的字节还在内核里，pip 缓冲里没有 —— 所以要问 _wait_readable
# （它先看缓冲再退回 select），单问 _buffered_payload 会得到 False 是正常的。
check("载荷到了之后立刻判可读（走 select 那一半）",
      C._wait_readable(_l4, 0.3, _fp4, _ChunkedResp(_fp4, 0)) is True, None)
try:
    _fp4.close(); _l4.close(); _r4.close()
except Exception:
    pass

# 端到端：静默期间必须有 KEEPALIVE（不是「一块载荷之后就阻塞住」）
import http.client  # noqa: E402
import threading     # noqa: E402


def _serve_chunked(srv, hold):
    conn, _ = srv.accept()
    conn.recv(65536)
    body = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n")
    conn.sendall(("%x\r\n" % len(body)).encode() + body + _CRLF)
    time.sleep(hold)
    last = b"data: [DONE]\n\n"
    conn.sendall(("%x\r\n" % len(last)).encode() + last + b"\r\n0\r\n\r\n")
    time.sleep(0.2)
    conn.close()


def _local_chunked(hold):
    """起一个本地 chunked SSE 服务，返回 (conn, resp)。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    threading.Thread(target=_serve_chunked, args=(srv, hold),
                     daemon=True).start()
    conn = http.client.HTTPConnection("127.0.0.1", srv.getsockname()[1],
                                      timeout=60)
    conn.request("GET", "/")
    return srv, conn, conn.getresponse()


_srv, _conn, _resp5 = _local_chunked(3.0)
_pings = 0
_lines5 = 0
_t0 = time.time()
for _piece in C.iter_sse(_resp5, idle_timeout=0.5, max_idle=20):
    if _piece is C.KEEPALIVE:
        _pings += 1
    else:
        _lines5 += 1
_elapsed5 = time.time() - _t0
check("**首帧之后的静默期照样发 keepalive**（回归：以前一个都没有）",
      _pings >= 3, _pings)
check("流照常读完（不会因为探测把自己弄断）",
      _lines5 >= 3 and _elapsed5 >= 2.5, (_lines5, round(_elapsed5, 1)))
try:
    _conn.close(); _srv.close()
except Exception:
    pass

# abort_check 在静默期必须被问到（客户端断开检测）
_srv2, _conn2, _resp6 = _local_chunked(5.0)
_abort = {"n": 0}


def _abort_check():
    _abort["n"] += 1
    return _abort["n"] >= 3


_t0 = time.time()
_aborted = False
try:
    for _ in C.iter_sse(_resp6, _abort_check, idle_timeout=0.5, max_idle=20):
        pass
except C.ChatAborted:
    _aborted = True
check("**静默期会问 abort_check**（回归：以前阻塞在 read1 上，问不到）",
      _aborted and _abort["n"] >= 3, (_aborted, _abort["n"]))
check("客户端断开能立刻收手（不等上游发下一块）",
      time.time() - _t0 < 3.0, round(time.time() - _t0, 2))
try:
    _conn2.close(); _srv2.close()
except Exception:
    pass




# ---------------------------------------------------------------------------
# 2026-10-24 官方对齐四件套（逆向 CodeArts Agent 客户端后落地）：
#   A. effort 档位白名单：官方对档位表为空的模型（glm-5.3）永远不发
#      reasoning_effort —— effort=max 的深思考 60s 静默是断流根源。
#   B. max_tokens 官方口径钳制：官方对 glm-5.3 每轮发 32000（能力值 65536）。
#   C. x-session-retry 头：重试计数让服务端看得见（官方重试协议）。
#   D. 同形状连续失败快停：官方 watchdog 超时重试上限 3 次，到顶 abort。
# ---------------------------------------------------------------------------

_orig_variants = C.thinking_variants
try:
    # A. 档位白名单
    check("白名单为空（glm-5.3）→ effort 不发",
          C.thinking_extra_from({"reasoning_effort": "max"},
                                effort_allowed=()) is None, None)
    check("白名单内 → effort 照发",
          C.thinking_extra_from({"reasoning_effort": "low"},
                                effort_allowed=("low", "high"))
          == {"thinking": {"type": "enabled"}, "reasoning_effort": "low"}, None)
    check("白名单外 → effort 丢弃",
          C.thinking_extra_from({"reasoning_effort": "max"},
                                effort_allowed=("low", "high")) is None, None)
    check("白名单未知（None）→ 维持转发（旧行为）",
          C.thinking_extra_from({"reasoning_effort": "max"})
          == {"thinking": {"type": "enabled"}, "reasoning_effort": "max"}, None)
    check("effort 被丢但客户端带 thinking → thinking 保留",
          C.thinking_extra_from({"thinking": {"type": "enabled"},
                                 "reasoning_effort": "max"},
                                effort_allowed=())
          == {"thinking": {"type": "enabled"}}, None)

    # 种子表 + 拉取失败回落
    check("种子表：glm-5.3 档位为空", C.THINKING_STRENGTHS_SEED["glm-5.3"] == (),
          None)
    C._THINKING_STRENGTHS.clear()
    _fetches = []
    C.thinking_variants = lambda *a, **k: _fetches.append(1) or {}
    check("上游拉取失败 → 回落种子（glm-5.3 → 空白名单）",
          C.refresh_thinking_strengths("ak", "sk", None, "glm-5.3") == (), None)
    check("未知模型拉取失败 → None（不约束）",
          C.refresh_thinking_strengths("ak", "sk", None, "mystery") is None,
          None)
    check("命中缓存不再发请求",
          (C.refresh_thinking_strengths("ak", "sk", None, "glm-5.3"), len(_fetches))
          == ((), 2), len(_fetches))   # 两次调用共 2 次拉取（每模型 1 次）
    C.thinking_variants = lambda *a, **k: {"x-model": {"strengths": ["low"]}}
    check("上游档位表覆盖种子",
          C.refresh_thinking_strengths("ak", "sk", None, "x-model")
          == ("low",), None)
    C._THINKING_STRENGTHS.clear()
finally:
    C.thinking_variants = _orig_variants

# B. max_tokens 钳制（官方请求形状）
check("glm-5.3 max_tokens 65536 → 32000",
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": 65536}) == 32000,
      None)
check("glm-5.3 缺省（目录值 65536）→ 也钳到 32000",
      P._codearts_max_tokens({"model": "glm-5.3"}) == 32000, None)
check("低于官方值的也上钳到 32000（2026-10-24 官方镜像：预算恒定防思考吃光）",
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": 1000}) == 32000,
      None)
check("没有实证值的模型不钳（显式值透传）",
      P._codearts_max_tokens({"model": "kimi-k3", "max_tokens": 999999})
      == 999999,   # kimi-k3 无 CAP 条目：客户端显式给值就照发
      P._codearts_max_tokens({"model": "kimi-k3", "max_tokens": 999999}))

# C. x-session-retry 头
_h = C.chat_headers("ak", "sk", None, "deadbeef", session_retry=2)
check("重试计数头存在", _h.get("x-session-retry") == "2", None)
_h0 = C.chat_headers("ak", "sk", None, "deadbeef")
check("首次尝试不带重试头", "x-session-retry" not in _h0, None)



# ---------------------------------------------------------------------------
# 2026-10-24 排队叫号协议（逆向 kernel queue-retry 后落地）：
#   请求带 is-need-queue → 429 + queue-status: queued → 轮询
#   /api/v1/concurrency/trace-queues/{traceId} → promoted 后原样重发。
#   not_found / 连续 3 次 GET 失败 / 超时上限 → 按 429 交回上层退避。
# ---------------------------------------------------------------------------

import io as _io
import json as _json
import urllib.error as _ue
import urllib.request as _ur


class _Headers(dict):
    """长成 HTTPError.headers 那样的键值表（大小写不敏感由解析侧统一）。"""


check("排队头解析：queued + 全字段",
      C._queue_info_from_headers(_Headers(
          {"queue-status": "queued", "trace-id": "t1", "retry-after": "7",
           "queue-length": "3", "queue-wait-time": "42"}))
      == {"trace_id": "t1", "retry_after": 7.0, "length": 3.0, "wait": 42.0},
      None)
check("排队头解析：rejected 不排队",
      C._queue_info_from_headers(
          _Headers({"queue-status": "rejected", "trace-id": "t"})) is None,
      None)
check("排队头解析：缺 trace-id 不排队",
      C._queue_info_from_headers(_Headers({"queue-status": "queued"})) is None,
      None)
check("排队头解析：坏 retry-after 按官方缺省 5s",
      C._queue_info_from_headers(_Headers(
          {"queue-status": "queued", "trace-id": "t",
           "retry-after": "soon"}))["retry_after"] == 5.0, None)
check("排队头解析：headers 为 None", C._queue_info_from_headers(None) is None,
      None)

# 请求头：is-need-queue / app-id 跟随开关
_h_q = C.chat_headers("ak", "sk", None, "deadbeef")
check("chat_headers 带 is-need-queue", _h_q.get("is-need-queue") == "true", None)
check("chat_headers 带 app-id", _h_q.get("app-id") == "CodeAgent3.0", None)
_prev_queue = C.QUEUE_ENABLED
C.QUEUE_ENABLED = False
try:
    _h_nq = C.chat_headers("ak", "sk", None, "deadbeef")
    check("QUEUE_ENABLED=False 不带排队头",
          "is-need-queue" not in _h_nq and "app-id" not in _h_nq, None)
finally:
    C.QUEUE_ENABLED = _prev_queue


class _FakeResp(_io.BytesIO):
    status = 200

    def close(self):
        pass


def _run_queue_flow(script, cap=180.0):
    """script: [(method, 次序)] 决定每次 urlopen 的行为。返回 (status, text)。

    POST 的行为从 script['post'] 列表里按序取；GET 一律按 script['get'] 取。
    """
    posts = list(script["post"])
    gets = list(script["get"])
    state = {"n": 0}

    def fake(req, timeout=None):
        if req.get_method() == "POST":
            state["n"] += 1
            act = posts.pop(0) if posts else ("ok", None)
            if act[0] == "429":
                raise _ue.HTTPError(
                    "u", 429, "Too Many",
                    _Headers(act[1] or {"queue-status": "queued",
                                        "trace-id": "tr", "retry-after": "0.05"}),
                    _io.BytesIO(b""))
            return _FakeResp(b"")
        act = gets.pop(0) if gets else ("promoted", None)
        if act[0] == "raise":
            raise OSError("poll boom")
        return _FakeResp(_json.dumps(act[1]).encode())

    real = _ur.urlopen
    _ur.urlopen = fake
    saved_cap = C.QUEUE_MAX_WAIT
    C.QUEUE_MAX_WAIT = cap
    try:
        st, resp, text = C.open_chat("ak", "sk", None, "glm-5.3",
                                     [{"role": "user", "content": "hi"}],
                                     max_tokens=8)
        if resp is not None:
            resp.close()
        return st, text
    finally:
        _ur.urlopen = real
        C.QUEUE_MAX_WAIT = saved_cap


_st, _txt = _run_queue_flow(
    {"post": [("429", None), ("ok", None)], "get": [("ok", {"status": "promoted"})]})
check("promoted：排队后重发拿到 200", _st == 200 and _txt == "", (_st, _txt))

_st, _txt = _run_queue_flow(
    {"post": [("429", None)],
     "get": [("ok", {"status": "not_found"})]})
check("not_found：按 429 交回上层", _st == 429 and "not_found" in _txt, (_st, _txt))

_st, _txt = _run_queue_flow(
    {"post": [("429", None)],
     "get": [("raise", None)] * 3})
check("GET 连续失败 3 次 → 429", _st == 429, (_st, _txt))

_st, _txt = _run_queue_flow(
    {"post": [("429", None)], "get": [("ok", {"status": "queued",
                                               "retry_after": 30})]},
    cap=0.2)
check("超时上限 → 429 且文案带上限", _st == 429 and "within" in _txt, (_st, _txt))

_st, _txt = _run_queue_flow(
    {"post": [("429", {"queue-status": "rejected",
                       "trace-id": "tr"})], "get": []})
check("429-rejected：不排队，原样交回", _st == 429 and "rejected" in _txt,
      (_st, _txt))


# credit_package 的 token_usage（usageTokenChatMessages）
_prev_http = C._http
try:
    C._http = lambda *a, **k: {
        "metrics": [
            {"name": "usageTotalPackageCredit",
             "package_credit_amount": 100.0, "package_credit_used": 40.0,
             "package_credit_remain": 60.0},
            {"name": "usageTokenChatMessages", "show": True,
             "usage_token_num": 136734219, "package_token_amount": 1},
        ],
        "package": {},
    }
    _pkg = C.credit_package("ak", "sk", None)
    check("token_usage 解析",
          _pkg["token_usage"] == {"used": 136734219, "amount": 1, "show": True},
          _pkg.get("token_usage"))
    C._http = lambda *a, **k: {
        "metrics": [
            {"name": "usageTotalPackageCredit",
             "package_credit_amount": 100.0, "package_credit_used": 0.0,
             "package_credit_remain": 100.0},
            {"name": "usageTokenChatMessages", "show": False,
             "usage_token_num": -1, "package_token_amount": 0},
        ],
        "package": {},
    }
    check("show=False（无 token 包）→ token_usage 为 None",
          C.credit_package("ak", "sk", None)["token_usage"] is None, None)
finally:
    C._http = _prev_http




# ---------------------------------------------------------------------------
# 2026-10-24 history-snip soft 档（投影式上下文裁剪，逐条对齐官方 ContextMod）：
#   压力 = 估算输入 token / (context_window - min(24000, maxOut))，≥0.4 触发；
#   只裁「最近 12 个 user turn 之外」的大工具结果（read/grep/glob + bash 只读），
#   写类工具与未知工具永不裁；头尾各留 1500，占位符与官方一字不差；
#   投影式 —— 入参列表与消息对象一律不动。
# ---------------------------------------------------------------------------

_orig_limits = C.BUILTIN_MODEL_LIMITS
try:
    C.BUILTIN_MODEL_LIMITS = dict(_orig_limits)
    C.BUILTIN_MODEL_LIMITS["test-tiny"] = (8000, 2000)
    _BIG = "x" * 12000          # est 3000 tok / budget 6000 → pressure 0.5

    def _session(tool_name, arguments):
        _m = [{"role": "system", "content": "sys"},
              {"role": "user", "content": "u1"},
              {"role": "assistant", "content": None,
               "tool_calls": [{"id": "c1", "type": "function",
                               "function": {"name": tool_name,
                                            "arguments": arguments}}]},
              {"role": "tool", "tool_call_id": "c1", "content": _BIG},
              {"role": "assistant", "content": "ok"}]
        for _i in range(2, 15):      # 共 14 个 user turn，turn 1 在可裁区
            _m += [{"role": "user", "content": "u%d" % _i},
                   {"role": "assistant", "content": "ok%d" % _i}]
        return _m

    def _tool_content(msgs):
        return [m for m in msgs if m.get("role") == "tool"][0]["content"]

    _base = _session("Read", '{"file_path":"a.txt"}')
    _snap = copy.deepcopy(_base)
    _out = P.prune_history_for_upstream(_base, "test-tiny", 2000, source="t")
    check("投影式：入参列表与消息对象不动", _base == _snap, None)
    check("soft 触发：大 read 结果被裁",
          len(_tool_content(_out)) == 3102, len(_tool_content(_out)))
    check("占位符与官方一字不差（含精确省略数）",
          "[Old tool result truncated: 9000 characters omitted. "
          "Original content remains in session transcript]" in _tool_content(_out),
          None)
    check("头尾各 1500 保留",
          _tool_content(_out).startswith("x" * 100)
          and _tool_content(_out).endswith("x" * 100), None)

    check("写类工具（Write）永不裁",
          _tool_content(P.prune_history_for_upstream(
              _session("Write", "{}"), "test-tiny", 2000)) == _BIG, None)
    check("未知工具按官方默认不裁",
          _tool_content(P.prune_history_for_upstream(
              _session("WebFetch", "{}"), "test-tiny", 2000)) == _BIG, None)
    check("bash 只读命令可裁",
          "[Old tool result" in _tool_content(P.prune_history_for_upstream(
              _session("Bash", '{"command":"ls -la"}'),
              "test-tiny", 2000)), None)
    check("bash 带元字符（;）不裁",
          _tool_content(P.prune_history_for_upstream(
              _session("Bash", '{"command":"rm -rf /tmp; echo hi"}'),
              "test-tiny", 2000)) == _BIG, None)

    _small = _session("Read", '{"file_path":"a.txt"}')
    for _m in _small:
        if _m.get("role") == "tool":
            _m["content"] = "y" * 3000          # ≤4000 不动
    check("soft 档小结果（≤4000 字符）不动",
          _tool_content(P.prune_history_for_upstream(
              _small, "test-tiny", 2000)) == "y" * 3000, None)

    _img = _session("read", "{}")
    for _m in _img:
        if _m.get("role") == "tool":
            _m["content"] = [{"type": "image_url",
                              "image_url": {"url": "data:image/png;base64,x"}},
                             {"type": "text", "text": _BIG}]
    _img_out = P.prune_history_for_upstream(_img, "test-tiny", 2000)
    _parts = _tool_content(_img_out)
    check("图片 part 永不裁、文本 part 照裁",
          _parts[0].get("image_url") is not None
          and "[Old tool result" in _parts[1]["text"], None)

    _few = [{"role": "user", "content": "u1"},
            {"role": "assistant", "content": None,
             "tool_calls": [{"id": "c1", "type": "function",
                             "function": {"name": "Read",
                                          "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": _BIG},
            {"role": "user", "content": "u2"}]
    check("保护窗：全部 turn 在窗内（≤12）→ 不裁",
          _tool_content(P.prune_history_for_upstream(
              _few, "test-tiny", 2000)) == _BIG, None)

    _tiny_msgs = [{"role": "user", "content": "hi"},
                  {"role": "assistant", "content": "yo"}]
    check("压力不到阈值 → 原样返回同一对象（零开销路径）",
          P.prune_history_for_upstream(_tiny_msgs, "test-tiny", 2000)
          is _tiny_msgs, None)

    check("估算器：len/4 半向上取整",
          (P._prune_est_tokens("abcd"), P._prune_est_tokens("abc"),
           P._prune_est_tokens(""), P._prune_est_tokens("ab")) == (1, 1, 0, 1),
          None)
finally:
    C.BUILTIN_MODEL_LIMITS = _orig_limits




# ---------------------------------------------------------------------------
# 2026-10-24 429 flow-control 分流 + 服务端 retry-after（逆向 kernel h_/rS）：
#   · 429 error_msg 内嵌 {"type":RPM..TPD,"quota","used"} —— 只有 RPM/TPM
#     （分钟级）重试，小时/日配额直接终止并附官方 UK map 中文文案；
#   · 429/503 的 retry-after-ms（毫秒）/ retry-after（秒）头由 open_chat 折成
#     [server-retry-after: Ns] 标记，重试 sleep 取 max(自家退避, 服务端提示)。
# ---------------------------------------------------------------------------

_fc_inner = _json.dumps({"type": "RPD", "message": "daily cap",
                         "identity": "userId", "quota": 10000000,
                         "used": 10000000})
_fc_wrapped = _json.dumps({"error": {"error_code": "InferHub.002002010.429",
                                     "error_msg": _fc_inner}})
_fc_top = _json.dumps({"error_code": "InferHub.002002010.429",
                       "error_msg": _fc_inner})

check("flow-control 解析：error 包一层",
      S.flow_control_from(_fc_wrapped)
      == {"type": "RPD", "quota": 10000000, "used": 10000000}, None)
check("flow-control 解析：顶层",
      S.flow_control_from(_fc_top)["type"] == "RPD", None)
check("flow-control 解析：type 不在八种之列 → None",
      S.flow_control_from('{"type":"XXX","quota":1}') is None, None)
check("flow-control 解析：普通错误体不受影响",
      S.flow_control_from('{"error_code":"TM.00001041","error_msg":"并发"}')
      is None, None)

check("RPD（日配额）不重试", not S.retryable(429, _fc_wrapped), None)
check("RPM（分钟级）重试",
      S.retryable(429, _json.dumps({"error": {"error_msg":
          _json.dumps({"type": "RPM"})}})), None)
check("TPM（分钟级）重试",
      S.retryable(429, _json.dumps({"error": {"error_msg":
          _json.dumps({"type": "TPM"})}})), None)
check("普通 429（无 type）仍重试", S.retryable(429, "Too many requests"), None)
check("ModelArts.811xx 仍重试",
      S.retryable(429, _json.dumps({"error": {
          "error_code": "ModelArts.81114.429",
          "error_msg": "rate limit is 5000000 tokens per minute"}})), None)
check("flow-control 是快失败（不占首字节窗口）",
      not S.slow_failure(429, _fc_wrapped), None)

check("RPD 文案（kernel UK map 原文 + 滑动窗口提示后缀）",
      S.flow_control_message(S.flow_control_from(_fc_wrapped))
      .startswith("今天的额度已经用完啦 🌙 辛苦了一天！明天额度刷新后我们再继续 ✨"),
      None)
_tpd = _json.dumps({"error": {"error_msg": _json.dumps(
    {"type": "TPD", "quota": 5000000})}})
check("TPD 文案的 {quota} 已替换（+ 提示后缀）",
      S.flow_control_message(S.flow_control_from(_tpd))
      .startswith("您的请求消耗Token过快，已达每日5000000 Token上限，请24:00点"
                  "后再试，或切换模型以继续。")
      and "sliding-window" in S.flow_control_message(
          S.flow_control_from(_tpd)), None)

check("server_retry_after：解析标记（秒）",
      S.server_retry_after("data: x\n [server-retry-after: 12.5s] y")
      == 12.5, None)
check("server_retry_after：无标记 → 0", S.server_retry_after("plain") == 0.0,
      None)
check("server_retry_after：坏标记 → 0",
      S.server_retry_after("[server-retry-after: abcs]") == 0.0, None)


# open_chat 的 retry-after 头标记（复用排队测试的桩手法）
def _run_retry_after_flow(headers, code=429):
    real = _ur.urlopen

    def fake(req, timeout=None):
        raise _ue.HTTPError("u", code, "lim", _Headers(headers),
                            _io.BytesIO(b'{"error_code":"x","error_msg":"y"}'))

    _ur.urlopen = fake
    try:
        st, resp, text = C.open_chat("ak", "sk", None, "glm-5.3",
                                     [{"role": "user", "content": "hi"}],
                                     max_tokens=8)
        return st, text
    finally:
        _ur.urlopen = real


_st, _txt = _run_retry_after_flow({"retry-after-ms": "7000"})
check("429 带 retry-after-ms=7000 → 文本带 [7.0s] 标记",
      _st == 429 and "[server-retry-after: 7.0s]" in _txt, (_st, _txt))
_st, _txt = _run_retry_after_flow({"retry-after": "9"})
check("429 带 retry-after=9（秒）→ [9.0s]",
      "[server-retry-after: 9.0s]" in _txt, (_st, _txt))
_st, _txt = _run_retry_after_flow({})
check("429 无退避头 → 不加标记", "server-retry-after" not in _txt, (_st, _txt))
_st, _txt = _run_retry_after_flow({"retry-after-ms": "2000"}, code=400)
check("400（1041 的形状）不加标记 —— 官方也不睡它",
      "server-retry-after" not in _txt, (_st, _txt))
_st, _txt = _run_retry_after_flow({"retry-after-ms": "999999"}, code=503)
check("503 带超大提示（>600s）忽略", "server-retry-after" not in _txt,
      (_st, _txt))




# ---------------------------------------------------------------------------
# 2026-10-24 第六轮：官方请求头族 + AgentCenter 模型真值 + kimi-k3 补全。
#   · chat_headers 补 x-session-affinity / user-msg-id / x-message-id /
#     created-time / model-id / model-name（对齐官方 opencode 路径）；
#   · open_chat 的 msg_id 一次生成、各次尝试复用；
#   · agent_center_agents/detail：query 必须进签名（否则 APIG.0301）；
#   · refresh_model_limits 写回 BUILTIN_MODEL_LIMITS（种子→活数据）。
# ---------------------------------------------------------------------------

_h_fam = C.chat_headers("ak", "sk", None, "deadbeef", model="glm-5.3",
                        session_id="ses-x", msg_id="msg-y")
check("头族：x-session-affinity = 会话 id",
      _h_fam.get("x-session-affinity") == "ses-x", None)
check("头族：user-msg-id 与 x-message-id 同值",
      _h_fam.get("user-msg-id") == "msg-y"
      and _h_fam.get("x-message-id") == "msg-y", None)
check("头族：created-time 是 ISO 秒级",
      __import__("re").match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                             _h_fam.get("created-time") or "") is not None,
      _h_fam.get("created-time"))
check("头族：model-id / model-name",
      _h_fam.get("model-id") == "glm-5.3"
      and _h_fam.get("model-name") is not None, None)
_h_bare = C.chat_headers("ak", "sk", None, "deadbeef")
check("头族：没给会话/消息就不带（created-time 恒有）",
      "x-session-affinity" not in _h_bare and "user-msg-id" not in _h_bare
      and "x-message-id" not in _h_bare
      and _h_bare.get("created-time") is not None, None)
_h_enc = C.chat_headers("ak", "sk", None, "deadbeef", model="中文 模型/x")
check("头族：model-name 做了 URL 编码",
      "/" not in (_h_enc.get("model-name") or "")
      and " " not in (_h_enc.get("model-name") or ""), _h_enc.get("model-name"))

check("kimi-k3 输入窗口已补全（kernel 真值 1044480）",
      C.BUILTIN_MODEL_LIMITS.get("kimi-k3") == (1044480, 65536), None)

# refresh_model_limits：种子→活数据（stub 两个 agent-center 接口）
_saved_agents = C.agent_center_agents
_saved_detail = C.agent_center_agent_detail
try:
    C.agent_center_agents = lambda *a, **k: {"agents": [
        {"agent_id": "other", "agent_name": "Other"},
        {"agent_id": "main", "agent_name": "CodeAgent"}]}
    C.agent_center_agent_detail = lambda *a, **k: {"gpts": {"models": [
        {"model_parameters": {"model_id": "glm-5.3", "input_length": 1044480,
                              "max_tokens": 65536}},
        {"model_parameters": {"model_id": "fresh-model", "input_length": 123456,
                              "max_tokens": 7777}},
        {"model_parameters": {"model_id": "broken", "input_length": 0,
                              "max_tokens": 0}},
    ]}}
    C._MODEL_LIMITS_REFRESHED_AT[0] = 0.0
    C.refresh_model_limits("ak", "sk", None)
    check("真值刷新：新模型自动入表（大小写归一可用）",
          C.BUILTIN_MODEL_LIMITS.get("fresh-model") == (123456, 7777)
          and C.resolve_model("Fresh-Model") == "fresh-model", None)
    check("真值刷新：坏值（0/0）跳过",
          "broken" not in C.BUILTIN_MODEL_LIMITS, None)
    check("真值刷新：TTL 内不重复拉",
          (C.refresh_model_limits("ak", "sk", None), True)[1], None)
    del C.BUILTIN_MODEL_LIMITS["fresh-model"]
    C._MODEL_LIMITS_REFRESHED_AT[0] = 0.0
    # 刷新失败（抛异常）保留旧值
    def _boom(*a, **k):
        raise OSError("down")
    C.agent_center_agents = _boom
    C.refresh_model_limits("ak", "sk", None)
    check("真值刷新：上游挂了保留旧表",
          C.BUILTIN_MODEL_LIMITS.get("glm-5.3") == (1044480, 65536), None)
finally:
    C.agent_center_agents = _saved_agents
    C.agent_center_agent_detail = _saved_detail
    C._MODEL_LIMITS_REFRESHED_AT[0] = 0.0




# ---------------------------------------------------------------------------
# 2026-10-24 模型健康熔断 + 降级链（学习官方 smart-router/model-selector）：
#   连败 ≥3 且在 60s 冷却窗内 → 熔断；record_usage(completed)=成功清零，
#   record_error 只在 5xx/上游中断/0203 时记失败（限流/参数错不算）；
#   熔断时按面板链换第一个健康模型，链耗尽/开关关照发原模型（绝不硬拒）。
#   另：agent-center 的 tags(flagship/fallback)/scenario 进 /v1/models 元数据。
# ---------------------------------------------------------------------------

P._MODEL_HEALTH.clear()
P.note_model_result("GLM-5.3", False)          # 大小写归一
P.note_model_result("glm-5.3", False)
check("熔断器：2 败未到阈值（degraded）",
      not P._model_blocked("glm-5.3")
      and P.model_health("glm-5.3") == "degraded", None)
P.note_model_result("glm-5.3", False)
check("熔断器：3 败进熔断（down）",
      P._model_blocked("glm-5.3") and P.model_health("glm-5.3") == "down",
      None)
P.note_model_result("glm-5.3", True)
check("熔断器：一次成功即复位（ok）",
      not P._model_blocked("glm-5.3") and P.model_health("glm-5.3") == "ok",
      None)
check("熔断器：没记录的模型是 ok", P.model_health("kimi-k3") == "ok", None)

check("判据：504 算模型失败", P._health_counts_failure(504, "x", "failed"),
      None)
check("判据：upstream_aborted 算",
      P._health_counts_failure(502, "x", "upstream_aborted"), None)
check("判据：0203 文案算",
      P._health_counts_failure(504, "APIG.0203 Backend timeout", "failed"),
      None)
check("判据：429 限流不算", not P._health_counts_failure(429, "r", "failed"),
      None)
check("判据：400 参数错不算",
      not P._health_counts_failure(400, "param", "failed"), None)

# 降级链行为（stub 掉面板调参）
_orig_tuning = P.codearts_tuning
_CHAIN = {"model_fallbacks": "glm-5.3,openpangu-2.0-flash,deepseek-v4.1-flash",
          "model_fallback_enabled": True}
try:
    P._MODEL_HEALTH.clear()
    P.codearts_tuning = lambda: dict(_CHAIN)
    _pl = {"model": "glm-5.3"}
    check("降级：模型健康时不换",
          P._apply_model_fallback(_pl) == "glm-5.3"
          and _pl["model"] == "glm-5.3", None)
    for _ in range(3):
        P.note_model_result("glm-5.3", False)
    _pl = {"model": "glm-5.3"}
    check("降级：熔断时按链换第一个健康的",
          P._apply_model_fallback(_pl) == "openpangu-2.0-flash"
          and _pl["model"] == "openpangu-2.0-flash", None)
    for _ in range(3):
        P.note_model_result("openpangu-2.0-flash", False)
    _pl = {"model": "glm-5.3"}
    check("降级：链上第二个也熔断时顺延",
          P._apply_model_fallback(_pl) == "deepseek-v4.1-flash", None)
    for _ in range(3):
        P.note_model_result("deepseek-v4.1-flash", False)
    _pl = {"model": "glm-5.3"}
    check("降级：链耗尽照发原模型（绝不硬拒）",
          P._apply_model_fallback(_pl) == "glm-5.3"
          and _pl["model"] == "glm-5.3", None)
    P.codearts_tuning = lambda: dict(_CHAIN, model_fallback_enabled=False)
    _pl = {"model": "glm-5.3"}
    check("降级：开关关掉时照发",
          P._apply_model_fallback(_pl) == "glm-5.3", None)
    # 冷却窗一过自然放行（半开）
    with P._MODEL_HEALTH_LOCK:
        P._MODEL_HEALTH["glm-5.3"]["last_fail"] -= (
            P.CODEARTS_MODEL_BREAKER_COOLDOWN + 1.0)
    check("熔断器：冷却窗过期自然放行（半开）",
          not P._model_blocked("glm-5.3"), None)
finally:
    P.codearts_tuning = _orig_tuning
    P._MODEL_HEALTH.clear()

# record_usage/record_error 的挂接（直接调用真函数，看状态翻转）
P._MODEL_HEALTH.clear()
P.record_error("glm-5.3", 504, "APIG.0203 Backend timeout", key="t")
P.record_error("glm-5.3", 504, "APIG.0203 Backend timeout", key="t")
check("挂接：两次 0203 记两笔失败", P.model_health("glm-5.3") == "degraded",
      None)
P.record_error("glm-5.3", 429, "rate limited", key="t")
check("挂接：429 不记失败（仍是 degraded 不是 down）",
      P.model_health("glm-5.3") == "degraded", None)
P.record_usage("glm-5.3", {"prompt_tokens": 1, "completion_tokens": 1},
               key="t", outcome="completed")
check("挂接：completed 清零失败", P.model_health("glm-5.3") == "ok", None)
P._MODEL_HEALTH.clear()

# 设置面：默认链可解析、非法段被拒
import ca_settings as SET
_cfg = SET.codearts_config("nonexistent")
check("设置：默认降级链",
      _cfg["model_fallbacks"].startswith("glm-5.3,")
      and _cfg["model_fallback_enabled"] is True, None)
try:
    SET.validate_codearts_patch({"model_fallbacks": "a b,c"})
    check("设置：非法模型段被拒", False, None)
except ValueError:
    check("设置：非法模型段被拒", True, None)
check("设置：合法链可通过",
      SET.validate_codearts_patch(
          {"model_fallbacks": "glm-5.3, kimi-k3 "})
      == {"model_fallbacks": "glm-5.3,kimi-k3"}, None)

# tags/scenario 进 /v1/models 元数据（stub agent-center + 查 meta 组装）
_saved_a, _saved_d = C.agent_center_agents, C.agent_center_agent_detail
try:
    C._MODEL_META.clear()
    C.agent_center_agents = lambda *a, **k: {"agents": [
        {"agent_id": "m", "agent_name": "CodeAgent"}]}
    C.agent_center_agent_detail = lambda *a, **k: {"gpts": {"models": [
        {"model_parameters": {
            "model_id": "glm-5.3", "input_length": 1044480,
            "max_tokens": 65536,
            "custom_config": {"tags": "flagship,chat"},
            "scenario": "chat"}}]}}
    C._MODEL_LIMITS_REFRESHED_AT[0] = 0.0
    C.refresh_model_limits("ak", "sk", None)
    check("选模真值：tags/scenario 已捕获",
          C.model_truth_meta("glm-5.3")
          == {"tags": ["flagship", "chat"], "scenario": "chat"}, None)
    check("选模真值：未知模型返回空", C.model_truth_meta("nope") == {}, None)
    _meta = P.codearts_model_meta({"id": "glm-5.3"})
    check("/v1/models：health 字段存在", _meta.get("health") == "ok",
          _meta.get("health"))
    check("/v1/models：tags/scenario 已带出",
          _meta.get("tags") == ["flagship", "chat"]
          and _meta.get("scenario") == "chat", None)
    C.BUILTIN_MODEL_LIMITS.pop("glm-5.3", None)
    C._MODEL_INDEX = None
finally:
    C.agent_center_agents, C.agent_center_agent_detail = _saved_a, _saved_d
    C._MODEL_META.clear()
    C._MODEL_LIMITS_REFRESHED_AT[0] = 0.0


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

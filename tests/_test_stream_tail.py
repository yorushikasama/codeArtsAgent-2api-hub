"""流式收尾语义的回归测试（ca_stream + 三个协议入口）。

2026-10-23 线上问题：**上游先吐正文、再塞一个错误帧**，网关把半截回答当
正常结束发给客户端，账上记一条 ``completed``：

    HTTP 200 + finish_reason=stop + [DONE]，没有 error 帧，
    usage.jsonl 只有一条 completed。

三条入口各有各的漏法：

  · Chat：收尾分支只写了「一个字都没出就报错」（``frame_err and not
    content_parts and not reasoning_parts``），出过内容时错误帧没有分支接住，
    直接落到 ``finish_reason or "stop"`` + ``record_usage(completed)``。
  · Responses / Messages：``tap`` 只把错误记进 sink 就照常喂给翻译器，翻译器
    不知道这件事，补了 ``response.completed`` / ``message_stop``；收尾处还是
    ``if tap["error"] and not usage`` —— 上游只要回过 usage，失败就记成成功，
    而且失败/成功各落一行。
  · 聚合路径（非流式）：同样的 ``if frame_err and not content and ...``，
    拼出来的残句被当成完整答案回 200。

这里钉住的是**语义**，不是实现：

1. ``tail_kind`` 的三态与优先级：错误永远压过完成；
2. ``frame_error`` 认得两种错误形状（``error_code`` / ``{"error": …}``）；
3. ``finish_reason=error`` 也算失败；
4. ``tap_lines`` 遇到错误帧必须打断翻译器（抛 ``UpstreamErrorFrame``）；
5. 三个入口在「出过内容 + 错误帧」时都发各自的错误终态、都不补正常结束、
   都只落一行失败账；
6. ``ca_stream`` 保持纯层：只 import json，不碰 socket / 日志 / 账号目录。

不联网。
"""

import io
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C        # noqa: E402
import ca_protocol as Q        # noqa: E402
import ca_proxy as P           # noqa: E402
import ca_stream as S          # noqa: E402

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


# ---------------------------------------------------------------------------
# 1. 纯层：帧解析与收尾判定
# ---------------------------------------------------------------------------

section("1. ca_stream 的帧解析与收尾判定")

check("错误帧：error_code 形状",
      S.frame_error({"error_code": "ModelArts.81101", "error_msg": "TPM limit"})
      == "ModelArts.81101 TPM limit",
      S.frame_error({"error_code": "ModelArts.81101",
                     "error_msg": "TPM limit"}))
check("错误帧：OpenAI 的 {\"error\": {...}} 形状也认",
      S.frame_error({"error": {"code": "rate_limit_exceeded",
                               "message": "slow down"}})
      == "rate_limit_exceeded slow down", None)
check("错误帧：只有 message 的裸 error 对象",
      S.frame_error({"error": {"message": "boom"}}) == "boom", None)
check("普通帧不算错误", S.frame_error({"choices": [{"delta": {}}]}) == "", None)
check("坏输入不炸", S.frame_error(None) == "" and S.frame_error("x") == "", None)

check("finish_reason=error 算失败",
      S.finish_error({"finish_reason": "error"}) is True, None)
check("finish_reason=ERROR（大写）也算",
      S.finish_error({"finish_reason": "ERROR"}) is True, None)
check("正常的 finish_reason 不算失败",
      not any(S.finish_error({"finish_reason": r})
              for r in ("stop", "length", "tool_calls", None)), None)

check("没有错误也没有断流 → complete",
      S.tail_kind() == S.COMPLETE, S.tail_kind())
check("错误帧 → error_frame", S.tail_kind(frame_err="X 1") == S.ERROR_FRAME, None)
check("断流 → upstream_aborted",
      S.tail_kind(truncated="closed") == S.UPSTREAM_ABORTED, None)
check("错误帧压过断流（两个都有时算错误帧）",
      S.tail_kind(frame_err="X 1", truncated="closed") == S.ERROR_FRAME, None)


# ---------------------------------------------------------------------------
# 2. 聚合路径：出过内容 + 错误帧，不许拼成「完整回答」
# ---------------------------------------------------------------------------

section("2. collect_sse：错误帧与正文共存")

_text = _frame({"choices": [{"delta": {"content": "前半段"}}]})
_err = _frame({"error_code": "ModelArts.81101", "error_msg": "TPM limit"})
_tail = _frame({"choices": [{"delta": {"content": "后半段"},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 4}})

_c, _r, _u, _e, _tc = S.collect_sse(_text + _err + _tail)
check("错误帧被抽出来", "ModelArts.81101" in _e, _e)
check("聚合仍然收下全部正文（调用方拿到错误码就会丢弃残句，"
      "聚合层不替它决定截到哪）",
      _c == "前半段后半段", _c)
check("错误帧后面的 usage 仍然收下（记账要用）",
      _u.get("prompt_tokens") == 9, _u)

_c2, _r2, _u2, _e2, _tc2 = S.collect_sse(_text + _tail)
check("没有错误帧时正常聚合",
      _c2 == "前半段后半段" and _e2 == "" and _u2.get("prompt_tokens") == 9,
      (_c2, _e2))

_c3 = S.collect_sse(_frame({"choices": [{"delta": {"content": "甲"}}]})
                    + _frame({"choices": [{"delta": {},
                                           "finish_reason": "error"}]}))[0]
check("finish_reason=error 不被当成正常结尾",
      S.collect_sse(_text + _frame({"choices": [{"delta": {},
                                                 "finish_reason": "error"}]}))[3]
      != "", None)


# ---------------------------------------------------------------------------
# 3. tap_lines：错误帧必须打断翻译器
# ---------------------------------------------------------------------------

section("3. tap_lines 遇到错误帧要打断翻译器")

_sink = {}
_taken = []
try:
    for _line in S.tap_lines([_text.encode("utf-8"), _err.encode("utf-8"),
                              _tail.encode("utf-8")], _sink):
        _taken.append(_line)
    check("错误帧应当抛 UpstreamErrorFrame", False, _taken)
except S.UpstreamErrorFrame as _exc:
    check("错误帧抛 UpstreamErrorFrame", True)
    check("异常带上上游的错误说明", "ModelArts.81101" in _exc.message, _exc.message)
    check("错误之前的行照常交给翻译器", len(_taken) == 1, _taken)
    check("sink 里也留了一份错误（调用方兜底用）",
          "ModelArts.81101" in _sink.get("error", ""), _sink)

_sink2 = {}
_taken2 = list(S.tap_lines([_text.encode("utf-8"), _tail.encode("utf-8")], _sink2))
check("没有错误帧时全部透传", len(_taken2) == 2, _taken2)
check("usage 记进 sink",
      _sink2.get("usage", {}).get("prompt_tokens") == 9, _sink2)
check("没有错误时 sink 不写 error 键（调用方的 tap.get('error') 兜底判断"
      "才不会被一个空串误触发）",
      "error" not in _sink2, _sink2)


# ---------------------------------------------------------------------------
# 4. 三个入口：出过内容后再来错误帧
# ---------------------------------------------------------------------------

section("4. Chat 流式：出过内容后的错误帧")


class _Handler(P.Handler):
    def __init__(self, path="/v1/chat/completions"):
        self.path = path
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

    def _error(self, code, message, err_type=None):
        self.status = code
        self.payload = {"error": {"message": message, "type": err_type}}
        return code, self.payload

    def _anthropic_error(self, code, message, err_type=None):
        return self._error(code, message, err_type)

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

    def __init__(self, lines):
        self._lines = list(lines)
        self.started_at = time.time()
        self.closed = False

    def lines(self, _abort_check=None, _stats=None):
        for line in self._lines:
            yield line

    def byte_lines(self, _abort_check=None, _stats=None):
        for line in self._lines:
            yield line.encode("utf-8")

    def close(self):
        self.closed = True


def _run_chat(lines):
    h = _Handler()
    h._codearts_open_lease = lambda *_a, **_k: (None, _Lease(lines))
    h._handle_codearts_chat_stream({
        "model": "glm-5.3", "stream": True,
        "messages": [{"role": "user", "content": "hi"}]})
    return h, h.wfile.getvalue().decode("utf-8")


_rows = []
_orig_error, _orig_usage = P.record_error, P.record_usage


def _spy_error(*args, **kwargs):
    _rows.append(("error", args[1] if len(args) > 1 else kwargs.get("status"),
                  kwargs.get("outcome"), kwargs.get("usage")))


def _spy_usage(*args, **kwargs):
    _rows.append(("usage", None, kwargs.get("outcome"), None))


P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_chat([_text, _err])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage

check("已经发过 200（首帧之后才发现错误）", _h.status == 200, _h.status)
check("已经吐出的正文仍在客户端手里", "前半段" in _sse, _sse[-200:])
check("**不再补 finish_reason=stop**",
      '"finish_reason": "stop"' not in _sse, _sse[-300:])
check("发的是明确的 error 帧", '"error"' in _sse, _sse[-300:])
check("错误帧带上游原因",
      "ModelArts.81101" in _sse, _sse[-300:])
check("错误帧的 code 走映射表（81101 → 429 限流语义）",
      '"code": 429' in _sse, _sse[-300:])
check("仍以 [DONE] 收尾（客户端要知道流结束了）",
      _sse.endswith("data: [DONE]\n\n"), _sse[-40:])
check("只落一行账，不是 completed",
      len(_rows) == 1 and _rows[0][0] == "error"
      and _rows[0][2] == "upstream_aborted", _rows)
check("失败行带上已收到的 usage", _rows and _rows[0][3] == {}, _rows)

# 出过内容 + finish_reason=error（不用错误帧的表达方式）
_fin_err = _frame({"choices": [{"delta": {},
                                "finish_reason": "error"}]})
_rows = []
P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_chat([_text, _fin_err])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage
check("finish_reason=error 同样按失败收尾",
      '"error"' in _sse and '"finish_reason": "stop"' not in _sse, _sse[-300:])
check("finish_reason=error 不记成 completed",
      _rows and _rows[0][0] == "error", _rows)

# 首帧就是错误帧：头还没发出去，仍回真状态码
_rows = []
P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_chat([_err])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage
check("首帧即错误帧仍回 429（不是 200 + 空流）", _h.status == 429, _h.status)
check("首帧即错误帧不写 SSE", _sse == "", _sse[:120])


# ---------------------------------------------------------------------------
# 5. Responses 入口
# ---------------------------------------------------------------------------

section("5. Responses 流式：错误帧发 response.failed")


def _run_responses(lines):
    h = _Handler("/v1/responses")
    h._codearts_open_lease = lambda *_a, **_k: (None, _Lease(lines))
    h._responses_codearts({"model": "glm-5.3", "stream": True,
                           "messages": [{"role": "user", "content": "hi"}]},
                          True, set(), {"tools": []}, None)
    return h, h.wfile.getvalue().decode("utf-8")


_rows = []
P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_responses([_text, _err])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage
check("错误帧之后发 response.failed", "response.failed" in _sse, _sse[-400:])
check("**不再发 response.completed**",
      "response.completed" not in _sse, _sse[-400:])
check("错误原因写进 failed 事件",
      "ModelArts.81101" in _sse, _sse[-400:])
check("responses 只落一行失败账",
      len(_rows) == 1 and _rows[0][0] == "error"
      and _rows[0][2] == "upstream_aborted", _rows)
check("responses 不再同一次请求既失败又成功",
      not [r for r in _rows if r[2] == "completed"], _rows)

# 正常流不能被这套收尾影响
_rows = []
P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_responses([_text, _tail])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage
check("正常流照常 response.completed",
      "response.completed" in _sse and "response.failed" not in _sse,
      _sse[-300:])
check("正常流记一条 completed",
      len(_rows) == 1 and _rows[0][2] == "completed", _rows)


# ---------------------------------------------------------------------------
# 6. Messages 入口
# ---------------------------------------------------------------------------

section("6. Messages 流式：错误帧发 event: error")


def _run_messages(lines):
    h = _Handler("/v1/messages")
    h._codearts_open_lease = lambda *_a, **_k: (None, _Lease(lines))
    h._messages_codearts_stream(
        {"model": "glm-5.3", "stream": True,
         "messages": [{"role": "user", "content": "hi"}]},
        lambda code, msg, _t=None: h._error(code, msg))
    return h, h.wfile.getvalue().decode("utf-8")


_rows = []
P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_messages([_text, _err])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage
check("错误帧之后发 event: error", "event: error" in _sse, _sse[-400:])
check("**不再补 message_stop**", "message_stop" not in _sse, _sse[-400:])
check("messages 只落一行失败账",
      len(_rows) == 1 and _rows[0][0] == "error"
      and _rows[0][2] == "upstream_aborted", _rows)

_rows = []
P.record_error, P.record_usage = _spy_error, _spy_usage
try:
    _h, _sse = _run_messages([_text, _tail])
finally:
    P.record_error, P.record_usage = _orig_error, _orig_usage
check("正常流照常 message_stop",
      "message_stop" in _sse and "event: error" not in _sse, _sse[-300:])
check("正常流记一条 completed",
      len(_rows) == 1 and _rows[0][2] == "completed", _rows)


# ---------------------------------------------------------------------------
# 7. 纯层约束与「只有一张映射表」
# ---------------------------------------------------------------------------

section("7. 分层与单一事实来源")

_src = io.open(S.__file__, encoding="utf-8").read()
_imports = set(__import__("re").findall(r"^(?:import|from)\s+([\w.]+)", _src,
                                        __import__("re").M))
check("ca_stream 只依赖标准库 json（纯函数层）",
      _imports <= {"json"}, sorted(_imports))
check("ca_stream 不碰 socket / 日志 / 账号目录",
      "import socket" not in _src and "self.wfile" not in _src
      and "logging" not in _src and "ACCOUNTS_DIR" not in _src, None)

_proxy_src = io.open(P.__file__, encoding="utf-8").read()
check("状态码映射与收尾判定只剩 ca_stream 一份",
      "def _codearts_fail_spec" not in _proxy_src
      and "def _codearts_frame_status" not in _proxy_src
      and "def _collect_codearts_sse" not in _proxy_src
      and "def _codearts_break_hint" not in _proxy_src, None)
check("ca_proxy 确实在用 ca_stream",
      "ca_stream.frame_status(" in _proxy_src
      and "ca_stream.tap_lines(" in _proxy_src, None)
check("收尾分支不再有「出过内容就不管错误帧」的条件",
      "if frame_err and not content_parts and not reasoning_parts" not in _proxy_src,
      None)
check("聚合路径同样不再按正文长度放过错误帧",
      "if frame_err and not content and not reasoning" not in _proxy_src, None)

# symtable：新增模块也不能有「用了但没定义」的全局名
import builtins as _builtins  # noqa: E402
import symtable as _symtable  # noqa: E402


def _undefined_globals(path, allow=("__file__", "__name__")):
    st = _symtable.symtable(io.open(path, encoding="utf-8").read(), path, "exec")
    mod = {s.get_name() for s in st.get_symbols()
           if s.is_assigned() or s.is_imported() or s.is_namespace()}
    bad = []

    def walk(table):
        for sym in table.get_symbols():
            name = sym.get_name()
            if (sym.is_global() and name not in mod and name not in allow
                    and not hasattr(_builtins, name)):
                bad.append((table.get_name(), name))
        for child in table.get_children():
            walk(child)

    walk(st)
    return bad


check("ca_stream 没有悬空全局名", not _undefined_globals(S.__file__),
      _undefined_globals(S.__file__))
check("ca_proxy 搬家后仍然干净", not _undefined_globals(P.__file__),
      _undefined_globals(P.__file__))

print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

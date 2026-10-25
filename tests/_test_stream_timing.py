"""流式落账的三个字段：ttft_ms / gen_ms / effort（面板三列的数据源）。

2026-10-26 回归：面板「最近请求」里流式+完成的行，耗时列有值，但
推理强度 / 首字 / 速度 三列永远是「—」。三个根因同源 —— record_usage
早就有这三个参数、面板也早就按行字段渲染（66-panel-core.js 读
r.reasoning_effort / r.ttft_ms / r.tokens_per_sec），但所有调用点一个都没传：

1. 首字：没有任何调用点传 ttft_ms → 行里恒 null。首帧下发时刻就在流式
   循环里（headers_sent 置位处），只是没人记。
2. 速度：tokens_per_sec 由 record_usage 用 gen_ms 派生（gen_ms > 0 才算），
   gen_ms 同样没人传 → 派生永不触发。
3. 推理强度：真正发给上游的档位在 _codearts_extra 的产物里
   （reasoning_effort 键），以前算完就扔，从没落到行上。

钉住三件事：三条流式入口（chat / responses / messages）的完成行都带
ttft_ms / gen_ms / effort；档位解析与 thinking_extra_from 同源（白名单外 /
none / 没给 → 行上不写）；真实 record_usage 落行时按 gen_ms 派生
tokens_per_sec（速度 = completion_tokens ÷ gen_ms）。
不联网。
"""

import io
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接运行也要隔离数据目录：本套件会触发真实的 record_usage 落行。经 run_all
# 跑时有沙箱；单独 `python tests/_test_stream_timing.py` 调试时没有，stub 行会
# 漏进真实 usage.jsonl（与 _test_codearts_stream_break.py 同一道防线）。
import atexit as _atexit
import shutil as _shutil
_iso_dir = tempfile.mkdtemp(prefix="wb-iso-%s-" % os.path.basename(__file__)[:-3])
os.environ["WB_PROXY_USAGE_DIR"] = _iso_dir
_atexit.register(lambda: _shutil.rmtree(_iso_dir, ignore_errors=True))

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
# 公共夹具：假 handler / 假 lease / record_usage 侦探
# ---------------------------------------------------------------------------

class _Handler(P.Handler):
    """只够流式方法跑完的最小 handler（wfile 进内存）。"""

    def __init__(self, path="/v1/chat/completions"):
        self.path = path
        self.wfile = io.BytesIO()
        self.status = None

    def _client_disconnected(self):
        return False

    def _json(self, code, obj):
        self.status = code
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
    """假租约：按脚本吐行，可选在最后一条前停顿（撑开 gen_ms）。

    ``extra`` 模拟真实租约上「建连成功那一轮实际发出的 extra」——
    effort 就是从这里取的。``broken=True`` 时立刻抛 UpstreamBroken
    （一帧未发就断，触发换号重开）。
    """

    account_label = "stub-label"
    account_key = "stub-key"

    def __init__(self, lines, extra=None, pause_before_last=0.0, broken=False):
        self._lines = list(lines)
        self._extra = extra
        self._pause = pause_before_last
        self._broken = broken
        self.started_at = time.time()
        self.closed = False

    @property
    def extra(self):
        return self._extra

    def lines(self, _abort_check=None, _stats=None):
        if self._broken:
            raise C.UpstreamBroken("upstream closed early", 0)
        total = len(self._lines)
        for i, line in enumerate(self._lines):
            if self._pause and i == total - 1:
                time.sleep(self._pause)
            yield line

    def byte_lines(self, _abort_check=None, _stats=None):
        for line in self.lines(_abort_check, _stats):
            yield line.encode("utf-8")

    def close_upstream(self):
        self.closed = True

    def release_slot(self):
        pass

    def close(self):
        self.closed = True


# 上游形状：正文 delta → 带用量的收尾 delta → [DONE]。
_tail_usage = ('data: {"choices":[{"delta":{},"finish_reason":"stop"}],'
               '"usage":{"prompt_tokens":11,"completion_tokens":23,'
               '"total_tokens":34}}\n\n')
_UPSTREAM = [
    'data: {"choices":[{"delta":{"content":"你"}}]}\n\n',
    'data: {"choices":[{"delta":{"content":"好"}}]}\n\n',
    _tail_usage,
    "data: [DONE]\n\n",
]
_EXTRA = {"reasoning_effort": "high", "user_prompt": "hi"}

_usage_calls = []
_orig_record_usage = P.record_usage


def _spy_record_usage(*args, **kwargs):
    _usage_calls.append(kwargs)
    return None


P.record_usage = _spy_record_usage

_PAYLOAD = {"model": "glm-5.3", "stream": True,
            "messages": [{"role": "user", "content": "hi"}]}


# ---------------------------------------------------------------------------
section("1. chat 流式：完成行带 ttft_ms / gen_ms / effort")

_h = _Handler()
_h._codearts_open_lease = lambda *_a, **_k: (
    None, _Lease(_UPSTREAM, extra=_EXTRA, pause_before_last=0.03))
_h._handle_codearts_chat_stream(dict(_PAYLOAD))
_check = _usage_calls[-1] if _usage_calls else {}
check("完成路径恰好落一条 completed", len(_usage_calls) == 1
      and _check.get("outcome") == "completed", _usage_calls)
check("ttft_ms 有值且为整数毫秒",
      isinstance(_check.get("ttft_ms"), int) and _check["ttft_ms"] >= 0,
      _check.get("ttft_ms"))
check("gen_ms 有值（末帧 − 首帧，这里 ≥ 停顿的 30ms）",
      isinstance(_check.get("gen_ms"), int) and _check["gen_ms"] >= 25,
      _check.get("gen_ms"))
check("ttft + gen = 耗时（gen 用 elapsed − ttft 收口）",
      _check.get("ttft_ms") is not None
      and _check["ttft_ms"] + _check["gen_ms"] == _check.get("elapsed_ms"),
      (_check.get("ttft_ms"), _check.get("gen_ms"), _check.get("elapsed_ms")))
check("effort 取自租约 extra 里真正发出的档位",
      _check.get("effort") == "high", _check.get("effort"))
check("给客户端的 SSE 完整收尾",
      _h.wfile.getvalue().decode("utf-8").endswith("data: [DONE]\n\n"))

# 断流重开：第一轮一帧未发就断，第二轮成功 —— ttft 必须从第二轮首帧算起，
# 不能因为「第一轮没发过帧」就整个丢掉。
_usage_calls.clear()
_h = _Handler()
_leases = [_Lease([], extra=_EXTRA, broken=True), _Lease(_UPSTREAM, extra=_EXTRA)]
_h._codearts_open_lease = lambda *_a, **_k: (None, _leases.pop(0))
_h._handle_codearts_chat_stream(dict(_PAYLOAD))
_check = _usage_calls[-1] if _usage_calls else {}
check("重开成功后 ttft/gen 照落（取成功那轮的首帧）",
      len(_usage_calls) == 1 and _check.get("outcome") == "completed"
      and isinstance(_check.get("ttft_ms"), int)
      and isinstance(_check.get("gen_ms"), int), _check)
check("重开成功后 effort 照落", _check.get("effort") == "high", _check)


# ---------------------------------------------------------------------------
section("2. 档位解析：与 thinking_extra_from 同源，没真发就不写")

_eff = P._sent_reasoning_effort
check("extra 带 reasoning_effort → 原样取回",
      _eff({"reasoning_effort": "high", "user_prompt": "x"}) == "high")
check("extra 为空 / 非法 → None",
      _eff({}) is None and _eff(None) is None and _eff("high") is None)
check("空串档位 → None（不写空键）", _eff({"reasoning_effort": ""}) is None)

# 端到端：客户端请求 → thinking_extra_from 产物 → 行上的档位。
check("reasoning_effort=high 直接透传为档位",
      _eff(C.thinking_extra_from({"reasoning_effort": "high"})) == "high")
check("camelCase reasoningEffort 同样解析",
      _eff(C.thinking_extra_from({"reasoningEffort": "low"})) == "low")
check("没给档位 → None（行上不写，面板显示「—」）",
      _eff(C.thinking_extra_from({})) is None)
check("effort=none → None（上游跑默认档，不能谎报 none）",
      _eff(C.thinking_extra_from({"reasoning_effort": "none"})) is None)
check("白名单外的档位被丢 → None（glm-5.3 空白名单防深思考）",
      _eff(C.thinking_extra_from({"reasoning_effort": "max"},
                                 effort_allowed=())) is None)
check("白名单内的档位保留",
      _eff(C.thinking_extra_from({"reasoning_effort": "high"},
                                 effort_allowed=("high", "medium"))) == "high")

# Anthropic 桥的 thinking budget 映射（round5 那张表）接到行上：
# 桥先把 thinking 折算成 chat 请求的 reasoning_effort（ca_protocol），再走
# 同一个 thinking_extra_from。disabled 折算成 "none"，而 none 不发上游 ——
# 行上因此也不写（上游实际跑默认档）。
for budget, expect in ((9000, "medium"), (16000, "high"), (32000, "xhigh")):
    anthropic_payload = {"thinking": {"type": "enabled",
                                      "budget_tokens": budget}}
    effort = P.ca_protocol.anthropic_effort_from_messages(anthropic_payload)
    check("thinking budget %d → %s（桥折算）" % (budget, expect),
          effort == expect, effort)
    check("thinking budget %d 折算的档位落到行上" % budget,
          _eff(C.thinking_extra_from({"reasoning_effort": effort})) == expect)
_none_effort = P.ca_protocol.anthropic_effort_from_messages(
    {"thinking": {"type": "disabled"}})
check("disabled 折算成 none、行上不写（上游不支持关思考）",
      _none_effort == "none"
      and _eff(C.thinking_extra_from({"reasoning_effort": _none_effort})) is None)


# ---------------------------------------------------------------------------
section("3. 真实 record_usage 落行：tokens_per_sec 按 gen_ms 派生")

# 换回真的 record_usage 落一行，再读回 JSONL 验证（侦探只在流式用例用）。
P.record_usage = _orig_record_usage
try:
    _row = P.record_usage("glm-5.3",
                          {"prompt_tokens": 11, "completion_tokens": 23,
                           "total_tokens": 34},
                          stream=True, elapsed_ms=4790, ttft_ms=800,
                          gen_ms=3990, effort="medium", key="test-key")
    check("行带 ttft_ms / gen_ms", _row["ttft_ms"] == 800
          and _row["gen_ms"] == 3990,
          (_row.get("ttft_ms"), _row.get("gen_ms")))
    check("速度列的数据源：completion ÷ (gen_ms/1000)",
          _row["tokens_per_sec"] == round(23 / 3.990, 2),
          _row.get("tokens_per_sec"))
    check("推理强度落在 reasoning_effort 键（面板读的就是它）",
          _row["reasoning_effort"] == "medium", _row.get("reasoning_effort"))
    _last = open(os.path.join(_iso_dir, "usage.jsonl"),
                 encoding="utf-8").readlines()[-1].strip()
    check("行确实进了 usage.jsonl",
          _last == json.dumps(_row, ensure_ascii=False), _last[:120])

    # 没有档位的请求（客户端没给 / 模型没有思考控制）：行上不写这个键，
    # 与旧行无法区分也不必区分 —— 面板对两种情况都显示「—」。
    _row2 = P.record_usage("glm-5.3",
                           {"prompt_tokens": 1, "completion_tokens": 1,
                            "total_tokens": 2},
                           stream=True, elapsed_ms=100, ttft_ms=10, gen_ms=90,
                           key="test-key")
    check("没传 effort 的行不带 reasoning_effort 键",
          "reasoning_effort" not in _row2, _row2.get("reasoning_effort"))
finally:
    P.record_usage = _spy_record_usage


# ---------------------------------------------------------------------------
section("4. Responses 桥流式：完成行同样带 ttft_ms / gen_ms / effort")

_usage_calls.clear()
_h = _Handler(path="/v1/responses")
_h._codearts_open_lease = lambda *_a, **_k: (
    None, _Lease(_UPSTREAM, extra=_EXTRA, pause_before_last=0.03))
_h._responses_codearts_stream(dict(_PAYLOAD), set(), {"tools": []}, None)
_check = _usage_calls[-1] if _usage_calls else {}
check("responses 完成路径落一条 completed",
      len(_usage_calls) == 1 and _check.get("outcome") == "completed",
      _usage_calls)
check("responses 行带 ttft_ms / gen_ms",
      isinstance(_check.get("ttft_ms"), int)
      and isinstance(_check.get("gen_ms"), int) and _check["gen_ms"] >= 25,
      (_check.get("ttft_ms"), _check.get("gen_ms")))
check("responses 行带 effort", _check.get("effort") == "high",
      _check.get("effort"))
check("responses 给客户端发的是 response.completed 终态",
      "response.completed" in _h.wfile.getvalue().decode("utf-8"),
      _h.wfile.getvalue().decode("utf-8")[-200:])


# ---------------------------------------------------------------------------
section("5. Messages 桥流式：完成行同样带 ttft_ms / gen_ms / effort")

_usage_calls.clear()
_h = _Handler(path="/v1/messages")
_h._codearts_open_lease = lambda *_a, **_k: (
    None, _Lease(_UPSTREAM, extra=_EXTRA, pause_before_last=0.03))
_h._messages_codearts_stream(
    dict(_PAYLOAD), lambda code, msg, _t=None: _h._json(code, {"error": msg}))
_check = _usage_calls[-1] if _usage_calls else {}
check("messages 完成路径落一条 completed",
      len(_usage_calls) == 1 and _check.get("outcome") == "completed",
      _usage_calls)
check("messages 行带 ttft_ms / gen_ms",
      isinstance(_check.get("ttft_ms"), int)
      and isinstance(_check.get("gen_ms"), int) and _check["gen_ms"] >= 25,
      (_check.get("ttft_ms"), _check.get("gen_ms")))
check("messages 行带 effort", _check.get("effort") == "high",
      _check.get("effort"))
_sse = _h.wfile.getvalue().decode("utf-8")
check("messages 给客户端发完整收尾（message_stop + 没有 error 事件）",
      "message_stop" in _sse and "event: error" not in _sse, _sse[-200:])


# ---------------------------------------------------------------------------
P.record_usage = _orig_record_usage

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

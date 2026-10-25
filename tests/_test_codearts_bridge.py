# -*- coding: utf-8 -*-
"""码道协议桥接：Responses / Messages 两条桥、角色归一、思考参数透传、max_tokens 夹紧、工具调用透传与聚合

不联网。2026-10-24 自 _test_codearts.py 按域拆出；共享夹具在
_codearts_fixtures.py。跑法：python tests/_test_codearts_bridge.py
"""
import calendar
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolated_dirs import isolated_data_dirs  # noqa: E402
isolated_data_dirs("wb-codearts-codearts-bridge-")

import ca_proxy as P  # noqa: E402
import ca_stream as S2  # noqa: E402
from ca_proxy import Handler  # noqa: E402
import ca_codearts as C  # noqa: E402

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
# /v1/responses：码道没有原生 Responses 端点，网关用翻译层桥接
# ---------------------------------------------------------------------------
#
# 逆向本地 CodeArts 客户端（vscode-codebot/out/extension.js）确认：它只发
# chat/completions 形状，没有 /v1/responses、previous_response_id 或 Responses
# 流事件。所以网关必须自己把 Responses 请求翻成 chat，再把码道的 SSE 还原成
# Responses 的 JSON / 事件流。这里钉住桥接的两条出口。

print()
print("== 码道 Responses 桥接 ==")


class _FakeResponsesHandler(P.Handler):
    def __init__(self):
        self.path = "/v1/responses"
        self.wfile = io.BytesIO()
        self.status = None
        self.payload = None

    def _client_disconnected(self):
        # 桩没有真实 socket；基类实现读 self.connection 会抛 AttributeError，
        # 被当成「客户端已断开」，码道链路于是在第一次尝试前就退出。
        return False

    def _json(self, code, obj):
        self.status = code
        self.payload = obj
        return code, obj

    def send_response(self, code):
        self.status = code

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass

    def _key_id(self):
        return "test-key"

    def _anthropic_error(self, code, message, err_type=None):
        self.status = code
        self.payload = {"type": "error",
                        "error": {"type": err_type or "api_error",
                                  "message": message}}
        return code, self.payload


_CHAT_RAW = (
    'data: {"choices":[{"delta":{"content":"你"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"好"},"finish_reason":"stop"}]}\n\n'
    "data: [DONE]\n\n"
)


def _stub_codearts(payload, want_stream=None, error_factory=None, anthropic=False):
    return None, {
        "model": payload.get("model"),
        "content": "你好",
        "reasoning": "",
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        "raw": _CHAT_RAW,
        "want_stream": bool(want_stream),
    }


class _StubLease:
    """测试替身：把一段现成 SSE 文本伪装成「实时行流」。

    2026-10-22 起真流式走 ca_codearts.open_chat + iter_sse，不再经过
    _codearts_chat_result，所以流式用例必须在这个新接缝上打桩，否则会真的
    去连上游（一次跑三分钟，看着像挂死）。
    """

    account_label = "stub"

    def __init__(self, text):
        self._text = text
        self.started_at = __import__("time").time()

    def lines(self, abort_check=None):
        for line in self._text.splitlines(keepends=True):
            yield line

    def byte_lines(self, abort_check=None, stats=None):
        # 签名要与真租约一致：线上调用会带一个 stats 字典回来填断流归因
        # （silent_s / bytes / pings），这里只接住、不填。
        for line in self.lines(abort_check):
            yield line.encode("utf-8")

    def close(self):
        pass


def _stub_open_lease(payload, model, messages, max_tokens, fail=None,
                     anthropic=False):
    return None, _StubLease(_CHAT_RAW)


# 一个最小的合法回合：单 system / 空列表会被网关在请求阶段拦下。
_USER = {"role": "user", "content": "hi"}

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._responses_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]},
                       False, set(), {"tools": []}, None)
check("非流式回 response 对象",
      isinstance(_h.payload, dict) and _h.payload.get("object") == "response",
      _h.payload)
check("非流式正文进 output_text", _h.payload.get("output_text") == "你好",
      _h.payload)
check("非流式保留 usage",
      (_h.payload.get("usage") or {}).get("input_tokens") == 3, _h.payload)

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._codearts_open_lease = _stub_open_lease
_h._responses_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]},
                       True, set(), {"tools": []}, None)
_sse = _h.wfile.getvalue().decode("utf-8")
check("流式发 Responses 事件（不是 chat.completion.chunk）",
      "response.output_text.delta" in _sse
      and "chat.completion.chunk" not in _sse, _sse[:300])
check("流式事件带 sequence_number", '"sequence_number"' in _sse)
check("流式以 response.completed 收尾",
      "response.completed" in _sse and "你好" in _sse, _sse[-400:])

# 入口分流：码道模型必须在这里就拐走，不能再落到 WorkBuddy 账号池
# （修复前的病灶：/v1/responses 只认 WorkBuddy 的 open_upstream，
# 码道模型在 /v1/models 里看得见，走 Responses 却永远 503）。
_h = _FakeResponsesHandler()
_h.headers = {}
_h.key_entry = None
_h._codearts_chat_result = _stub_codearts
_h._request_realm = lambda explicit=None: "cn"
# 账号池删除后没有「第二套上游」可落：码道模型必须交给码道翻译层，
# 其余名字一律 404。以前这里桩掉 open_upstream 来证明「没落进池子」，
# 现在池子根本不存在，改桩分发点。
_hit = {"codearts": False}
_saved_dispatch = _h._responses_codearts


def _spy_dispatch(*args, **kwargs):
    _hit["codearts"] = True
    return _saved_dispatch(*args, **kwargs)


_h._responses_codearts = _spy_dispatch
_h._handle_responses({"model": "deepseek-v4.1-flash", "input": "hi"})

check("Responses 把码道模型交给码道翻译层", _hit["codearts"], _hit)
check("Responses 入口能返回码道正文",
      (_h.payload or {}).get("output_text") == "你好", _h.payload)

_h404 = _FakeResponsesHandler()
_h404.headers = {}
_h404.key_entry = None
_h404._handle_responses({"model": "no-such-model", "input": "hi"})
check("Responses 对非码道模型回 404",
      _h404.status == 404, (_h404.status, _h404.payload))


# ---------------------------------------------------------------------------
# Anthropic Messages：同一个缺口，开关打开后码道模型也不能掉进空池
# ---------------------------------------------------------------------------

print()
print("== 码道 Messages 桥接 ==")

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._messages_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]}, False)
_msg_blocks = (_h.payload or {}).get("content") or []
check("Messages 非流式回 Anthropic message",
      (_h.payload or {}).get("type") == "message", _h.payload)
check("Messages 非流式正文进 text block",
      any(b.get("type") == "text" and b.get("text") == "你好"
          for b in _msg_blocks), _h.payload)
check("Messages 非流式保留 usage",
      (_h.payload.get("usage") or {}).get("input_tokens") == 3, _h.payload)
check("Messages 非流式回填 model",
      _h.payload.get("model") == "deepseek-v4.1-flash", _h.payload)

# 单 system / 空消息列表：上游回 ModelArts.81001.400，报错点离原因太远，
# 网关在请求阶段就拦下（2026-10-23）。
_SYSTEM_ONLY = {"model": "deepseek-v4.1-flash",
                "messages": [{"role": "system", "content": "you are terse"}]}
_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._responses_codearts(dict(_SYSTEM_ONLY), False, set(), {"tools": []}, None)
check("Responses 只有 system 时回 400，文案点名 81001",
      _h.status == 400 and "81001" in str((_h.payload or {}).get("error", {}).get("message")),
      (_h.status, _h.payload))

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._messages_codearts(dict(_SYSTEM_ONLY), False)
check("Messages 只有 system 时回 Anthropic 信封的 400",
      _h.status == 400
      and (_h.payload or {}).get("type") == "error"
      and (_h.payload or {}).get("error", {}).get("type") == "invalid_request_error",
      (_h.status, _h.payload))

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._codearts_open_lease = _stub_open_lease
_h._messages_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]}, True)
_sse = _h.wfile.getvalue().decode("utf-8")
check("Messages 流式事件齐全",
      "event: message_start" in _sse
      and "text_delta" in _sse
      and "event: message_stop" in _sse, _sse[:400])

_h = _FakeResponsesHandler()
_h.headers = {}
_h.key_entry = None
_h._codearts_chat_result = _stub_codearts
_h._request_realm = lambda explicit=None: "cn"
_hit = {"codearts": False}
_saved_msg_dispatch = _h._messages_codearts


def _spy_msg_dispatch(*args, **kwargs):
    _hit["codearts"] = True
    return _saved_msg_dispatch(*args, **kwargs)


_h._messages_codearts = _spy_msg_dispatch
_h._handle_messages({"model": "deepseek-v4.1-flash",
                     "messages": [{"role": "user", "content": "hi"}],
                     "max_tokens": 16})
check("Messages 把码道模型交给码道翻译层", _hit["codearts"], _hit)
check("Messages 入口能返回码道正文",
      any(b.get("type") == "text" and b.get("text") == "你好"
          for b in (_h.payload or {}).get("content") or []), _h.payload)

_h404 = _FakeResponsesHandler()
_h404.headers = {}
_h404.key_entry = None
_h404._handle_messages({"model": "no-such-model",
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 16})
check("Messages 对非码道模型回 404",
      _h404.status == 404, (_h404.status, _h404.payload))


# ---------------------------------------------------------------------------
print()
print("== _error 必须返回哨兵（不回 None） ==")
#
# 2026-10-21 线上事故：_error 发完响应隐式返回 None，而调用方靠
# `if error is not None` 判「是否已回过响应」。于是每条失败请求在回完 502
# 之后又被当成成功继续走 result["model"]，日志里留下一段
# TypeError: 'NoneType' object is not subscriptable，真实错误被埋掉。

_h2 = _FakeResponsesHandler()
_h2.headers = {}
_h2._handle_expect_continue = lambda: None
_h2._discard_body = lambda: None
_r = P.Handler._error(_h2, 502, "boom", "upstream_error")
check("_error 回的不是 None", _r is not None, repr(_r))
check("_error 回的是 RESPONDED", _r is P.RESPONDED, repr(_r))
_r2 = P.Handler._anthropic_error(_h2, 400, "nope", "invalid_request_error")
check("_anthropic_error 回的是 RESPONDED", _r2 is P.RESPONDED, repr(_r2))


def _stub_fail(payload, want_stream=None, error_factory=None):
    """模拟「已回过响应」的形态：返回 (RESPONDED, None)。"""
    return P.RESPONDED, None


_h3 = _FakeResponsesHandler()
_h3._codearts_chat_result = _stub_fail
# 以前这一行会抛 TypeError；现在应安静返回、不碰 result
_out = P.Handler._handle_codearts_chat(
    _h3, {"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}]})
check("已回过响应的路径不再解引用 result",
      _out is P.RESPONDED, repr(_out))


# ---------------------------------------------------------------------------
# 发给码道的消息：角色名归一，正文不动
# ---------------------------------------------------------------------------

print()
print("== 码道链路的角色归一 ==")

_seen = {}


def _fake_chat(ak, sk, tok, model, messages, max_tokens=None, stream=True,
               extra=None, timeout=None, tools=None, tool_choice=None,
               abort_check=None, aborted=None, session_id=None,
               header_timeout=None, idle_timeout=None, session_retry=None):
    # 桩要跟上真实签名：tools / tool_choice（2026-10-21 透传）、
    # abort_check（2026-10-22 客户端断开感知）。漏一个关键字参数就是
    # TypeError，测出来像「角色归一坏了」，其实是桩老了。
    _seen["model"] = model
    _seen["messages"] = messages
    _seen["max_tokens"] = max_tokens
    _seen["stream"] = stream
    _seen["extra"] = extra
    _seen["tools"] = tools
    _seen["tool_choice"] = tool_choice
    _seen["abort_check"] = abort_check
    _seen["session_id"] = session_id
    _seen["session_retry"] = session_retry
    return 200, (
        'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
        'data: {"usage":{"prompt_tokens":1,"completion_tokens":1,'
        '"total_tokens":2}}\n\ndata: [DONE]\n\n')


class _FakePool:
    """测试替身：固定给同一个会话，不碰真实账号目录。

    码道路径每轮都向 _CODEARTS_POOL 要号（多账号负载/故障转移）——
    桩要打在这条接缝上，否则会真读磁盘、拿不到账号就直接 503。
    """

    def __init__(self, sess):
        self.sess = sess
        self.released = 0
        self.penalties = []

    def acquire(self, timeout=None, session_key=None, model=None):
        self.last_session_key = session_key
        self.last_model = model
        return self.sess, "a"

    def remember(self, session_key, key, now=None):
        self.last_remember = (session_key, key)

    def release(self, key):
        self.released += 1

    def penalize(self, key, seconds):
        self.penalties.append((key, seconds))

    def _usable(self):
        return [self.sess]

    def snapshot(self):
        return {"a": {"in_flight": 0, "cooling_s": 0.0}}


_saved_pool = P._CODEARTS_POOL
_saved_chat, _saved_hb = C.chat_for_model, C.heartbeat
_saved_record = P.record_usage
C.heartbeat = lambda *a, **k: (True, "ok")
P._CODEARTS_POOL = _FakePool({
    "accessKey": "AK", "secretKey": "SK", "securitytoken": "TK",
    "account": {"id": "a", "label": "a"},
    "expires_at": "2099-01-01T00:00:00.000Z"})
C.chat_for_model = _fake_chat
P.record_usage = lambda *a, **k: None
try:
    _err, _res = P.Handler._codearts_chat_result(
        _FakeResponsesHandler(),
        {"model": "deepseek-v4.1-flash",
         "messages": [
             {"role": "developer", "content": "you are a coding agent"},
             {"role": "user", "content": [{"type": "text", "text": "yo"}]},
         ]},
        want_stream=False)
finally:
    P._CODEARTS_POOL = _saved_pool
    C.chat_for_model = _saved_chat
    C.heartbeat = _saved_hb
    P.record_usage = _saved_record

_sent = _seen.get("messages") or []
check("developer 角色发出去前归一成 system",
      bool(_sent) and _sent[0].get("role") == "system", _sent)
check("多模态的 content 分片保持原样",
      len(_sent) > 1 and isinstance(_sent[1].get("content"), list), _sent)
check("上游按流式请求（码道只收流式）", _seen.get("stream") is True, _seen)


# ---------------------------------------------------------------------------
print()
print("== 码道路径的思考参数透传 ==")

_mapping = [
    ({}, None, "不带参数 -> 不透传（沿用上游默认）"),
    # 上游不接受关思考（会回 81001 参数错），所以这种请求被丢弃而不是透传。
    ({"thinking": {"type": "disabled"}}, None, "disabled 被丢弃（上游不支持关）"),
    ({"thinking": {"type": "enabled", "budget_tokens": 8192}},
     {"thinking": {"type": "enabled", "budget_tokens": 8192}}, "budget 原样透传"),
    ({"reasoning_effort": "none"}, None, "effort=none 同上，不发"),
    ({"thinking": "disabled"}, None, "字符串 disabled 也丢弃"),
    ({"reasoningEffort": "low"},
     {"thinking": {"type": "enabled"}, "reasoning_effort": "low"}, "camelCase effort"),
]
for payload, expect, label in _mapping:
    got = C.thinking_extra_from(payload)
    check(label, got == expect, "得到 %r，期望 %r" % (got, expect))


def _run_with(payload):
    """跑一次码道聚合，返回 fake 收到的 extra。"""
    _seen.clear()
    saved_chat, saved_rec = C.chat_for_model, P.record_usage
    saved_hb = C.heartbeat
    C.heartbeat = lambda *a, **k: (True, "ok")
    saved_pool = P._CODEARTS_POOL
    P._CODEARTS_POOL = _FakePool({
        "accessKey": "AK", "secretKey": "SK", "securitytoken": "TK",
        "account": {"id": "a", "label": "a"},
        "expires_at": "2099-01-01T00:00:00.000Z"})
    C.chat_for_model = _fake_chat
    P.record_usage = lambda *a, **k: None
    try:
        body = {"model": "glm-5.3",
                "messages": [{"role": "user", "content": "hi"}]}
        body.update(payload)
        P.Handler._codearts_chat_result(_FakeResponsesHandler(), body,
                                        want_stream=False)
        return _seen.get("extra")
    finally:
        P._CODEARTS_POOL = saved_pool
        C.chat_for_model = saved_chat
        C.heartbeat = saved_hb
        P.record_usage = saved_rec


# 模型名归一：大写变体进、上游真名出（统计/限额/降级链共用同一个桶）
_seen.clear()
_run_with({"model": "GLM-5.3", "max_tokens": 100})
check("客户端写 GLM-5.3，打到上游与用量记录的都是 glm-5.3",
      _seen.get("model") == "glm-5.3", _seen.get("model"))
_seen.clear()
_run_with({"model": "totally-unknown-model"})
check("认不出的模型名原样放行（不编近似名）",
      _seen.get("model") == "totally-unknown-model", _seen.get("model"))

check("开思考的请求，extra 传到上游",
      _run_with({"thinking": {"type": "enabled", "budget_tokens": 4096}})
      == {"thinking": {"type": "enabled", "budget_tokens": 4096},
          "user_prompt": "hi"},
      "extra 没传到 chat_for_model")
check("关思考的请求不再发给上游（避免 81001）",
      _run_with({"thinking": {"type": "disabled"}}) == {"user_prompt": "hi"},
      "disabled 不该被透传")
check("没要求时 extra 只剩官方镜像的 user_prompt（2026-10-24 起）",
      _run_with({}) == {"user_prompt": "hi"},
      "默认请求不该带 thinking")


# ---------------------------------------------------------------------------
print()
print("== max_tokens 夹紧（客户端固定发 128000 的回归） ==")
#
# 2026-10-21 线上事故：ZCode 对所有模型固定发 max_tokens=128000，而 glm-5.3 的
# 输出上限是 65536。上游不回「值太大」，而是回
# InferHub.001001005.400 The request param is invalid —— 一句话把整个请求打死，
# 且这个码不在 ca_stream.retryable 里，重试多少次都是同样的 502。
# 现象：用户侧「glm-5.3 一直失败」，而同账号的 GLM-5.2 正常。

# ---------------------------------------------------------------------------
print()
print("== 积分静态兜底（服务重启后 credit 全 0 的回归） ==")
#
# 2026-10-22 线上事故：面板上每条请求的积分都是 0.00。原因是 CREDIT_TIERS 是
# 进程内的运行时状态，只在有人请求模型目录时才被填充 —— 服务重启后、第一次
# 拉 /v1/models 之前，credit_for_usage 查不到档位就返回 None，记录里留着 0。
# 实测：重启后那批请求全 0；手动打一次 /v1/models 再发请求，立刻变成 0.0428。
# 修法是把上游实测到的几档固化进 CREDIT_TIERS_STATIC 作为兜底。

check("静态表覆盖 glm-5.3", "glm-5.3" in C.CREDIT_TIERS_STATIC)
check("静态表的 ratio 与上游一致", 
      C.CREDIT_TIERS_STATIC["glm-5.3"]["ratio"] == 0.0443,
      C.CREDIT_TIERS_STATIC["glm-5.3"]["ratio"])
check("运行时表为空时，积分仍能算出来（不再返回 None）",
      C.credit_for_usage("glm-5.3", 153, 0, 31) is not None,
      C.credit_for_usage("glm-5.3", 153, 0, 31))
_c = C.credit_for_usage("glm-5.3", 13, 0, 64)
check("算出来的量级对（13 入 / 64 出 ≈ 0.04 积分）",
      _c is not None and 0.03 < _c < 0.06, _c)
check("未定价模型仍然返回 None（不编倍率）",
      C.credit_for_usage("Qwen3-VL-235B", 100, 0, 100) is None,
      C.credit_for_usage("Qwen3-VL-235B", 100, 0, 100))
check("openpangu-2.0-pro 仍是两段计价",
      len(C.CREDIT_TIERS_STATIC["openpangu-2.0-pro"]["tiers"]) == 2,
      C.CREDIT_TIERS_STATIC["openpangu-2.0-pro"]["tiers"])
# 运行时表优先：上游调价时不能被静态表盖过
_saved = dict(C.CREDIT_TIERS)
try:
    C.CREDIT_TIERS["glm-5.3"] = {"ratio": 0.5, "tiers": [
        {"input_from": 0, "input_to": -1, "ratio": 0.5,
         "input_price": 100.0, "cache_price": 0.0, "output_price": 0.0}]}
    check("运行时档位优先于静态兜底",
          C.credit_tier_for("glm-5.3")["ratio"] == 0.5,
          C.credit_tier_for("glm-5.3")["ratio"])
finally:
    C.CREDIT_TIERS.clear()
    C.CREDIT_TIERS.update(_saved)

check("128000 被夹到 glm-5.3 的 65536（模型最大输出）",
      C.clamp_max_tokens("glm-5.3", 128000) == (65536, True),
      C.clamp_max_tokens("glm-5.3", 128000))
check("正好等于模型上限的值不动（65536 是能力，不是错值）",
      C.clamp_max_tokens("glm-5.3", 65536) == (65536, False),
      C.clamp_max_tokens("glm-5.3", 65536))
# kimi-k3 的 65536 是实测出来的：65536 → 200，81920 / 100000 / 131072 /
# 262144 → 全是 001001005。没有这条会退化成「ZCode 发 128000 一律 400」。
check("kimi-k3 的 128000 也夹到 65536",
      C.clamp_max_tokens("kimi-k3", 128000) == (65536, True),
      C.clamp_max_tokens("kimi-k3", 128000))
check("kimi-k3 输入窗口 = kernel 真值 1044480（2026-10-24 从官方 kernel 日志补全；"
      "AgentCenter 真值刷新上线后此表会自动跟活数据走）",
      C.BUILTIN_MODEL_LIMITS["kimi-k3"][0] == 1044480,
      C.BUILTIN_MODEL_LIMITS["kimi-k3"])
check("表里没有的模型不夹（别用猜的数改坏本来能过的请求）",
      C.clamp_max_tokens("kimi-k2.6-vl", 128000) == (128000, False),
      C.clamp_max_tokens("kimi-k2.6-vl", 128000))
check("chat_body 里的 max_tokens 已夹到模型上限",
      C.chat_body("glm-5.3", [], max_tokens=128000)["max_tokens"] == 65536,
      C.chat_body("glm-5.3", [], max_tokens=128000))
check("chat_body 对无模型上限的模型保持原值",
      C.chat_body("kimi-k2.6-vl", [], max_tokens=128000)["max_tokens"] == 128000,
      C.chat_body("kimi-k2.6-vl", [], max_tokens=128000))


# ---------------------------------------------------------------------------
print()
print("== 工具调用透传与聚合 ==")
#
# 同一个事故的第二半：chat_body 过去只组 model/messages/max_tokens/stream，
# tools 整个被丢掉。IDE 客户端（ZCode 一次发 39 个工具）于是完全不知道有哪些
# 工具可用，只能把调用写成 `<tool_call>…</tool_call>` 纯文本发回来 ——
# 上游明明原生支持 function calling（会回 delta.tool_calls + finish_reason
# tool_calls），聚合层却只收 content / reasoning_content，把 tool_calls 丢了。

_TOOLS = [{"type": "function", "function": {"name": "get_date",
                                          "description": "d",
                                          "parameters": {"type": "object"}}}]
_body = C.chat_body("glm-5.3", [], max_tokens=256, tools=_TOOLS,
                    tool_choice="auto")
check("chat_body 带上了 tools", _body.get("tools") == _TOOLS, _body)
check("chat_body 带上了 tool_choice", _body.get("tool_choice") == "auto", _body)
check("没有 tools 时不塞空字段",
      "tools" not in C.chat_body("glm-5.3", [], max_tokens=256),
      C.chat_body("glm-5.3", [], max_tokens=256))

# --- 扁平（Responses）形状必须包成码道认的 function 包裹 ---
#
# 线上实测：Responses 入口把 Codex 的扁平声明原样转给码道，上游回
# `InferHub.001001015.400 Tool function cannot empty` —— 它按 tool["function"]
# 取名字，取到空就拒掉整个请求。而 WorkBuddy 上游恰恰要扁平（见
# _test_custom_tools 的 "ordinary function tool untouched"），所以这层转换
# 只能留在码道自己的模块里，不能改通用转换函数。

_FLAT = [{"type": "function", "name": "get_date", "description": "d",
          "parameters": {"type": "object", "properties": {}}, "strict": True}]
_shaped = C.normalize_tools(_FLAT)
check("扁平声明被包进 function",
      _shaped and _shaped[0].get("function", {}).get("name") == "get_date",
      _shaped)
check("name/description/parameters/strict 都搬进去了",
      _shaped and _shaped[0]["function"].get("parameters") == {"type": "object", "properties": {}}
      and _shaped[0]["function"].get("strict") is True, _shaped)
check("已经是包裹形状的不重复包一层",
      C.normalize_tools(_TOOLS) == _TOOLS, C.normalize_tools(_TOOLS))
check("码道没有执行器的声明（custom/web_search）被丢掉",
      C.normalize_tools([{"type": "custom", "name": "apply_patch"},
                         {"type": "web_search"}]) == [],
      C.normalize_tools([{"type": "custom", "name": "apply_patch"},
                         {"type": "web_search"}]))
check("chat_body 里走的就是包裹形状",
      (C.chat_body("glm-5.3", [], max_tokens=256, tools=_FLAT)
       .get("tools") or [{}])[0].get("function", {}).get("name") == "get_date",
      C.chat_body("glm-5.3", [], max_tokens=256, tools=_FLAT).get("tools"))

# 上游真实返回的形状（2026-10-21 线上实测抓的帧）
_SSE_TOOL = (
    'data: {"choices":[{"delta":{"role":"assistant",'
    '"reasoning_content":"let me call it"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"","tool_calls":[{"id":"call_1",'
    '"index":0,"type":"function","function":{"name":"get_date",'
    '"arguments":"{\\"day\\":"}}]}}]}\n\n'
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
    '"function":{"arguments":"3}"}}]}}],"usage":'
    '{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}\n\n'
    'data: [DONE]\n\n'
)
_c, _r, _u, _e, _tc = S2.collect_sse(_SSE_TOOL)
check("tool_calls 被聚合出来", len(_tc) == 1, _tc)
check("工具名正确", _tc and _tc[0]["function"]["name"] == "get_date", _tc)
check("id 正确", _tc and _tc[0]["id"] == "call_1", _tc)
check("分片的 arguments 被拼接",
      _tc and _tc[0]["function"]["arguments"] == '{"day":3}',
      _tc[0]["function"]["arguments"] if _tc else None)
check("usage 照样收到", _u.get("total_tokens") == 15, _u)
check("无 tool 调用时返回空列表", S2.collect_sse(
    'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')[4] == [], "应为空")


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 体验版积分：credit_package 的解析口径
# （接口是 snap-access /snap-manager/v1/statistics/plugin，客户端「总已用积分」
#   那一栏用的同一个；2026-10-21 实测响应结构如下）
print()
print("== 体验版积分解析 ==")

_CREDIT_PAYLOAD = {
    "metrics": [
        {"name": "usageTotalPackageCredit", "package_credit_amount": 11500.0,
         "package_credit_used": 4817.0, "package_credit_remain": 6683.0},
        {"name": "usageBasicPackageCredit", "package_credit_amount": 500.0,
         "package_credit_used": 0.0, "package_credit_remain": 500.0},
        {"name": "usageBonusPackageCredit", "package_credit_amount": 11000.0,
         "package_credit_used": 4817.0, "package_credit_remain": 6183.0},
    ],
    "package": {"package_name_cn": "体验版",
                "spec_code": "codearts.agent.individual.trial", "status": "normal"},
    "start_date": "2026-10-15", "end_date": "2026-11-16",
}

_saved_http = C._http
C._http = lambda *a, **k: dict(_CREDIT_PAYLOAD)
try:
    cp = C.credit_package("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("积分总量", cp["total"] == 11500.0, cp)
check("积分已用", cp["used"] == 4817.0, cp)
check("积分剩余", cp["remaining"] == 6683.0, cp)
check("积分百分比", cp["percent"] == 41.89, cp)
check("积分套餐名", cp["package_name"] == "体验版", cp)
check("积分到期日", cp["end_date"] == "2026-11-16", cp)
check("基础包分项", cp["basic"]["total"] == 500.0, cp["basic"])
check("赠送包分项", cp["bonus"]["used"] == 4817.0, cp["bonus"])

# 没有 usageTotalPackageCredit 时返回 None（不是造一堆 0 出来）
C._http = lambda *a, **k: {"metrics": [], "package": {}}
try:
    none_cp = C.credit_package("AK", "SK", "TOK")
finally:
    C._http = _saved_http
check("没有总量指标时返回 None", none_cp is None, none_cp)

# remain 缺失时用 total - used 兜底
C._http = lambda *a, **k: {
    "metrics": [{"name": "usageTotalPackageCredit",
                 "package_credit_amount": 100.0, "package_credit_used": 30.0}],
    "package": {},
}
try:
    fb = C.credit_package("AK", "SK", "TOK")
finally:
    C._http = _saved_http
check("remain 缺失时按 total-used 兜底", fb["remaining"] == 70.0, fb)

# ---------------------------------------------------------------------------
# 每日签到（活动页「每日签到领 1000 积分」）：/v1/ops 的积分体系
# 响应结构照抄 2026-10-19 本机客户端日志里的 delivery / claim / confirm。
# ---------------------------------------------------------------------------
print()
print("== 每日签到（积分） ==")


def _welfare_delivery(claimed):
    daily = {
        "campaignId": 1, "title": "每日签到领1000积分", "type": "USER_LOGIN",
        "benefitAmount": 1000, "benefitUnit": "CREDIT",
        "status": "CONFIRMED" if claimed else "ELIGIBLE",
        "claimable": not claimed, "description": "每日签到领取1000积分",
    }
    return {
        "channel": "IDE", "serverTime": 1792392647046,
        "items": [
            {"campaignId": 4, "title": "新用户注册送 4000 积分",
             "type": "NEW_USER_REGISTER", "benefitAmount": 4000,
             "benefitUnit": "CREDIT", "status": "CLAIMED", "claimable": False},
            daily,
        ],
    }


_welfare_state = {"claimed": False}
_welfare_calls = []


def _fake_welfare_http(method, url, headers=None, body=None, timeout=None):
    path = urllib.parse.urlsplit(url).path
    _welfare_calls.append({
        "method": method, "url": url, "headers": dict(headers or {}),
        "body": json.loads(body) if body else None,
    })
    if path == C.WELFARE_DELIVERY_PATH:
        return {"code": 0, "message": "ok", "data": _welfare_delivery(_welfare_state["claimed"])}
    if path == C.WELFARE_CLAIM_PATH:
        _welfare_state["claimed"] = True
        return {"code": 0, "message": "ok", "data": {
            "campaignId": 1, "campaignTitle": "每日签到领1000积分",
            "status": "CLAIMED", "totalAmount": 1000,
            "claimedAt": "2026-10-21T01:00:00Z"}}
    if path == C.WELFARE_CONFIRM_PATH:
        return {"code": 0, "message": "ok", "data": {
            "campaignId": 1, "campaignTitle": "每日签到领1000积分",
            "status": "CONFIRMED", "totalAmount": 1000,
            "claimedAt": "2026-10-21T01:00:00Z"}}
    raise AssertionError("unexpected welfare url: " + url)


_saved_http = C._http
C._http = _fake_welfare_http
C._welfare_cache.clear()
try:
    _acts = C.welfare_activities("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("活动清单按 type 找到每日签到", _acts["daily"]["campaign_id"] == 1, _acts["daily"])
check("活动清单保留其它活动", len(_acts["items"]) == 2, len(_acts["items"]))
check("签到金额取 benefitAmount", _acts["daily"]["amount"] == 1000, _acts["daily"])
check("可领状态是 ELIGIBLE", _acts["daily"]["status"] == "ELIGIBLE", _acts["daily"])

_get = _welfare_calls[-1]
check("delivery 是 GET 且带 channel=IDE",
      _get["method"] == "GET" and "channel=IDE" in _get["url"], _get["url"])
check("delivery 带 AK/SK 签名", "Authorization" in _get["headers"], sorted(_get["headers"]))
check("delivery 带 STS 令牌",
      _get["headers"].get("X-Security-Token") == "TOK", sorted(_get["headers"]))

# 领取：claim → confirm → 重新拉清单确认状态
_welfare_state["claimed"] = False
_welfare_calls.clear()
C._http = _fake_welfare_http
C._welfare_cache.clear()
try:
    _claim = C.welfare_claim_daily("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("签到成功", _claim["ok"] is True and _claim["already"] is False, _claim)
check("签到后状态是 CONFIRMED", _claim["status"] == "CONFIRMED", _claim)
check("签到达成后带回刷新过的活动状态",
      _claim["activity"]["status"] == "CONFIRMED", _claim.get("activity"))
check("签到带回 1000 积分", _claim["amount"] == 1000, _claim)

_claim_call = next(c for c in _welfare_calls if c["method"] == "POST"
                   and c["url"].endswith(C.WELFARE_CLAIM_PATH))
check("claim body 带 campaignId", _claim_call["body"]["campaignId"] == 1, _claim_call["body"])
check("claim body 带 channel=IDE", _claim_call["body"]["channel"] == "IDE", _claim_call["body"])
check("幂等键形如 claim_1_<毫秒>",
      _claim_call["body"]["idempotentKey"].startswith("claim_1_"), _claim_call["body"])

_confirm_call = next(c for c in _welfare_calls if c["method"] == "POST"
                     and c["url"].endswith(C.WELFARE_CONFIRM_PATH))
check("领完自动 confirm", _confirm_call["body"] == {"campaignId": 1}, _confirm_call["body"])
check("签到后重新拉了一次清单（不信本地状态）",
      sum(1 for c in _welfare_calls if c["url"].startswith(C.SNAP_HOST + C.WELFARE_DELIVERY_PATH)) == 2,
      len(_welfare_calls))

# 已领过就不要再打 claim / confirm
_welfare_state["claimed"] = True
_welfare_calls.clear()
C._http = _fake_welfare_http
C._welfare_cache.clear()
try:
    _again = C.welfare_claim_daily("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("今日已签到时直接返回 already", _again["ok"] is True and _again["already"] is True, _again)
check("已签到不再发 POST",
      not any(c["method"] == "POST" for c in _welfare_calls), _welfare_calls)

# 业务失败：code 非 0 要抛出来（HTTP 仍是 200）
C._http = lambda *a, **k: {"code": 4000,
                           "message": "invalid channel, group not found",
                           "data": None}
C._welfare_cache.clear()
try:
    _raised = False
    try:
        C.welfare_daily("AK", "SK", "TOK")
    except C.CodeArtsError as exc:
        _raised = True
        check("业务错误带上游 message", "invalid channel" in str(exc), str(exc))
    check("code 非 0 视为失败", _raised)
finally:
    C._http = _saved_http
    C._welfare_cache.clear()


print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

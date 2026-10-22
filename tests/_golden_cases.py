# -*- coding: utf-8 -*-
"""Golden 输入：录制脚本与对拍套件共用这一份，避免两边漂移。

**什么时候重新录**：只有「确认行为变化是想要的」（改逻辑，不是搬家）才跑
``python tests/record_protocol_golden.py``，然后 review 生成的 diff；
其它情况对拍失败就是回归，别改 golden 去迁就代码。

录制与对拍都把 ``new_id`` 和 ``time`` 钉死，所以帧可以逐字节比较。
"""
import contextlib
import itertools
import json
import os

import ca_protocol as Q

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")
ANTHROPIC_GOLDEN = os.path.join(GOLDEN_DIR, "anthropic_stream.json")
RESPONSES_GOLDEN = os.path.join(GOLDEN_DIR, "responses_stream.json")


@contextlib.contextmanager
def deterministic():
    """把随机 id 与时钟钉死。退出时还原，别影响同进程里的其它用例。"""
    real_new, real_time = Q.new_id, Q.time
    counter = itertools.count(1)
    Q.new_id = lambda prefix: "%s%04d" % (prefix, next(counter))

    class _Clock:
        @staticmethod
        def time():
            return 1792691000.0

    Q.time = _Clock
    try:
        yield
    finally:
        Q.new_id, Q.time = real_new, real_time


def _chunk(delta=None, finish=None, **extra):
    body = {"choices": [{"index": 0, "delta": delta or {}}]}
    if finish:
        body["choices"][0]["finish_reason"] = finish
    body.update(extra)
    return body


def _lines(chunks):
    out = [b"data: " + json.dumps(c, ensure_ascii=False).encode("utf-8")
           for c in chunks]
    out.append(b"data: [DONE]")
    return iter(out)


# ---------------------------------------------------------------------------
# Anthropic Messages：同一串 chat delta 应产出同一串 Anthropic 帧
# ---------------------------------------------------------------------------

ANTHROPIC_CASES = [
    {
        "name": "正文 + usage（含缓存命中）",
        "holder": {},
        "chunks": [
            {"id": "chatcmpl-g1", "model": "glm-5.3",
             "choices": [{"delta": {"role": "assistant", "content": "你"}}]},
            {"choices": [{"delta": {"content": "好"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 11, "completion_tokens": 3,
                       "prompt_tokens_details": {"cached_tokens": 7}}},
        ],
    },
    {
        "name": "思考 + 正文",
        "holder": {},
        "chunks": [
            {"choices": [{"delta": {"reasoning_content": "先想"}}]},
            {"choices": [{"delta": {"reasoning_content": "一下"}}]},
            {"choices": [{"delta": {"content": "答案"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 5, "completion_tokens": 4}},
        ],
    },
    {
        "name": "两个工具调用",
        "holder": {},
        "chunks": [
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call_a", "type": "function",
                 "function": {"name": "get_time", "arguments": "{\"tz\""}},
            ]}}]},
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": ": \"UTC\"}"}},
            ]}}]},
            {"choices": [{"delta": {"tool_calls": [
                {"index": 1, "id": "call_b", "type": "function",
                 "function": {"name": "ping", "arguments": "{}"}},
            ]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 9, "completion_tokens": 6}},
        ],
    },
    {
        "name": "max_tokens 收尾",
        "holder": {},
        "chunks": [
            {"choices": [{"delta": {"content": "半截"}}]},
            {"choices": [{"delta": {}, "finish_reason": "length"}],
             "usage": {"prompt_tokens": 3, "completion_tokens": 2}},
        ],
    },
    {
        "name": "空流（只有 [DONE]）",
        "holder": {},
        "chunks": [],
    },
    {
        "name": "上游错误帧",
        "holder": {},
        "chunks": [{"error": {"message": "upstream exploded", "code": "X"}}],
    },
    {
        "name": "stop_sequence 命中（上游回显了停止串）",
        "holder": {"stop_sequences": ["STOP"]},
        "chunks": [
            {"choices": [{"delta": {"content": "结果：STOP"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 4, "completion_tokens": 3}},
        ],
    },
]


def run_anthropic(case):
    holder = dict(case.get("holder") or {})
    frames = Q.stream_messages_events(_lines(case["chunks"]), "glm-5.3", holder)
    return [frame.decode("utf-8") for frame in frames]


# ---------------------------------------------------------------------------
# Responses：事件顺序是 Codex CLI 的硬约束，整段帧序列值得钉死
# ---------------------------------------------------------------------------

_RESPONSES_TOOLS = [
    {"type": "function", "name": "get_time",
     "parameters": {"type": "object", "properties": {"tz": {"type": "string"}}}},
    {"type": "function", "name": "ping", "parameters": {"type": "object"}},
]

RESPONSES_CASES = [
    {
        "name": "正文",
        "base_body": {"model": "glm-5.3", "stream": True,
                      "input": "hi", "tools": _RESPONSES_TOOLS},
        "chunks": [
            {"id": "chatcmpl-r1", "model": "glm-5.3",
             "choices": [{"delta": {"content": "收"}}]},
            {"choices": [{"delta": {"content": "到"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}],
             "usage": {"prompt_tokens": 12, "completion_tokens": 2,
                       "prompt_tokens_details": {"cached_tokens": 5}}},
        ],
    },
    {
        "name": "思考 + max_tokens",
        "base_body": {"model": "glm-5.3", "stream": True, "input": "hi"},
        "chunks": [
            {"choices": [{"delta": {"reasoning_content": "想想"}}]},
            {"choices": [{"delta": {"reasoning_content": "再想想"}}]},
            {"choices": [{"delta": {}, "finish_reason": "length"}],
             "usage": {"prompt_tokens": 6, "completion_tokens": 9,
                       "completion_tokens_details": {"reasoning_tokens": 9}}},
        ],
    },
    {
        "name": "单个工具调用",
        "base_body": {"model": "glm-5.3", "stream": True,
                      "input": "hi", "tools": _RESPONSES_TOOLS},
        "chunks": [
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call_t1", "type": "function",
                 "function": {"name": "get_time", "arguments": "{\"tz\":\"UTC\"}"}},
            ]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 8, "completion_tokens": 5}},
        ],
    },
    {
        "name": "两个工具调用（参数分片）",
        "base_body": {"model": "glm-5.3", "stream": True,
                      "input": "hi", "tools": _RESPONSES_TOOLS},
        "chunks": [
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call_u1", "type": "function",
                 "function": {"name": "get_time", "arguments": "{\"tz\""}},
            ]}}]},
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": ": \"CST\"}"}},
                {"index": 1, "id": "call_u2", "type": "function",
                 "function": {"name": "ping", "arguments": "{}"}},
            ]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 10, "completion_tokens": 7}},
        ],
    },
    {
        "name": "空流",
        "base_body": {"model": "glm-5.3", "stream": True, "input": "hi"},
        "chunks": [],
    },
    {
        "name": "只有工具、没有正文",
        "base_body": {"model": "glm-5.3", "stream": True,
                      "input": "hi", "tools": _RESPONSES_TOOLS},
        "chunks": [
            {"choices": [{"delta": {"tool_calls": [
                {"index": 0, "id": "call_only", "type": "function",
                 "function": {"name": "ping", "arguments": "{}"}},
            ]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}],
             "usage": {"prompt_tokens": 4, "completion_tokens": 2}},
        ],
    },
]


def run_responses(case):
    base_body = dict(case.get("base_body") or {})
    holder = {
        "base_body": base_body,
        "base_messages": base_body.get("messages"),
        "request_meta": {},
        "namespace_map": {},
        "custom_names": set(),
    }
    frames = Q.stream_responses_events(
        _lines(case["chunks"]), "glm-5.3", holder)
    return [frame.decode("utf-8") for frame in frames]


def collect():
    """录/跑都走这里：返回 {协议: [{name, frames}, ...]}。"""
    with deterministic():
        return {
            "anthropic": [{"name": c["name"], "frames": run_anthropic(c)}
                          for c in ANTHROPIC_CASES],
            "responses": [{"name": c["name"], "frames": run_responses(c)}
                          for c in RESPONSES_CASES],
        }

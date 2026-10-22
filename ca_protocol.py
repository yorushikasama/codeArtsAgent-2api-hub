# -*- coding: utf-8 -*-
"""ca_protocol.py - 三种协议之间的**纯函数**转换层（第一刀）

## 为什么要有这个文件

`ca_proxy.py` 已经两万多行，三条协议（OpenAI Chat / Responses / Anthropic
Messages）的转换逻辑和 HTTP handler 搅在一起：函数里读 `self.wfile`、摸
`holder`/`state`，想单测只能起一个真服务器打 socket。这个模块的边界很硬：

    **进参是数据，出参是数据，不碰 socket、不读全局、不写日志。**

## 分层（按顺序往里搬）

1. **帧层**（本文件目前只有这一层）：把事件对象变成 SSE 字节 / 把
   finish_reason 映射成 Anthropic 的 stop_reason。纯格式化，零依赖。
2. **增量层**：一个 chat delta → 若干 Anthropic/Responses 事件。现在散在
   `_messages_codearts_stream` / `_responses_codearts_stream` 里。
3. **请求层**：Anthropic/Responses 请求体 → chat 请求体（`messages_to_chat`
   及其 11 个辅助函数，约 500 行）。这一层最大，要连带 `_anthropic_*` 一族
   一起搬，需单独一轮。

搬的时候只做**移动**，不改逻辑；每搬一层跑一次全量测试当安全网。
"""

import json


def anthropic_sse_frame(event, payload):
    """一个 Anthropic SSE 帧（bytes）：``event: x`` + 单行 data。

    data 用紧凑分隔符（``,`` / ``:``）：SSE 里换行会让帧断开，紧凑 JSON 也
    顺带小一点。``payload`` 里的 ``type`` 会被 ``event`` 覆盖 —— 两者必须
    一致，否则客户端按哪个走都可能。
    """
    body = dict(payload or {})
    body["type"] = event
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return ("event: %s\ndata: %s\n\n" % (event, raw)).encode("utf-8")


def normalize_roles(messages):
    """Map role names the upstream rejects onto ones it accepts.
    WorkBuddy only knows system / user / assistant / tool. OpenAI's newer
    "developer" role (used by the Codex CLI and current SDKs) is the same thing
    as "system", but sending it verbatim fails with code 11128.
    """
    out = []
    for m in messages or []:
        if not isinstance(m, dict):
            out.append(m)
            continue
        item = m
        if m.get("role") == "developer":
            item = dict(m)
            item["role"] = "system"
        out.append(item)
    return out


def strip_empty_function_calls(obj):
    """PATCHED-BY-OPS: 递归剔除空 function_call 占位（Responses/chat 通用）。"""
    changed = False
    if isinstance(obj, dict):
        fc = obj.get("function_call")
        if isinstance(fc, dict) and not fc.get("name"):
            obj.pop("function_call", None)
            changed = True
        tc = obj.get("tool_calls")
        if isinstance(tc, list) and not tc:
            obj.pop("tool_calls", None)
            changed = True
        for v in list(obj.values()):
            if strip_empty_function_calls(v):
                changed = True
    elif isinstance(obj, list):
        for v in obj:
            if strip_empty_function_calls(v):
                changed = True
    return changed
def clean_responses_frame(frame):
    """PATCHED-BY-OPS: 清洗 Responses SSE 帧（bytes）。
    输入 b'event: x\ndata: {...}\n\n'；只改写 data: 行的 JSON，
    event: 行原样保留。解析失败原样返回（不破坏未知格式）。
    """
    if not frame:
        return frame
    try:
        text = frame.decode("utf-8")
    except Exception:
        return frame
    out, changed = [], False
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("data:"):
            payload = st[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    obj = json.loads(payload)
                    if strip_empty_function_calls(obj):
                        line = "data: " + json.dumps(obj, ensure_ascii=False)
                        changed = True
                except Exception:
                    pass
        out.append(line)
    return ("\n".join(out) + "\n\n").encode("utf-8") if changed else frame


def anthropic_stop_reason(finish_reason):
    """chat 的 finish_reason → Anthropic 的 stop_reason。

    没映射就是 end_turn：Anthropic 的枚举只有四个值，把未知值原样透传会让
    SDK 解析失败。
    """
    value = str(finish_reason or "").strip().lower()
    if value == "length":
        return "max_tokens"
    if value in ("tool_calls", "function_call"):
        return "tool_use"
    if value in ("content_filter", "refusal"):
        return "refusal"
    return "end_turn"

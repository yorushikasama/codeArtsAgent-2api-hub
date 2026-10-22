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

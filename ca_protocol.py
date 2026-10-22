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
import uuid


def anthropic_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def best_cached_tokens(usage):
    """Best cache-hit value across every alias the upstreams emit (E3).

    Order mirrors the panel: prompt_tokens_details.cached_tokens >
    prompt_cache_hit_tokens > cache_read_input_tokens > cached_tokens >
    input_tokens_details.cached_tokens > completion_tokens_details.
    First positive value wins; zero aliases never shadow a real hit.
    """
    if not isinstance(usage, dict):
        return 0
    prompt_details = usage.get("prompt_tokens_details") or {}
    input_details = usage.get("input_tokens_details") or {}
    details = usage.get("completion_tokens_details") or {}
    for value in (prompt_details.get("cached_tokens"),
                  usage.get("prompt_cache_hit_tokens"),
                  usage.get("cache_read_input_tokens"),
                  usage.get("cached_tokens"),
                  input_details.get("cached_tokens"),
                  details.get("cached_tokens")):
        try:
            number = float(value or 0)
        except (TypeError, ValueError):
            continue
        if number > 0:
            # Token counts must stay integers: the Codex client parses
            # response.completed strictly and rejects 123.0 (invalid number).
            return int(number)
    return 0


def anthropic_usage(usage):
    out = {
        "input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "output_tokens": 0,
    }
    if not isinstance(usage, dict):
        return out
    try:
        out["input_tokens"] = int(usage.get("prompt_tokens") or 0)
    except (TypeError, ValueError):
        pass
    try:
        out["output_tokens"] = int(usage.get("completion_tokens") or 0)
    except (TypeError, ValueError):
        pass
    cached = usage.get("prompt_cache_hit_tokens")
    if cached is None:
        cached = best_cached_tokens(usage)
    try:
        out["cache_read_input_tokens"] = int(cached or 0)
    except (TypeError, ValueError):
        pass
    try:
        out["cache_creation_input_tokens"] = int(usage.get("prompt_cache_write_tokens") or 0)
    except (TypeError, ValueError):
        pass
    service_tier = usage.get("service_tier")
    if service_tier:
        out["service_tier"] = service_tier
    return out


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


SSE_READ_BLOCK = 64 * 1024

def new_id(prefix):
    return prefix + uuid.uuid4().hex


def anthropic_message_id(value):
    value = anthropic_text(value)
    if not value:
        return new_id("msg_")
    return value if value.startswith("msg_") else "msg_" + value


def anthropic_error_type(status):
    """Map an HTTP status to the Anthropic error.type vocabulary."""
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = 500
    if status in (400, 422):
        return "invalid_request_error"
    if status == 401:
        return "authentication_error"
    if status == 403:
        return "permission_error"
    if status == 404:
        return "not_found_error"
    if status == 429:
        return "rate_limit_error"
    if status in (503, 529):
        return "overloaded_error"
    return "api_error"


def strip_data_prefix(line):
    line = line.strip()
    # SSE comment / heartbeat / keepalive / empty line
    if not line or line.startswith(":"):
        return ""
    while line.startswith("data:"):
        line = line[5:].strip()
    # Handle possible "data: : heartbeat"
    if not line or line.startswith(":"):
        return ""
    return line


def iter_sse_lines(source, block_size=SSE_READ_BLOCK, before_read=None):
    """按块读取流式响应并逐行产出，把逐行 read 的 syscall 开销摊掉。

    直接 `for line in resp` 迭代 http.client.HTTPResponse 时，每一行都要走
    一次 read() syscall，而每次 syscall 都要释放并重新抢回 GIL。一轮流式回复
    动辄几千条事件，于是进程大部分时间花在二十来个 handler 线程之间来回交接
    GIL 上，而不是在干活。4 vCPU 真机实测（v1.7.2，15~20 req/s）：10 秒内
    106 214 次 futex，占全部 syscall 时间的 71%，其中约三分之二来自这条逐行
    读取路径。

    read1() 每次最多一次底层 syscall，所以按块取回来再在内存里切行，能把
    syscall 数降一到两个数量级。延迟不变：read1() 一有字节就返回，完整的行
    立刻产出；只有跨块的那一行需要等下一块。

    产出的行**带换行符**，与直接迭代 response 的形状完全一致，调用方一行都
    不用改。没有 read1 的对象（列表、文本模式的文件……）退回普通迭代。

    `before_read` 在每个**可能阻塞的 read1 之前**调一次，调用方可以在这里把
    攒下的写出掉：一个读取块里的事件因此合成一次 write，而下一个字节一到就
    立刻产出——延迟与逐块写完全一样，只是不再一个 chunk 一次 sendall。
    """
    read1 = getattr(source, "read1", None)
    if read1 is None:
        for line in source:
            if before_read is not None:
                before_read()
            yield line
        return
    buf = b""
    while True:
        if before_read is not None:
            before_read()
        chunk = read1(block_size)
        if not chunk:
            break
        buf += chunk
        if b"\n" not in buf:
            continue
        head, _, buf = buf.rpartition(b"\n")
        for line in head.split(b"\n"):
            yield line + b"\n"
    if buf:
        # 上游没以换行收尾时，最后一行照旧要交出去（迭代 response 也是这个形状）。
        yield buf


def stream_messages_events(raw_iter, model, holder=None):
    """Yield Anthropic Messages SSE frames from a chat-completions SSE stream."""
    holder = holder if isinstance(holder, dict) else {}
    state = {
        "started": False,
        "done": False,
        "failed": False,
        "id": "",
        "model": model,
        "stop": "end_turn",
        "thinking_open": False,
        "thinking_idx": None,
        "text_open": False,
        "text_idx": None,
        "next": 0,
        "tools": {},
        "tool_order": [],
        "usage": None,
    }

    def usage_payload():
        return anthropic_usage(state.get("usage"))

    def ensure_start(chunk=None):
        if state["started"]:
            return None
        state["started"] = True
        if isinstance(chunk, dict):
            state["id"] = anthropic_text(chunk.get("id"))
            state["model"] = anthropic_text(chunk.get("model")) or state["model"]
        return anthropic_sse_frame("message_start", {
            "message": {
                "id": anthropic_message_id(state["id"]),
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": state["model"],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
        })

    def ensure_thinking():
        frames = []
        if not state["thinking_open"]:
            state["thinking_idx"] = state["next"]
            state["next"] += 1
            state["thinking_open"] = True
            frames.append(anthropic_sse_frame("content_block_start", {
                "index": state["thinking_idx"],
                "content_block": {"type": "thinking", "thinking": ""},
            }))
        return frames

    def ensure_text():
        frames = []
        if not state["text_open"]:
            if state["thinking_open"]:
                state["thinking_open"] = False
                frames.append(anthropic_sse_frame(
                    "content_block_stop", {"index": state["thinking_idx"]}))
            state["text_idx"] = state["next"]
            state["next"] += 1
            state["text_open"] = True
            frames.append(anthropic_sse_frame("content_block_start", {
                "index": state["text_idx"],
                "content_block": {"type": "text", "text": ""},
            }))
        return frames

    for line in iter_sse_lines(raw_iter):
        if state["done"] or state["failed"]:
            break
        data = strip_data_prefix(line.decode("utf-8", "replace"))
        if not data:
            continue
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except Exception:
            continue
        if isinstance(chunk.get("error"), dict):
            state["failed"] = True
            err = chunk["error"]
            yield anthropic_sse_frame("error", {
                "error": {
                    "type": anthropic_error_type(502),
                    "message": anthropic_text(err.get("message") or "upstream error"),
                }
            })
            return
        start = ensure_start(chunk)
        if start:
            yield start
        # Capture usage before the choices guard: the final upstream frame
        # carries both the usage block and the finish_reason (and no delta),
        # so skipping it here would zero out every streaming usage row.
        if isinstance(chunk.get("usage"), dict):
            state["usage"] = chunk["usage"]
        choices = chunk.get("choices") if isinstance(chunk.get("choices"), list) else []
        if not choices:
            continue
        choice = choices[0] if isinstance(choices[0], dict) else {}
        delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
        # Upstream thinking trace (deepseek-style reasoning_content) becomes
        # native thinking blocks so the client can display the reasoning.
        reason = delta.get("reasoning_content")
        if isinstance(reason, str) and reason:
            for frame in ensure_thinking():
                yield frame
            yield anthropic_sse_frame("content_block_delta", {
                "index": state["thinking_idx"],
                "delta": {"type": "thinking_delta", "thinking": reason},
            })
        text = delta.get("content")
        if isinstance(text, str) and text:
            for frame in ensure_text():
                yield frame
            yield anthropic_sse_frame("content_block_delta", {
                "index": state["text_idx"],
                "delta": {"type": "text_delta", "text": text},
            })
        for call in delta.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            try:
                idx = int(call.get("index") or 0)
            except (TypeError, ValueError):
                idx = 0
            entry = state["tools"].get(idx)
            if entry is None:
                entry = {"idx": idx, "block": None, "id": "", "name": "", "opened": False}
                state["tools"][idx] = entry
                state["tool_order"].append(idx)
            if call.get("id"):
                entry["id"] = anthropic_text(call.get("id"))
            fn = call.get("function") if isinstance(call.get("function"), dict) else {}
            if fn.get("name"):
                entry["name"] = anthropic_text(fn.get("name"))
            args = fn.get("arguments") if fn.get("arguments") is not None else ""
            if not entry["opened"] and (entry["id"] or entry["name"] or args):
                if state["thinking_open"]:
                    state["thinking_open"] = False
                    yield anthropic_sse_frame("content_block_stop", {"index": state["thinking_idx"]})
                if state["text_open"]:
                    state["text_open"] = False
                    yield anthropic_sse_frame("content_block_stop", {"index": state["text_idx"]})
                entry["opened"] = True
                entry["block"] = state["next"]
                state["next"] += 1
                if not entry["id"]:
                    entry["id"] = "toolu_" + str(idx)
                yield anthropic_sse_frame("content_block_start", {
                    "index": entry["block"],
                    "content_block": {
                        "type": "tool_use",
                        "id": entry["id"],
                        "name": entry["name"],
                        "input": {},
                    },
                })
            if entry["opened"] and args:
                yield anthropic_sse_frame("content_block_delta", {
                    "index": entry["block"],
                    "delta": {"type": "input_json_delta", "partial_json": anthropic_text(args)},
                })
        finish = choice.get("finish_reason")
        if finish:
            state["stop"] = anthropic_stop_reason(finish)
    if state["failed"]:
        return
    if not state["started"]:
        start = ensure_start(None)
        if start:
            yield start
    if state["thinking_open"]:
        state["thinking_open"] = False
        yield anthropic_sse_frame("content_block_stop", {"index": state["thinking_idx"]})
    if state["text_open"]:
        state["text_open"] = False
        yield anthropic_sse_frame("content_block_stop", {"index": state["text_idx"]})
    for idx in state["tool_order"]:
        entry = state["tools"][idx]
        if not entry["opened"]:
            continue
        yield anthropic_sse_frame("content_block_stop", {"index": entry["block"]})
    state["done"] = True
    # Hand the raw upstream usage block back to the caller: the stream
    # response records it on the usage row, and without this every streamed
    # Messages request was logged as usage_missing.
    holder["usage"] = state.get("usage")
    yield anthropic_sse_frame("message_delta", {
        "delta": {"stop_reason": state["stop"], "stop_sequence": None},
        "usage": usage_payload(),
    })
    yield anthropic_sse_frame("message_stop", {})


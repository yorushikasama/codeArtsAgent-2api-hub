# -*- coding: utf-8 -*-
"""ca_protocol.py - 三种协议之间的**纯函数**转换层

## 为什么要有这个文件

`ca_proxy.py` 已经两万多行，三条协议（OpenAI Chat / Responses / Anthropic
Messages）的转换逻辑和 HTTP handler 搅在一起：函数里读 `self.wfile`、摸
`holder`/`state`，想单测只能起一个真服务器打 socket。这个模块的边界很硬：

    **进参是数据，出参是数据，不碰 socket、不读全局、不写日志。**

## 分层（已完成的部分）

1. **帧层**：事件对象 ↔ SSE 字节；finish_reason → Anthropic stop_reason。
2. **增量层**：
   - `stream_messages_events`：chat delta → Anthropic Messages 事件
   - `stream_responses_events`：chat delta → Responses API 事件（含 DSML
     兜底、namespace 还原、网路工具拦截）
3. **请求层**：
   - `messages_to_chat` 一族（11 个函数）：Anthropic 请求 → chat 请求
   - `parse_dsml_tool_calls` / `estimate_tokens` / `build_citations` 等纯工具
4. **传输原语**：`iter_sse_lines` / `strip_data_prefix` / `SSE_READ_BLOCK`

## 唯一的注入点

`stream_responses_events(..., webtools=None)`：网路工具的名字与判定来自
`ca_webtools`，为了不把 I/O 模块拖进来，由调用方（ca_proxy 的包装函数）
注入模块对象。纯函数层本身不 import ca_webtools。

搬的时候只做**移动**，不改逻辑；每搬一层跑一次全量测试当安全网。
"""

import json
import re
import time
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
    """Chat 的 usage → Anthropic 的 usage。

    **``input_tokens`` 不含缓存部分**（2026-10-23）。Anthropic 的语义是
    ``input_tokens`` = 这次真正「新读入」的 token，缓存命中/写入另计
    （``cache_read_input_tokens`` / ``cache_creation_input_tokens``）；
    OpenAI 形状的 ``prompt_tokens`` 是**总数，已经包含**缓存命中。以前这里
    直接照搬，Claude Code 的用量面板会把缓存部分算两遍 —— 显示的成本比实际
    高一大截（缓存读通常便宜 10 倍，重复计费看着像账单暴涨）。

    只有上游**明确给出**了缓存计数时才做减法：没给的时候就无从区分，此时
    照搬 prompt_tokens 才是对的（否则会把输入整个抹成 0）。
    """
    out = {
        "input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "output_tokens": 0,
    }
    if not isinstance(usage, dict):
        return out
    try:
        prompt_total = int(usage.get("prompt_tokens") or 0)
    except (TypeError, ValueError):
        prompt_total = 0
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
    # 只有真的知道缓存是多少，才能从总数里把它扣掉；否则保持原值。
    known_cache = (out["cache_read_input_tokens"]
                   + out["cache_creation_input_tokens"])
    out["input_tokens"] = (max(0, prompt_total - known_cache)
                           if known_cache else prompt_total)
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


def empty_conversation_error(messages):
    """没有一轮 user/assistant 时给客户端的拒绝文案；没问题返回 None。

    码道上游对「只有 system（或干脆空列表）」的请求回
    ``ModelArts.81001.400 messages 参数非法``——这个报错出现在上游，
    离真正原因很远：Responses 只发 ``instructions``、或者客户端把整段
    提示词塞进系统消息时最容易撞上。在网关这层先拦下来，文案写清缺什么。

    ``tool`` / ``function`` 也算一轮：它们只可能出现在助手回合之后，
    真出现了就让上游去判，别在这里误伤。
    """
    if not isinstance(messages, (list, tuple)):
        return None
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "").strip().lower()
        if role in ("user", "assistant", "tool", "function"):
            return None
    return ("messages must contain at least one user or assistant message: "
            "the codearts upstream rejects a system-only prompt with "
            "ModelArts.81001.400 (messages 参数非法). Send the actual question "
            "as a user message.")


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
    if not changed:
        return frame
    # splitlines() 把结尾的换行全吃掉了，这里补回**恰好一个**空行：SSE 的一帧
    # 以空行结束。以前直接 ``+ "\n\n"``，输入本来就以 "\n\n" 结尾时（清理前的
    # 帧都是）会多出一个换行 —— SSE 能容忍，但下游按行对比帧时会看到漂移。
    return ("\n".join(out).rstrip("\n") + "\n\n").encode("utf-8")


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
        # 结尾若干字符，只在给了 stop_sequences 时维护：用来判断最后一条
        # 停止串有没有被上游吐出来（见 matched_stop_sequence）。
        "tail": "",
    }
    stops = holder.get("stop_sequences")
    stops = [s for s in stops if isinstance(s, str) and s] \
        if isinstance(stops, (list, tuple)) else []
    tail_limit = max([len(s) for s in stops] or [0])

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
        text_line = line.decode("utf-8", "replace")
        if text_line.lstrip().startswith(":"):
            # 上游静默时 tap_lines 把 KEEPALIVE 翻成一条 SSE 注释行。Anthropic
            # 的协议里有自己的心跳事件（``event: ping``），Claude Code 认它；
            # 以前这一行被 strip_data_prefix 当空行丢掉，模型长思考时客户端
            # 收不到任何字节，nginx 60s 空闲就把连接切了。
            # **开场之前不发**：第一帧要留给 message_start，否则调用方的
            # 「首帧才提交 200」会先被心跳兑现掉（那正是要避免的事）。
            if state["started"]:
                yield anthropic_sse_frame("ping", {})
            continue
        data = strip_data_prefix(text_line)
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
            if tail_limit:
                state["tail"] = (state["tail"] + text)[-tail_limit:]
            for frame in ensure_text():
                yield frame
            yield anthropic_sse_frame("content_block_delta", {
                "index": state["text_idx"],
                "delta": {"type": "text_delta", "text": text},
            })
        for call in delta.get("tool_calls") or []:
            if not isinstance(call, dict):
                continue
            # **缺 index 时不能一律归 0**：并行两个调用且都不带 index 时，
            # 第二个会被并进第一个的槽位 —— 两个工具合成一个，参数拼成坏
            # JSON。判据与 ca_stream.merge_tool_call 一致：带 index 按 index；
            # 没 index 但有新 id → 新开一个；都没有（纯参数续片）→ 续在最后
            # 一个上。
            raw_idx = call.get("index")
            idx = None
            if raw_idx is not None:
                try:
                    idx = int(raw_idx)
                except (TypeError, ValueError):
                    idx = None
            if idx is None:
                if call.get("id") or not state["tool_order"]:
                    idx = (max(state["tool_order"]) + 1
                           if state["tool_order"] else 0)
                else:
                    idx = state["tool_order"][-1]
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
        "delta": {
            "stop_reason": state["stop"],
            # 只有「自然结束」才可能有 stop_sequence；max_tokens / tool_use
            # 一律 None（Anthropic 的枚举也是这个口径）。
            "stop_sequence": (matched_stop_sequence(state.get("tail"), stops)
                              if state["stop"] == "end_turn" else None),
        },
        "usage": usage_payload(),
    })
    yield anthropic_sse_frame("message_stop", {})


def anthropic_json_text(value):
    if value is None:
        return "{}"
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return "{}"


def anthropic_block_text(block):
    if not isinstance(block, dict):
        return ""
    if "text" in block:
        return anthropic_text(block.get("text"))
    if "content" in block:
        return anthropic_content_to_text(block.get("content"))
    return ""


def anthropic_image_part(block):
    source = block.get("source") if isinstance(block, dict) else None
    url = ""
    if isinstance(source, dict):
        stype = str(source.get("type") or "")
        if stype == "base64":
            media = anthropic_text(source.get("media_type") or "image/png")
            data = anthropic_text(source.get("data"))
            url = "data:%s;base64,%s" % (media, data)
        elif stype == "url":
            url = anthropic_text(source.get("url"))
        elif stype == "file":
            url = anthropic_text(source.get("file_id") or source.get("url"))
    return {"type": "image_url", "image_url": {"url": url}}


def anthropic_document_text(block):
    if not isinstance(block, dict):
        return ""
    title = anthropic_text(block.get("title"))
    source = block.get("source") if isinstance(block.get("source"), dict) else {}
    stype = str(source.get("type") or "")
    body = ""
    if stype == "text":
        body = anthropic_text(source.get("data"))
    elif stype == "content":
        body = anthropic_content_to_text(source.get("content"))
    elif stype == "base64":
        media = anthropic_text(source.get("media_type") or "application/octet-stream")
        body = "[document %s omitted]" % media
    elif stype == "url":
        body = anthropic_text(source.get("url"))
    elif stype == "file":
        body = anthropic_text(source.get("file_id") or source.get("url"))
    if title:
        return title + "\n" + body
    return body


def anthropic_content_to_text(value, is_error=None):
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        parts = []
        for item in value:
            if not isinstance(item, dict):
                continue
            typ = str(item.get("type") or "")
            if typ == "image":
                # 图片不能拼进文本：data URL 动辄几十万字符，塞进 tool 消息
                # 既让模型看不到图，又很容易把上下文撑爆。真正的图由调用方
                # 取出去放进紧随其后的一条 user 消息（Chat 的 tool 消息
                # content 只接受字符串），这里只留一个占位。
                parts.append("[image omitted from tool result]")
            elif typ == "document":
                parts.append(anthropic_document_text(item))
            else:
                parts.append(anthropic_block_text(item))
        text = "".join(parts)
    elif isinstance(value, dict):
        text = anthropic_block_text(value)
    else:
        text = anthropic_text(value)
    if is_error is True:
        return "error: " + text
    return text


def anthropic_images_in(value):
    """取出 content 里的图片块，转成 Chat 的 image_url 分片。

    tool 消息只能带字符串，所以这些分片要放进**紧随其后**的一条 user 消息：
    Claude Code 读图、MCP 截图都是这个形状，丢掉就等于模型收不到图。
    """
    out = []
    if not isinstance(value, list):
        return out
    for item in value:
        if not isinstance(item, dict):
            continue
        typ = str(item.get("type") or "")
        if typ == "image":
            part = anthropic_image_part(item)
            if (part.get("image_url") or {}).get("url"):
                out.append(part)
        elif typ == "document":
            # 文档本身也可能套着一层 content（里面还有图）。
            source = item.get("source")
            if isinstance(source, dict):
                out.extend(anthropic_images_in(source.get("content")))
    return out


def anthropic_system_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if not isinstance(item, dict):
                continue
            text = anthropic_text(item.get("text"))
            if text:
                parts.append(text)
        return "\n".join(parts)
    return ""


def anthropic_tool_choice(value):
    if isinstance(value, str):
        val = value.strip().lower()
        return {"auto": "auto", "any": "required", "none": "none",
                "required": "required"}.get(val, val)
    if isinstance(value, dict):
        typ = str(value.get("type") or "").strip().lower()
        if typ == "auto":
            return "auto"
        if typ == "any":
            return "required"
        if typ == "none":
            return "none"
        if typ == "tool":
            return {"type": "function",
                    "function": {"name": anthropic_text(value.get("name"))}}
    return None


def anthropic_tools_to_chat(tools):
    out = []
    skipped = []
    if not isinstance(tools, list):
        return out, skipped
    for item in tools:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("function"), dict):
            out.append(item)
            continue
        name = anthropic_text(item.get("name") or item.get("type"))
        schema = item.get("input_schema")
        if schema is None:
            schema = item.get("parameters")
        if schema is None:
            if name:
                skipped.append(name)
            continue
        fn = {"name": name}
        if item.get("description") is not None:
            fn["description"] = item.get("description")
        fn["parameters"] = schema
        out.append({"type": "function", "function": fn})
    return out, skipped


def anthropic_effort_from_messages(payload):
    if not isinstance(payload, dict):
        return None
    output_config = payload.get("output_config")
    if isinstance(output_config, dict):
        effort = anthropic_text(output_config.get("effort")).strip()
        if effort:
            return effort
    thinking = payload.get("thinking")
    if not isinstance(thinking, dict):
        return None
    typ = anthropic_text(thinking.get("type")).strip().lower()
    if typ == "disabled":
        return "none"
    if typ != "enabled":
        return None
    try:
        budget = int(thinking.get("budget_tokens") or 0)
    except (TypeError, ValueError):
        return None
    if budget <= 0:
        return None
    if budget >= 32000:
        return "xhigh"
    if budget >= 16000:
        return "high"
    if budget >= 8000:
        return "medium"
    return "low"


def anthropic_blocks_to_messages(role, blocks):
    tool_calls = []
    tool_messages = []
    content_parts = []
    texts = []
    # 工具结果里的图片：tool 消息只能带字符串，所以这些分片单独攒起来，
    # 在最后追加一条 user 消息。丢掉它们等于模型收不到图（Claude Code 读图、
    # MCP 截图都是这个形状）。
    tool_images = []
    has_non_text = False
    for block in blocks:
        if not isinstance(block, dict):
            continue
        typ = str(block.get("type") or "")
        if typ in ("thinking", "redacted_thinking"):
            continue
        if typ in ("tool_use", "server_tool_use"):
            tool_calls.append({
                "id": anthropic_text(block.get("id")),
                "type": "function",
                "function": {
                    "name": anthropic_text(block.get("name")),
                    "arguments": anthropic_json_text(block.get("input")),
                },
            })
            continue
        if typ == "tool_result":
            tool_messages.append({
                "role": "tool",
                "tool_call_id": anthropic_text(block.get("tool_use_id")),
                "content": anthropic_content_to_text(block.get("content"),
                                                      block.get("is_error")),
            })
            tool_images.extend(anthropic_images_in(block.get("content")))
            continue
        if typ == "image":
            part = anthropic_image_part(block)
            if not (part.get("image_url") or {}).get("url"):
                continue
            has_non_text = True
            content_parts.append(part)
            continue
        if typ == "document":
            has_non_text = True
            content_parts.append({"type": "text", "text": anthropic_document_text(block)})
            continue
        text = anthropic_block_text(block)
        texts.append(text)
        content_parts.append({"type": "text", "text": text})
    out = list(tool_messages)
    if not tool_calls and not texts and not has_non_text and not tool_images:
        return out
    msg = {"role": role or "user"}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    if has_non_text:
        msg["content"] = content_parts
    elif texts:
        msg["content"] = "".join(texts)
    else:
        msg["content"] = ""
    # 一条只有图片的 user 消息是空正文：给一句说明，否则有的实现会把它当
    # 空消息丢掉，图又看不到。
    if tool_images:
        out.append({"role": "user",
                    "content": [{"type": "text",
                                 "text": "Images returned by the tool result above:"}]
                               + tool_images})
    if msg.get("content") or tool_calls:
        out.append(msg)
    return out


def messages_to_chat(payload, default_max_tokens=None):
    """Translate an Anthropic Messages request into Chat Completions."""
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    model = anthropic_text(payload.get("model")).strip()
    if not model:
        raise ValueError("model is required")
    messages_in = payload.get("messages")
    if not isinstance(messages_in, list):
        raise ValueError("messages must be a list")
    if not messages_in:
        raise ValueError("messages must not be empty")
    chat = {"model": model, "messages": []}
    for key in ("temperature", "top_p"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    if payload.get("max_tokens") is not None:
        chat["max_tokens"] = payload["max_tokens"]
    else:
        default_max = default_max_tokens(model) if default_max_tokens else None
        if default_max:
            chat["max_tokens"] = default_max
    if payload.get("stream") is not None:
        chat["stream"] = bool(payload.get("stream"))
    stops = payload.get("stop_sequences")
    if isinstance(stops, list) and stops:
        chat["stop"] = stops
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and metadata.get("user_id") is not None:
        chat["user"] = metadata.get("user_id")
    tools, skipped = anthropic_tools_to_chat(payload.get("tools"))
    if tools:
        chat["tools"] = tools
    choice = anthropic_tool_choice(payload.get("tool_choice"))
    if choice is not None:
        chat["tool_choice"] = choice
    raw_choice = payload.get("tool_choice")
    if isinstance(raw_choice, dict) and raw_choice.get("disable_parallel_tool_use") is True:
        chat["parallel_tool_calls"] = False
    effort = anthropic_effort_from_messages(payload)
    if effort:
        chat["reasoning_effort"] = effort
    messages = []
    system = anthropic_system_text(payload.get("system"))
    if skipped:
        note = ("These Anthropic server tools are not available here: "
                + ", ".join(skipped) + ". Do not call them.")
        system = (system + "\n" + note) if system else note
    if system:
        messages.append({"role": "system", "content": system})
    for index, item in enumerate(messages_in):
        if not isinstance(item, dict):
            continue
        role = anthropic_text(item.get("role")).strip() or "user"
        content = item.get("content")
        if role in ("system", "developer"):
            # Claude Code >= 2.1.286 turns on Anthropic's mid-conversation
            # system beta and carries system messages inside `messages`. The
            # upstream knows the system role, so keep the message where the
            # client put it rather than failing the whole request.
            text = anthropic_system_text(content) or anthropic_content_to_text(content)
            if text:
                messages.append({"role": "system", "content": text})
            continue
        if role not in ("user", "assistant"):
            raise ValueError(
                "messages[%d].role %r must be user or assistant; "
                "pass a system prompt in the top-level system field" % (index, role))
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
        elif isinstance(content, list):
            messages.extend(anthropic_blocks_to_messages(role, content))
        elif content is not None:
            text = anthropic_text(content)
            if text:
                messages.append({"role": role, "content": text})
    chat["messages"] = messages
    return chat


TAG_START = r"<[^>]*DSML[^>]*"


DSML_CALLS_RE = re.compile(TAG_START + r"calls>(.*?)</[^>]*DSML[^>]*calls>", re.DOTALL)


DSML_INVOKE_RE = re.compile(TAG_START + r"invoke\s+name=[\x22\x27]([^\x22\x27]+)[\x22\x27]>(.*?)</[^>]*invoke>", re.DOTALL)


DSML_PARAM_RE = re.compile(TAG_START + r"parameter\s+name=[\x22\x27]([^\x22\x27]+)[\x22\x27][^>]*>(.*?)</[^>]*parameter>", re.DOTALL)


def parse_dsml_tool_calls(text):
    if not text or "DSML" not in text:
        return None, text
    match = DSML_CALLS_RE.search(text)
    if not match:
        return None, text
    calls_block = match.group(1)
    tool_calls = []
    for inv_match in DSML_INVOKE_RE.finditer(calls_block):
        func_name = inv_match.group(1)
        params_block = inv_match.group(2)
        params = {}
        for p_match in DSML_PARAM_RE.finditer(params_block):
            p_name = p_match.group(1)
            p_val = p_match.group(2).strip()
            params[p_name] = p_val
        tool_calls.append({
            "id": new_id("call_"),
            "name": func_name,
            "arguments": json.dumps(params, ensure_ascii=False),
        })
    clean = (text[:match.start()].strip() + " " + text[match.end():].strip()).strip()
    return tool_calls, clean


CJK_RE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")


def estimate_tokens(text):
    if not text:
        return 0
    if not isinstance(text, str):
        text = str(text)
    cjk = len(text) - len(CJK_RE.sub("", text))
    other = len(text) - cjk
    return cjk + max(1, int(other / 3.6)) if text else 0


def is_truncated_arguments(raw):
    """True when a non-empty tool-arguments string is not valid JSON.

    A stream cut off by max_tokens or a dropped connection leaves the last
    tool call with half-written JSON. An empty/whitespace string is a legal
    no-argument tool, and any parseable JSON (including null/scalars/arrays)
    is the model's own output for the client to validate - only non-empty
    unparsable strings count as truncation.
    """
    if not isinstance(raw, str):
        return False
    trimmed = raw.strip()
    if not trimmed:
        return False
    try:
        json.loads(trimmed)
        return False
    except Exception:
        return True


NS_SEP = "__"


def resolve_namespaced_name(name, mapping):
    """把模型回传的名字解析回 (bare_name, namespace)。接受 js / ns__js / ns::js。

    还有一种**网关自己造出来**的形态：两个 namespace 下有同名工具时，
    ``expand_namespace_tools`` 把后来的那个送出成 ``ns__tool``（否则第二个
    server 的工具对模型完全不可见）。它的 mapping 值是 namespace，所以这里
    命中后要把自己加的前缀剥掉，否则回程会把 ``server_b__search`` 原样当成
    工具名派发，客户端找不到它。
    """
    if not name:
        return name, ""
    name = str(name)
    if name in mapping:
        ns = mapping[name]
        # 网关加的前缀：ns + "__" 正好是这个名字的开头。真·工具名以自己
        # namespace 加下划线开头的概率可以忽略，而丢掉一整个 server 的工具
        # 是线上真会遇到的（Codex 接两个 MCP server）。
        if ns and name.startswith(str(ns) + NS_SEP):
            return name[len(str(ns)) + len(NS_SEP):], ns
        return name, ns
    if "::" in name:
        idx = name.find("::")
        if idx > 0:
            tail = name[idx + 2:]
            head = name[:idx]
            if tail in mapping:
                return tail, mapping[tail]
            return tail, head

    # ns__tool 用精确比对，避免 namespace 内含 '__'（如 codex_apps__github）时切错
    for tool, ns in mapping.items():
        if name == ns + NS_SEP + tool:
            return tool, ns

    return name, ""


def stamp_namespace(item, mapping):
    """把模型回传的扁平工具名还原成 (name, namespace)。

    串流的 response.output_item.done 事件才是客户端派发工具呼叫的依据，
    所以每个 function_call / custom_tool_call 项目都要在送出前补上 namespace。
    """
    if not mapping or not isinstance(item, dict):
        return item
    bare, ns = resolve_namespaced_name(item.get("name"), mapping)
    if ns:
        item["name"] = bare
        item["namespace"] = ns
    return item


def apply_namespace_to_calls(output_items, mapping):
    """替 Responses 的 function_call / custom_tool_call 补上 namespace。"""
    if not mapping or not isinstance(output_items, list):
        return output_items, 0
    fixed = 0
    for item in output_items:
        if not isinstance(item, dict):
            continue
        if item.get("type") not in ("function_call", "custom_tool_call"):
            continue
        if item.get("namespace"):
            continue
        bare, ns = resolve_namespaced_name(item.get("name"), mapping)
        if ns:
            item["name"] = bare
            item["namespace"] = ns
            fixed += 1
    return output_items, fixed


def unwrap_custom_input(args):
    """Pull the freeform string back out of an {"input": "..."} argument blob."""
    if not isinstance(args, str):
        return json.dumps(args or "", ensure_ascii=False)
    try:
        parsed = json.loads(args)
    except Exception:
        return args
    if isinstance(parsed, dict):
        val = parsed.get("input")
        if isinstance(val, str):
            return val
        if val is not None:
            return json.dumps(val, ensure_ascii=False)
    if isinstance(parsed, str):
        return parsed
    return args


CITATION_MD_RE = re.compile(r"\[([^\]\n]{1,200})\]\((https?://[^)\s]+)\)")


def build_citations(text, sources):
    """把模型实际引用到的来源转成 url_citation annotations。

    只标注真的有出现在工具输出里的网址 —— 模型自己编的连结不会被当成引用。
    """
    text = str(text or "")
    if not text or not sources:
        return []
    by_url = {}
    for s in sources or []:
        if not isinstance(s, dict):
            continue
        url = str(s.get("url") or "").strip()
        if not url:
            continue
        by_url.setdefault(url, s)
        by_url.setdefault(url.rstrip("/"), s)

    anns = []
    seen = set()

    def add(url, title, start, end):
        key = (url, start, end)
        if key in seen or start < 0 or end <= start:
            return
        seen.add(key)
        anns.append({
            "type": "url_citation",
            "url": url,
            "title": title or url,
            "start_index": start,
            "end_index": end,
        })

    md_spans = []
    for m in CITATION_MD_RE.finditer(text):
        url = m.group(2)
        src = by_url.get(url) or by_url.get(url.rstrip("/"))
        if not src:
            continue
        md_spans.append((m.start(0), m.end(0)))
        add(url, src.get("title") or m.group(1), m.start(0), m.end(0))

    for m in re.finditer(r"https?://[^\s<>()\[\]]+", text):
        if any(m.start(0) >= s and m.end(0) <= e for s, e in md_spans):
            continue
        url = m.group(0).rstrip(".,;:!?")
        src = by_url.get(url) or by_url.get(url.rstrip("/"))
        if not src:
            continue
        add(url, src.get("title"), m.start(0), m.start(0) + len(url))

    anns.sort(key=lambda a: (a["start_index"], a["end_index"]))
    return anns


def web_tools_active(body):
    """True when this request's tools were swapped for the gateway's own.

    Interception only applies to a request whose definitions the gateway
    injected: with the switch off, a client's own same-named function must be
    forwarded instead of being swallowed here.
    """
    return isinstance(body, dict) and body.get("_web_tools") is True


def responses_usage(u):
    """Chat 的 usage → Responses 的 usage。

    ``total_tokens`` 缺失时用 prompt + completion 补上：上游有只给前两项的
    收尾帧，而 Responses 形状要求这三项自洽。以前这里是 ``or 0`` 直接照搬，
    客户端看到的是「输入 12 / 输出 2 / 合计 0」（2026-10-23）。
    """
    if not u:
        return None
    det = u.get("completion_tokens_details") or {}
    pdet = u.get("prompt_tokens_details") or {}
    prompt = u.get("prompt_tokens") or 0
    completion = u.get("completion_tokens") or 0
    total = u.get("total_tokens") or 0
    if not total:
        try:
            total = int(prompt) + int(completion)
        except (TypeError, ValueError):
            total = 0
    return {
        "input_tokens": prompt,
        "input_tokens_details": {
            "cached_tokens": u.get("prompt_cache_hit_tokens")
            or det.get("cached_tokens") or pdet.get("cached_tokens") or 0,
        },
        "output_tokens": completion,
        "output_tokens_details": {"reasoning_tokens": det.get("reasoning_tokens") or 0},
        "total_tokens": total,
    }


def stream_responses_events(upstream, model, holder, webtools=None):
    """Yield Responses-API SSE frames translated from chat-completions chunks."""
    fetch_name = (getattr(webtools, "WEB_FETCH_NAME", "")
                  if webtools is not None else "")

    def _is_internal(name):
        return bool(webtools is not None and name
                    and webtools.is_internal_tool(name))
    resp_id, msg_id, rs_id = new_id("resp_"), new_id("msg_"), new_id("rs_")
    created = int(time.time())
    seq = 0
    text_parts, reason_parts = [], []
    outputs = []
    reason_index = None
    msg_index = None
    finish = "stop"
    usage = None
    tool_calls_map = {}
    text_buffer = ""
    dsml_tool_calls = []
    saw_done = False
    custom_names = set(holder.get("custom_names") or ())
    ns_map = holder.get("namespace_map") or {}
    # 由反代代跑的网路工具呼叫，收集起来不转发给客户端
    _internal_calls = {}
    # Only reach for same-named calls when this request's definitions were the
    # gateway's own (see web_tools_active); otherwise they belong to the client.
    _own_web_tools = web_tools_active(holder.get("base_body"))
    # Echo the request capabilities the client actually sent, same as the
    # non-streaming path; these were hardcoded before.
    meta = holder.get("request_meta") or {}
    def resp_obj(status):
        obj = {
            "id": resp_id,
            "object": "response",
            "created_at": created,
            "status": status,
            "model": model,
            "output": [o for o in outputs if o],
            "output_text": "".join(text_parts),
            "parallel_tool_calls": meta.get("parallel_tool_calls", True),
            "tool_choice": meta.get("tool_choice", "auto"),
            "tools": meta.get("tools") or [],
            "metadata": {},
        }
        u = responses_usage(usage)
        if u:
            obj["usage"] = u
        if ns_map:
            obj["output"], _nsf = apply_namespace_to_calls(obj.get("output") or [], ns_map)
        return obj
    def ev(etype, payload):
        nonlocal seq
        seq += 1
        data = {"type": etype, "sequence_number": seq}
        data.update(payload)
        body = json.dumps(data, ensure_ascii=False)
        return ("event: " + etype + chr(10) + "data: " + body + chr(10) + chr(10)).encode("utf-8")
    def reason_item(status):
        return {
            "id": rs_id,
            "type": "reasoning",
            "status": status,
            "summary": [{"type": "summary_text", "text": "".join(reason_parts)}],
        }
    def _annotations():
        """引用来源：只认工具真的回传过的网址。"""
        try:
            return build_citations("".join(text_parts), holder.get("web_sources") or [])
        except Exception:
            return []

    def msg_item(status):
        item = {"id": msg_id, "type": "message", "status": status,
                "role": "assistant", "content": []}
        if text_parts:
            item["content"] = [{"type": "output_text", "text": "".join(text_parts),
                              "annotations": _annotations()}]
        return item
    def _finalize():
        # Close out the stream: reasoning item, structured tool calls,
        # DSML fallback, the message item and response.completed.
        nonlocal msg_index, text_buffer
        # 若一帧上游数据都没到（空流），开场事件还得补上 —— 否则客户端收到
        # 的第一帧就是 response.completed，既没有 response.created 也没有
        # in_progress，部分客户端会把它当成协议错误丢掉。
        yield from _lifecycle()
        if reason_index is not None and outputs[reason_index] is None:
            full_r = "".join(reason_parts)
            yield ev("response.reasoning_summary_text.done", {
                "item_id": rs_id, "output_index": reason_index, "summary_index": 0, "text": full_r,
            })
            yield ev("response.reasoning_summary_part.done", {
                "item_id": rs_id, "output_index": reason_index, "summary_index": 0,
                "part": {"type": "summary_text", "text": full_r},
            })
            outputs[reason_index] = reason_item("completed")
            yield ev("response.output_item.done",
                     {"output_index": reason_index, "item": outputs[reason_index]})
        # 1. Emit completed structured tool calls
        for idx in sorted(tool_calls_map.keys()):
            entry = tool_calls_map[idx]
            if entry.get("custom"):
                yield ev("response.custom_tool_call_input.done", {
                    "output_index": entry["output_index"],
                    "item_id": entry["item_id"],
                    "call_id": entry["id"],
                    "input": unwrap_custom_input(entry["arguments"]),
                })
                fc_item = {
                    "id": entry["item_id"],
                    "type": "custom_tool_call",
                    "status": "completed",
                    "call_id": entry["id"],
                    "name": entry["name"],
                    "input": unwrap_custom_input(entry["arguments"]),
                }
            else:
                yield ev("response.function_call_arguments.done", {
                    "output_index": entry["output_index"],
                    "item_id": entry["item_id"],
                    "call_id": entry["id"],
                    "arguments": entry["arguments"],
                })
                fc_item = {
                    "id": entry["item_id"],
                    "type": "function_call",
                    "status": "completed",
                    "call_id": entry["id"],
                    "name": entry["name"],
                    "arguments": entry["arguments"],
                }
            stamp_namespace(fc_item, ns_map)
            outputs[entry["output_index"]] = fc_item
            yield ev("response.output_item.done", {
                "output_index": entry["output_index"],
                "item": fc_item,
            })
        # Flush remaining buffered text if any
        if text_buffer:
            calls_rem, clean_rem = parse_dsml_tool_calls(text_buffer)
            if calls_rem:
                dsml_tool_calls.extend(calls_rem)
            if clean_rem:
                text_parts.append(clean_rem)
                if msg_index is not None:
                    yield ev("response.output_text.delta", {
                        "item_id": msg_id, "output_index": msg_index,
                        "content_index": 0, "delta": clean_rem,
                    })
            text_buffer = ""
        # 2. DSML fallback: emit buffered/parsed DSML tool calls if no structured tool_calls were emitted
        full_text = "".join(text_parts)
        dsml_calls = dsml_tool_calls
        if not dsml_calls:
            extra_calls, clean_text = parse_dsml_tool_calls(full_text)
            if extra_calls:
                dsml_calls = extra_calls
                full_text = clean_text
        if dsml_calls and not tool_calls_map:
            for dc in dsml_calls:
                # DSML 形状的网路工具呼叫一样由反代执行
                if _own_web_tools and _is_internal(dc.get("name")):
                    entry = _internal_calls.setdefault(dc.get("id") or new_id("call_"),
                                                       {"name": dc.get("name"), "arguments": "{}"})
                    entry["name"] = dc.get("name") or entry["name"]
                    entry["arguments"] = dc.get("arguments") or entry.get("arguments") or "{}"
                    continue
                out_idx = len(outputs)
                fc_item = {
                    "id": new_id("fc_"),
                    "type": "function_call",
                    "status": "completed",
                    "call_id": dc.get("id") or new_id("call_"),
                    "name": dc.get("name") or "",
                    "arguments": dc.get("arguments") or "{}",
                }
                stamp_namespace(fc_item, ns_map)
                outputs.append(fc_item)
                yield ev("response.output_item.added", {
                    "output_index": out_idx,
                    "item": dict(fc_item, status="in_progress", arguments=""),
                })
                yield ev("response.function_call_arguments.delta", {
                    "output_index": out_idx,
                    "item_id": fc_item["id"],
                    "call_id": fc_item["call_id"],
                    "delta": fc_item["arguments"],
                })
                yield ev("response.function_call_arguments.done", {
                    "output_index": out_idx,
                    "item_id": fc_item["id"],
                    "call_id": fc_item["call_id"],
                    "arguments": fc_item["arguments"],
                })
                yield ev("response.output_item.done", {
                    "output_index": out_idx,
                    "item": fc_item,
                })
        # 这一轮如果有代跑的网路工具呼叫，就把完成事件留给下一轮，
        # 否则客户端会以为整个回合已经结束（旧版是在回合用尽时补一个合成的
        # resp_wrapup，那才是 issue #43 真正的病灶）。
        if _internal_calls:
            holder.setdefault("internal_calls", []).extend(
                {"name": v["name"], "arguments": v["arguments"]}
                for v in _internal_calls.values()
            )
            holder["suppress_completion"] = True
            # 让 App 画出原生的「已搜寻网路」卡片：对每个代跑的呼叫送出
            # web_search_call 项目与生命周期事件。
            for _v in _internal_calls.values():
                _nm = str(_v.get("name") or "")
                try:
                    _a = json.loads(_v.get("arguments") or "{}")
                except Exception:
                    _a = {}
                if not isinstance(_a, dict):
                    _a = {}
                if _nm == fetch_name:
                    _action = {"type": "open_page", "url": webtools.url_arg(_a)}
                else:
                    _action = {"type": "search", "query": webtools.query_args(_a)}
                _ws_id = new_id("ws_")
                _ws_idx = len(outputs)
                outputs.append(None)
                yield ev("response.output_item.added", {
                    "output_index": _ws_idx,
                    "item": {"id": _ws_id, "type": "web_search_call",
                             "status": "in_progress"},
                })
                yield ev("response.web_search_call.in_progress", {
                    "output_index": _ws_idx, "item_id": _ws_id,
                })
                yield ev("response.web_search_call.searching", {
                    "output_index": _ws_idx, "item_id": _ws_id,
                })
                _ws_item = {"id": _ws_id, "type": "web_search_call", "status": "completed"}
                if _action.get("query") or _action.get("url"):
                    _ws_item["action"] = _action
                outputs[_ws_idx] = _ws_item
                yield ev("response.output_item.done", {
                    "output_index": _ws_idx, "item": _ws_item,
                })
                yield ev("response.web_search_call.completed", {
                    "output_index": _ws_idx, "item_id": _ws_id,
                })
        # 3. Emit message item only if text was emitted OR no other output item exists
        has_other_items = any(o for o in outputs if o)
        if msg_index is not None or full_text or not has_other_items:
            if msg_index is None:
                msg_index = len(outputs)
                outputs.append(None)
                yield ev("response.output_item.added", {
                    "output_index": msg_index,
                    "item": {"id": msg_id, "type": "message", "status": "in_progress",
                             "role": "assistant", "content": []},
                })
                yield ev("response.content_part.added", {
                    "item_id": msg_id, "output_index": msg_index, "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": _annotations()},
                })
            yield ev("response.output_text.done", {
                "item_id": msg_id, "output_index": msg_index, "content_index": 0, "text": full_text,
            })
            yield ev("response.content_part.done", {
                "item_id": msg_id, "output_index": msg_index, "content_index": 0,
                "part": {"type": "output_text", "text": full_text,
                         "annotations": _annotations()},
            })
            outputs[msg_index] = msg_item("completed")
            yield ev("response.output_item.done", {"output_index": msg_index, "item": outputs[msg_index]})
        nonlocal usage
        # 只有**完全没有**上游用量时才估算。以前的条件是「total_tokens 为 0
        # 也估算」，而上游回一条 usage 但 total_tokens 恰好是 0（空回答 /
        # 只回思考内容的收尾帧）时，真实的 prompt/completion 会被一份估算值
        # 整个盖掉 —— 账上记的和上游算的不是一回事（2026-10-23）。
        _has_real_usage = isinstance(usage, dict) and (
            usage.get("prompt_tokens") or usage.get("completion_tokens")
            or usage.get("total_tokens"))
        if not _has_real_usage:
            out_txt = "".join(text_parts)
            rs_txt = "".join(reason_parts)
            if out_txt or rs_txt:
                comp = estimate_tokens(out_txt) + estimate_tokens(rs_txt)
                prompt_est = max(1, estimate_tokens(str(meta.get("input") or "")))
                usage = {
                    "prompt_tokens": prompt_est,
                    "completion_tokens": comp,
                    "total_tokens": prompt_est + comp,
                    "completion_tokens_details": {"reasoning_tokens": estimate_tokens(rs_txt)},
                    "prompt_tokens_details": {"cached_tokens": 0},
                }
                holder["usage"] = usage
        status = ("completed" if (finish != "length" and not dropped_truncated)
                  else "incomplete")
        final = resp_obj(status)
        if finish == "length":
            final["incomplete_details"] = {"reason": "max_output_tokens"}
        if not holder.get("suppress_completion"):
            yield ev("response.completed", {"response": final})

    # 只有第一轮开场。第二轮以后再送一次 response.created，客户端会
    # 看到同一则回应被开了两次。
    #
    # **推迟到第一帧上游数据**（2026-10-23）：这两个事件以前在 for 循环之前
    # 就 yield 了，而码道流式路径是「翻译器产出的第一帧才提交 200」。于是
    # 200 在读上游之前就发出去了 —— 首帧即 1041（限流）时既不能重试也不能
    # 换号，只能以「200 + 空流」收场，README 里那句「收到第一帧才提交 200」
    # 对 Responses 根本不成立。现在第一帧真的到了才开场。
    started_lifecycle = False

    def _lifecycle():
        nonlocal started_lifecycle
        if started_lifecycle or holder.get("suppress_lifecycle"):
            return
        started_lifecycle = True
        yield ev("response.created", {"response": resp_obj("in_progress")})
        yield ev("response.in_progress", {"response": resp_obj("in_progress")})

    for raw in upstream:
        text_line = raw.decode("utf-8", "replace")
        if text_line.strip().startswith(":"):
            # 上游静默时 tap_lines 会把 KEEPALIVE 哨兵翻成一条 SSE 注释行。
            # 以前这一行被 strip_data_prefix 当成空行丢掉，于是模型长思考
            # 期间客户端一个字节都收不到 —— 叠加 nginx 60s / CF 100s 的空闲
            # 超时，Codex 这条链最容易被中间层切断。**只在开场之后发**：
            # 开场之前发就等于把 200 提前承诺了（见上面）。
            if started_lifecycle:
                yield b": keepalive\n\n"
            continue
        data = strip_data_prefix(text_line)
        if not data or data == "[DONE]":
            if data == "[DONE]":
                saw_done = True
            continue
        try:
            chunk = json.loads(data)
        except Exception:
            continue
        if not started_lifecycle:
            yield from _lifecycle()
        u = chunk.get("usage")
        if u:
            if usage is None or (u.get("total_tokens") or 0) >= (usage.get("total_tokens") or 0):
                usage = u
                holder["usage"] = usage
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}
            piece = delta.get("reasoning_content")
            if piece:
                if reason_index is None:
                    reason_index = len(outputs)
                    outputs.append(None)
                    yield ev("response.output_item.added",
                             {"output_index": reason_index, "item": reason_item("in_progress")})
                    yield ev("response.reasoning_summary_part.added", {
                        "item_id": rs_id, "output_index": reason_index, "summary_index": 0,
                        "part": {"type": "summary_text", "text": ""},
                    })
                reason_parts.append(piece)
                yield ev("response.reasoning_summary_text.delta", {
                    "item_id": rs_id, "output_index": reason_index,
                    "summary_index": 0, "delta": piece,
                })
            for tc in delta.get("tool_calls") or []:
                # 缺 index 的判据同 merge_tool_call：带 index 按 index；
                # 没 index 但有新 id 就新开；都没有就续在最后一个上。
                # 以前这里 `tc.get("index", 0)` 会把并行的多个调用全并进 0。
                idx = tc.get("index")
                if idx is None:
                    if tc.get("id") or not tool_calls_map:
                        idx = (max(tool_calls_map) + 1) if tool_calls_map else 0
                    else:
                        idx = max(tool_calls_map)
                else:
                    try:
                        idx = int(idx)
                    except (TypeError, ValueError):
                        idx = (max(tool_calls_map) + 1) if tool_calls_map else 0
                fn = tc.get("function") or {}
                fn_name = fn.get("name") or ""
                fn_args = fn.get("arguments") or ""
                call_id = tc.get("id") or ""
                # web_search / web_fetch 由反代执行，不转发给客户端
                if idx in _internal_calls or (
                        _own_web_tools and fn_name
                        and _is_internal(fn_name)):
                    entry = _internal_calls.setdefault(idx, {"name": fn_name, "arguments": ""})
                    if fn_name:
                        entry["name"] = fn_name
                    if fn_args:
                        entry["arguments"] += fn_args
                    continue
                if idx not in tool_calls_map:
                    out_idx = len(outputs)
                    outputs.append(None)
                    c_id = call_id or new_id("call_")
                    is_custom = bool(fn_name) and fn_name in custom_names
                    entry = {
                        "output_index": out_idx,
                        "id": c_id,
                        "name": fn_name,
                        "arguments": fn_args,
                        "custom": is_custom,
                        "item_id": new_id("ctc_" if is_custom else "fc_"),
                    }
                    tool_calls_map[idx] = entry
                    item = {
                        "id": entry["item_id"],
                        "status": "in_progress",
                        "call_id": c_id,
                        "name": fn_name,
                    }
                    if is_custom:
                        item["type"] = "custom_tool_call"
                        item["input"] = ""
                    else:
                        item["type"] = "function_call"
                        item["arguments"] = ""
                    # namespace 必须在 output_item.added 就带上（照 CiderCC-UwU
                    # proxy.mjs openItem 的做法）。事后才补只会改到 done，
                    # 客户端早就从 added 事件派发过了。
                    stamp_namespace(item, ns_map)
                    yield ev("response.output_item.added", {
                        "output_index": out_idx,
                        "item": item,
                    })
                else:
                    entry = tool_calls_map[idx]
                    if fn_name and not entry["name"]:
                        entry["name"] = fn_name
                        if fn_name in custom_names:
                            entry["custom"] = True
                    if fn_args:
                        entry["arguments"] += fn_args
                        if entry.get("custom"):
                            yield ev("response.custom_tool_call_input.delta", {
                                "output_index": entry["output_index"],
                                "item_id": entry["item_id"],
                                "call_id": entry["id"],
                                "delta": fn_args,
                            })
                        else:
                            yield ev("response.function_call_arguments.delta", {
                                "output_index": entry["output_index"],
                                "item_id": entry["item_id"],
                                "call_id": entry["id"],
                                "delta": fn_args,
                            })
            piece = delta.get("content")
            if piece:
                if msg_index is None:
                    if reason_index is not None:
                        full_r = "".join(reason_parts)
                        yield ev("response.reasoning_summary_text.done", {
                            "item_id": rs_id, "output_index": reason_index,
                            "summary_index": 0, "text": full_r,
                        })
                        yield ev("response.reasoning_summary_part.done", {
                            "item_id": rs_id, "output_index": reason_index, "summary_index": 0,
                            "part": {"type": "summary_text", "text": full_r},
                        })
                        outputs[reason_index] = reason_item("completed")
                        yield ev("response.output_item.done",
                                 {"output_index": reason_index, "item": outputs[reason_index]})
                    msg_index = len(outputs)
                    outputs.append(None)
                    yield ev("response.output_item.added", {
                        "output_index": msg_index,
                        "item": {"id": msg_id, "type": "message", "status": "in_progress",
                                 "role": "assistant", "content": []},
                    })
                    yield ev("response.content_part.added", {
                        "item_id": msg_id, "output_index": msg_index, "content_index": 0,
                        "part": {"type": "output_text", "text": "", "annotations": _annotations()},
                    })
                # DSML tool call buffering: do not stream raw DSML tags to client
                text_buffer += piece
                while text_buffer:
                    idx = text_buffer.find("<")
                    if idx == -1:
                        text_parts.append(text_buffer)
                        yield ev("response.output_text.delta", {
                            "item_id": msg_id, "output_index": msg_index,
                            "content_index": 0, "delta": text_buffer,
                        })
                        text_buffer = ""
                        break
                    m = DSML_CALLS_RE.search(text_buffer)
                    if m and m.start() == idx:
                        if idx > 0:
                            lead = text_buffer[:idx]
                            text_parts.append(lead)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": lead,
                            })
                        calls_found, _ = parse_dsml_tool_calls(m.group(0))
                        if calls_found:
                            dsml_tool_calls.extend(calls_found)
                        text_buffer = text_buffer[m.end():]
                        continue
                    cand = text_buffer[idx:idx+30]
                    is_cand = ("DSML" in cand) or (len(cand) < 10 and not any(c in cand for c in (" ", "\t", "\n", ">")))
                    if is_cand:
                        lead = text_buffer[:idx]
                        text_parts.append(lead)
                        yield ev("response.output_text.delta", {
                            "item_id": msg_id, "output_index": msg_index,
                            "content_index": 0, "delta": lead,
                        })
                        text_buffer = text_buffer[idx:]
                        break
                    else:
                        next_lt = text_buffer[idx+1:].find("<")
                        if next_lt != -1:
                            flush_len = idx + 1 + next_lt
                            lead = text_buffer[:flush_len]
                            text_parts.append(lead)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": lead,
                            })
                            text_buffer = text_buffer[flush_len:]
                        else:
                            text_parts.append(text_buffer)
                            yield ev("response.output_text.delta", {
                                "item_id": msg_id, "output_index": msg_index,
                                "content_index": 0, "delta": text_buffer,
                            })
                            text_buffer = ""
                            break
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    # Truncated streams (max_tokens, dropped connection) can leave tool-call
    # arguments as half-written JSON. Do not close those calls out as
    # completed: drop them before finalize so the client never receives a
    # function_call_arguments.done / output_item.done with unparsable
    # arguments. Complete calls in the same batch are kept.
    dropped_truncated = 0
    if tool_calls_map and (finish == "length" or not saw_done):
        for idx in sorted(tool_calls_map.keys()):
            entry = tool_calls_map[idx]
            if is_truncated_arguments(entry.get("arguments")):
                tool_calls_map.pop(idx, None)
                dropped_truncated += 1
    yield from _finalize()


def anthropic_parse_tool_input(value):
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except Exception:
            return {"raw": value}
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed}
    return {"value": value}


def matched_stop_sequence(text, stop_sequences):
    """Best-effort：产出文本**结尾**命中的那条停止串；判断不了就 None。

    为什么只能 best-effort：Anthropic 的语义是「生成到停止串前一刻就停」，
    命中的串本身不该出现在输出里。码道上游正是这样 —— 2026-10-23 直连实测
    （``stop=["六"]``）只回 ``finish_reason=stop``，正文/思考里都看不到「六」，
    所以**没有任何信号**能反推是哪条命中。这里只在「上游把串吐出来了」时
    回答（有些实现会包含），宁可为 None 也不猜；多串同时命中时取最长的。

    调用方据此填 ``stop_sequence`` 字段：填不出来就保持 null，客户端本来也
    允许它为 null。
    """
    if not isinstance(text, str) or not text or not isinstance(stop_sequences, (list, tuple)):
        return None
    candidates = [s for s in stop_sequences if isinstance(s, str) and s]
    for seq in sorted(candidates, key=len, reverse=True):
        if text.endswith(seq):
            return seq
    return None


def chat_to_messages(obj, stop_sequences=None):
    """Fold one Chat Completions object into an Anthropic Messages object.

    ``stop_sequences`` 只用于回填 ``stop_sequence``：Anthropic 要求告诉客户端
    「是哪条停止串命中的」。码道上游把命中的停止串**丢掉**（实测 2026-10-23：
    文本停在串前，只回 ``finish_reason=stop``），所以只有上游真把串吐出来时
    才填得上；填不上就保持 None，绝不猜。
    """
    if not isinstance(obj, dict):
        obj = {}
    choices = obj.get("choices") if isinstance(obj.get("choices"), list) else []
    message = {}
    finish = ""
    if choices and isinstance(choices[0], dict):
        message = choices[0].get("message") if isinstance(choices[0].get("message"), dict) else {}
        finish = choices[0].get("finish_reason") or ""
    content = []
    # The upstream thinking trace becomes a native thinking block so clients
    # such as Claude Code can render it; the request side drops incoming
    # thinking blocks, so nothing unsigned ever reaches the upstream.
    reasoning = anthropic_text(message.get("reasoning_content"))
    if reasoning:
        content.append({"type": "thinking", "thinking": reasoning})
    text = message.get("content")
    if isinstance(text, list):
        text = "".join(anthropic_block_text(part) for part in text if isinstance(part, dict))
    text = anthropic_text(text)
    if text:
        content.append({"type": "text", "text": text})
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") if isinstance(call.get("function"), dict) else {}
            content.append({
                "type": "tool_use",
                "id": anthropic_text(call.get("id")) or new_id("toolu_"),
                "name": anthropic_text(fn.get("name")),
                "input": anthropic_parse_tool_input(fn.get("arguments")),
            })
    return {
        "id": anthropic_message_id(obj.get("id")),
        "type": "message",
        "role": "assistant",
        "model": anthropic_text(obj.get("model")),
        "content": content,
        "stop_reason": anthropic_stop_reason(finish),
        "stop_sequence": (matched_stop_sequence(text, stop_sequences)
                          if anthropic_stop_reason(finish) == "end_turn" else None),
        "usage": anthropic_usage(obj.get("usage")),
    }

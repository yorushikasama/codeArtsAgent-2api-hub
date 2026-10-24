# -*- coding: utf-8 -*-
"""ca_stream.py - 码道上游流式帧的**解析与收尾语义**（纯函数层）

## 为什么要有这个文件

`ca_proxy.py` 已经两万多行，而「一帧上游数据是什么意思」「流该怎么收尾」
这类判断原来散在三个 handler 里（Chat / Responses / Messages），每次改动都要
在三个地方各修一遍，于是出现了同一种 bug 修一处漏两处：

2026-10-23 的线上问题就是典型 —— 上游先吐正文、再塞一个 ``error_code`` 帧。
Chat 那条路只写了「一个字都没出就报错」的分支，出过内容时错误帧会直接落到
``finish_reason=stop`` + ``[DONE]``，客户端把半截回答当完整结果，``usage.jsonl``
记成 ``completed``；Responses / Messages 更彻底，它们的翻译器根本不认识
``error_code``，连错误事件都不发。

这个模块的边界和 ``ca_protocol`` 一样硬：

    **进参是数据，出参是数据，不碰 socket、不读全局、不写日志。**

## 分层

1. **帧解析**：``frame_error`` / ``frame_usage`` / ``collect_sse`` /
   ``merge_tool_call`` —— 一帧 JSON 能读出什么。
2. **行流旁路**：``tap_lines`` —— 在把上游行流交给协议翻译器之前，顺手记下
   usage 与错误帧。错误帧会抛 ``UpstreamErrorFrame``，逼调用方先收尾，**不能**
   让翻译器继续走它的「正常完成」终态。
3. **收尾判定**：``tail_kind`` —— 一条流结束时是 ``complete`` /
   ``error_frame`` / ``upstream_aborted``。错误永远压过完成：只要出现过错误帧，
   就不许再补 ``finish_reason``。
4. **错误语义**：``fail_spec`` / ``frame_status`` / ``retryable`` /
   ``concurrency_full`` / ``error_detail`` / ``break_hint`` —— 上游错误码到
   「对外状态码 + 客户端该不该重试」的唯一一张表。

搬的时候只做**移动**；唯一的行为变化是 ``frame_error`` 现在也认 OpenAI 形状的
``{"error": {...}}`` 帧（上游偶尔用它代替 ``error_code``），以及 ``tail_kind``
把「错误优先级」写成显式规则，而不是靠调用点漏写分支。
"""

import json

#: ``tail_kind`` 的三种结果。
COMPLETE = "complete"
ERROR_FRAME = "error_frame"
UPSTREAM_ABORTED = "upstream_aborted"


class UpstreamErrorFrame(Exception):
    """上游在流里给了明确的错误帧（HTTP 仍是 200）。

    只用来打断翻译器：它意味着这一轮**不会**有合法的结束事件，调用方必须
    按各自协议发一个错误终态，而不是让翻译器补 ``response.completed`` /
    ``message_stop``。
    """

    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = str(message or "")


def frame_error(piece):
    """这一帧是不是上游错误？是就返回 ``"CODE MESSAGE"``，否则空串。

    码道的形状是 ``{"error_code": ..., "error_msg": ...}``；OpenAI 兼容层
    偶尔回 ``{"error": {"code": ..., "message": ...}}``。两种都认，因为它们的
    含义完全一样 —— 这一轮已经废了。
    """
    if not isinstance(piece, dict):
        return ""
    code = piece.get("error_code")
    if code:
        msg = piece.get("error_msg") or piece.get("error") or ""
        return ("%s %s" % (code, msg)).strip()
    err = piece.get("error")
    if isinstance(err, dict):
        return ("%s %s" % (err.get("code") or err.get("type") or "",
                           err.get("message") or err.get("msg") or "")).strip()
    if isinstance(err, str) and err:
        return err
    return ""


def frame_usage(piece):
    """这一帧带的 usage 块（没有就 None）。"""
    if isinstance(piece, dict) and isinstance(piece.get("usage"), dict):
        return piece["usage"]
    return None


def finish_error(choice):
    """``finish_reason=error`` 也是失败（WorkBuddy 那条路早已这么判定）。

    上游有时不用错误帧，而是用 ``finish_reason: "error"`` 表示这一轮废了。
    以前只有 WorkBuddy 路径认（#389），码道这侧会把它原样转发并记成完成。
    """
    return (isinstance(choice, dict)
            and str(choice.get("finish_reason") or "").lower() == "error")


def tail_kind(frame_err="", truncated=""):
    """一条流结束时该怎么收尾。

    **顺序就是语义**：只要出现过错误帧，就不许当正常结束 —— 哪怕上游在错误
    之后又发了 ``finish_reason``，哪怕正文已经吐了一大半。断流同理。
    """
    if frame_err:
        return ERROR_FRAME
    if truncated:
        return UPSTREAM_ABORTED
    return COMPLETE


def merge_tool_call(calls, call):
    """把一帧 ``delta.tool_calls`` 并进累积列表。

    同一个 index 会分多帧到达：第一帧带 id/type/name，后面的帧只带 arguments
    的增量片段。按 index 归并，缺失字段沿用已有值。

    **缺 index 时不能一律归 0**（2026-10-23）。以前 ``int(call.get("index")
    or 0)``：上游并行发两个调用、都没写 index 时，第二个的 name/arguments
    会被并进第一个的槽位 —— 两个调用合成一个，参数拼成 ``{"a":1}{"b":2}``
    这种坏 JSON。现在的判据：

      · 带了 index → 按 index；
      · 没带 index，但带了新的 ``id``（一个新的调用开始）→ 新开槽位；
      · 没带 index 也没 id（纯参数续片）→ 接在**最后一个**槽位上。

    最后这条是关键：上游常把 arguments 分片成多帧而只在第一帧给 index，
    后面各帧省略它 —— 那些帧必须续在同一个调用上，不能各开一个。
    """
    if not isinstance(call, dict):
        return
    raw_index = call.get("index")
    index = None
    if raw_index is not None:
        try:
            index = int(raw_index)
        except (TypeError, ValueError):
            index = None
    if index is None:
        if call.get("id") or not calls:
            index = len(calls)
        else:
            index = len(calls) - 1
    while len(calls) <= index:
        calls.append({"id": "", "type": "function",
                      "function": {"name": "", "arguments": ""}})
    slot = calls[index]
    for key in ("id", "type"):
        if call.get(key):
            slot[key] = call[key]
    fn = call.get("function") or {}
    target = slot.setdefault("function", {"name": "", "arguments": ""})
    if fn.get("name"):
        target["name"] = fn["name"]
    if fn.get("arguments"):
        target["arguments"] = (target.get("arguments") or "") + fn["arguments"]


def collect_sse(text, sink=None):
    """把码道的 SSE 流聚合成 (正文, 推理, usage, 帧内错误, tool_calls)。

    码道回的是 OpenAI 形状的 chunk，但错误可能藏在帧里而 HTTP 仍是 200，
    所以必须逐帧扫错误码 —— 只看状态码会把失败读成成功。

    tool_calls（2026-10-21 补）：上游 function calling 是原生支持的，会以
    ``delta.tool_calls`` 逐帧下发（同一个 index 的 arguments 分片续接），外加
    ``finish_reason="tool_calls"``。以前这里只收 content / reasoning_content，
    tool_calls 被整段丢掉 —— 上游明明正确地请求了工具，网关聚合完就把
    delta 清空，于是渲染层永远看不到调用，模型自己编的 ``<tool_call>`` 文本
    反而被当成正文发出去。

    ``sink``（2026-10-23 补）：可选字典，回填 ``finish_reason``。以前这里完全
    不看收尾原因，于是 ``length``（撞 max_tokens 被截断）在非流式路径上被渲染
    成 ``stop`` —— 客户端以为回答说完了，截断的工具参数当成完整 JSON 去解析。
    返回值保持五个元素，老调用点不用动。
    """
    content, reasoning, usage, err = "", "", {}, ""
    tool_calls = []
    for line in (text or "").splitlines():
        if not line.startswith("data:"):
            continue
        chunk = line[5:].strip()
        if not chunk or chunk == "[DONE]":
            continue
        try:
            piece = json.loads(chunk)
        except Exception:
            continue
        bad = frame_error(piece)
        if bad:
            err = bad
            continue
        u = frame_usage(piece)
        if u is not None:
            usage = u
        for choice in piece.get("choices") or []:
            if finish_error(choice):
                err = err or "upstream finished with finish_reason=error"
            elif sink is not None and choice.get("finish_reason"):
                # error 已经进了 err，不该同时当成一个正常收尾原因。
                sink["finish_reason"] = choice["finish_reason"]
            delta = choice.get("delta") or {}
            content += delta.get("content") or ""
            reasoning += delta.get("reasoning_content") or ""
            for call in delta.get("tool_calls") or []:
                merge_tool_call(tool_calls, call)
    return content, reasoning, usage, err, tool_calls


def tap_lines(lines, sink, keepalive=None, keepalive_frame=b": keepalive\n\n"):
    """把 usage / 帧内错误顺手记进 ``sink``，再把行原样交给翻译器。

    事件翻译器只负责出事件、不管记账；流式路径没有聚合结果，用量只能在这里捞。

    上游静默产生的 ``keepalive`` 哨兵在这里翻成一条 SSE 注释行：协议允许
    以 ``:`` 开头的噪声，翻译器与客户端都该忽略它。放在这一层而不是每个
    翻译器里，是为了让 Chat / Responses / Messages 三条路共用一个口径。

    **错误帧不交给翻译器**：它抛 ``UpstreamErrorFrame``，调用方据此发本协议
    的错误终态并按失败记账。以前这里只是把错误记进 sink 然后照常喂下去，
    翻译器毫不知情地补了 ``response.completed`` / ``message_stop`` —— 客户端
    看到的就是「半截回答 + 正常结束」。
    """
    for line in lines:
        if keepalive is not None and line is keepalive:
            yield keepalive_frame
            continue
        text = line.decode("utf-8", "replace") if isinstance(line, bytes) else line
        if not isinstance(text, str):
            # 不是文本也不是已登记的哨兵：原样透传，解析不了就别猜。
            yield line
            continue
        stripped = text.strip()
        if stripped.startswith("data:"):
            raw = stripped[5:].strip()
            if raw and raw != "[DONE]":
                try:
                    piece = json.loads(raw)
                except Exception:
                    piece = None
                if isinstance(piece, dict):
                    u = frame_usage(piece)
                    if u is not None:
                        sink["usage"] = u
                    bad = frame_error(piece)
                    if not bad:
                        # **finish_reason=error 也算失败**，而且必须在这里
                        # 拦下来：它不带任何错误码，翻译器只会把它当成一个
                        # 普通的收尾原因，于是 Messages 补 message_stop
                        # （Claude Code 看到 end_turn）、Responses 补
                        # response.completed（Codex 看到 completed）—— 半截
                        # 回答被当成完整结果。Chat 那条路自己判了，这两条没有。
                        for choice in piece.get("choices") or []:
                            if finish_error(choice):
                                bad = "upstream finished with finish_reason=error"
                                break
                    if bad:
                        sink["error"] = bad
                        raise UpstreamErrorFrame(bad)
        yield line


def break_hint(stats):
    """断流时附一句「为什么、该怎么办」，给客户端/agent 看。

    ``silent_s`` 是**一个字节都没到**的时长（SSE 注释也算字节，见
    ``ca_codearts.iter_sse``），不是「没解析出 data 帧」的时长。线上同一条
    请求连撞三次，静默分别是 59.8 / 59.8 / 60.0 秒 —— 这不是随机抖动，而是
    上游（APIG 的「后端超时」，默认 60 s）对**没有输出**的连接按空闲收掉。

    所以这类失败有个很坑的性质：**同一个请求会一直在同一处被切**。客户端
    自动重试时，表现就是「反复回复同一句话」（2026-10-23 15:15–15:18 三次
    同形状请求，各吐 5.4/6.4/7.1 KB 后静默 60 s）。只报
    ``IncompleteRead(0 bytes read)`` 会让上层以为是网络抖动、继续原样重试，
    所以要把「这一轮该拆小」直接写在错误里。
    """
    silent = (stats or {}).get("silent_s") or 0.0
    if silent < 50:
        return ""
    return (" (upstream sent no bytes for %.0fs and was cut by its ~60s idle "
            "limit; the same request fails at the same point, so split this "
            "turn into smaller steps or lower the thinking budget)"
            % silent)


def fail_spec(status, code, detail, anthropic=False):
    """上游失败 → ``(HTTP 状态码, error.type)``。

    这张表照 CodeArts2API-Go 的 ``internal/apierr``（README 里也有一份）：

      | 情况 | 状态码 | OpenAI type | Anthropic type |
      |---|---|---|---|
      | 账号池为空 | 503 | server_error | overloaded_error |
      | **凭据失效（无法续期）** | 502 | **credentials_error** | authentication_error |
      | 上游并发上限 / 429 | 429 | rate_limit_error | rate_limit_error |
      | 参数 / 模型名不合法 | 400 | invalid_request_error | invalid_request_error |
      | 模型不存在 | 404 | invalid_request_error | invalid_request_error |
      | 上游 5xx / 网络 | 502 | upstream_error | overloaded_error |

    关键是**别把「重试没意义」的错报成 502**：以前我们把 max_tokens 超限
    （``InferHub.001001005.400``）也回 502 upstream_error，客户端当成网关抖动
    反复重试同一条错误请求，日志里每次都是同一个 400。
    """
    text = "%s %s" % (code or "", detail or "")
    low = text.lower()
    # 1041 在 HTTP 上是 400，但语义是「等会儿再来」，所以先于参数错判断
    if (status == 429 or "tm.00001041" in low or "modelarts.811" in low
            or "rate limit" in low or "too many requests" in low
            or "并发会话数已达上限" in text):
        return 429, "rate_limit_error"
    # TM.00001054 内容安全拦截：请求本身被审掉了，换号、重试都不会变。以前
    # 落进 502 让客户端当网关抖动重试，同一句话会被反复送审。
    if "00001054" in low or "content moderation" in low or "内容安全" in text:
        return 400, "invalid_request_error"
    # TM.00020005 租户被冻结（账号侧状态，见官方 Kernel 的 tenant frozen 拦截）：
    # 重试同一请求永远不会成，要人去面板续费/解冻。502 只会让它一直退避。
    if "00020005" in low or "tenant frozen" in low:
        return 403, "invalid_request_error"
    if (status in (401, 403) or "apig.0301" in low or "apig.0303" in low
            or "sts5.18" in low or "security token" in low):
        # 只看**明确的凭据错误码**。以前还匹配裸的 "authentication" /
        # "authorization"：5xx 的说明里只要出现 "authentication service
        # unavailable" 这类字样，就会被判成「你的凭据失效了」，把一个上游
        # 故障说成用户要重新登录 —— 客户端于是不会重试，只会提示去重新授权。
        return 502, ("authentication_error" if anthropic else "credentials_error")
    if (status == 404 or "002002009" in low or "model is not registered" in low
            or "model not found" in low or "模型不存在" in text):
        return 404, "invalid_request_error"
    # InferHub.001001020.406 "The request model is not multimodal"：客户端把
    # 图片发给了纯文本模型。这是**请求本身**的问题（换模型就好），回 400；
    # 以前落进 502，客户端当成网关抖动一遍遍重试同一张图。
    if ("001001020" in low or "not multimodal" in low
            or "不支持多模态" in text):
        return 400, "invalid_request_error"
    # InferHub.4004.200 benefit not found：这是**限时福利渠道**的回复 ——
    # 账号没有该模型的权益（没领、领完了、或这个账号本来就不在白名单里）。
    # 它不是网关故障，重试同一条请求也不会变；回 502 只会让客户端反复退避。
    if "4004.200" in low or "benefit not found" in low:
        return 404, "invalid_request_error"
    # APIG.0203 Backend timeout：APIG 等后端等超时了（实测约 60s 一刀）。
    # 这不是网关自己挂了，重试同一条请求只会再等一个 60s —— 回 504，让客户端
    # 看到「上游算太久」而不是一个含糊的 502。
    if "apig.0203" in low or "backend timeout" in low:
        return 504, ("overloaded_error" if anthropic else "upstream_error")
    if (status == 400 or "001001005" in low or "param is invalid" in low
            or "malformed_json" in low):
        # 不再匹配裸的「参数」两个字：错误说明里只要提到「参数」就被判成
        # 400，会让「网关自己重试了 4 轮、最后却告诉客户端是你的请求错了」
        # 这种情况发生。真正该判 400 的是**明确的参数错误码**（001001005）
        # 与上游参数校验失败的原文（param is invalid / malformed_json）。
        return 400, "invalid_request_error"
    return 502, ("overloaded_error" if anthropic else "upstream_error")


def frame_status(text, anthropic=False):
    """帧内错误（HTTP 200 + error_code）→ 该回给客户端的 ``(状态码, type)``。

    上游把很多错误塞在 SSE 帧里而不是 HTTP 状态码上。首帧之前我们还来得及
    回一个真正的状态码，就别一律当 502 —— 客户端靠它决定「等一会儿重试」
    还是「这个请求本身就错了，改了再发」。

    **不要再维护第二张表**：这里以前自己写了一份（只认 1041 和参数错），
    于是「模型不存在」「没有福利权益」这类帧内错误全部落成 502，和
    ``fail_spec`` 的说法不一致。现在统一走那张表 —— 帧内错误拿不到
    HTTP 状态码，就传 200 让 body 去匹配。
    """
    body = str(text or "")
    code, _sep, detail = body.partition(" ")
    return fail_spec(200, code or body, detail or body, anthropic)


def slow_failure(status, text, exc=None):
    """这次失败会不会「耗掉一整个首字节窗口」？

    用来估「再来一轮要多久」。分两类：

      · **快**：1041（并发会话满）、429（TPM / 请求数限流）、参数错、模型
        不存在 —— 上游毫秒级就回，再试一次几乎不花时间。
      · **慢**：5xx、网络异常、APIG.0203 Backend timeout —— 要等满首字节
        超时（实测约 60 秒）。

    以前一律按 60 秒估，于是「已经花了 15 秒」之后连 0.1 秒就返回的 1041
    也不再重试：TPM 退避设计 4 次（5/12/25/40），实际只能用 2 次。
    """
    if exc is not None:
        return True
    body = str(text or "")
    low = body.lower()
    # flow-control 429 是 APIG 毫秒级回的（不是等首字节超时），按快失败估。
    if flow_control_from(body) is not None:
        return False
    if (status == 429 or status in (400, 404)
            or "tm.00001041" in low or "modelarts.811" in low
            or "rate limit" in low or "too many requests" in low
            or "并发会话数已达上限" in body
            or "002002009" in low or "001001005" in low
            or "4004.200" in low or "001001020" in low
            or "00001054" in low or "00020005" in low
            or "param is invalid" in low or "benefit not found" in low):
        return False
    return True


#: 429 flow-control 的八种 type（官方 FCn 表，逆自 kernel）。
FLOW_CONTROL_TYPES = ("RPM", "RPH", "RP6H", "RPD", "TPM", "TPH", "TP6H", "TPD")
#: 官方 ``h_()``：只有**分钟级**（RPM=请求数 / TPM=token 数）值得退避重试；
#: 小时/日配额重试也不会变，官方直接终止并展示配额文案。
FLOW_CONTROL_RETRYABLE = ("RPM", "TPM")
#: 官方限流 FAQ（codeartsagent_faq_0015）口径：额度按「用户 × 模型」独立
#: 计算，5 小时 / 7 天滑动窗口，恢复是**滑动释放**（整点滑出最早 1 小时、
#: 每日零点滑出最早 1 天，所以是「陆续恢复」）；官方对超限的第一推荐就是
#: 「切换其他模型」—— 不同模型额度独立，立即恢复。降级链正是这条建议的
#: 自动化。补一句恢复语义到客户端错误里，比干等有方向。
FLOW_CONTROL_HINT = (" (per-model sliding-window quota: switch to another "
                     "model for immediate capacity, or wait - it recovers "
                     "gradually as old usage slides out of the window)")
#: 官方 kernel UK map 的中文文案（一字不差；TPD 的 ``{quota}`` 运行时替换）。
#: 注意这是 kernel 侧的口径 —— extension.js 的 FU map 里 RP6H 的 l10n key
#: 与英文值对不上（官方自己的 bug，中文环境会显示英文），别抄那份。
FLOW_CONTROL_MESSAGES = {
    "RPM": "您最近的操作有点快哦⚡️系统需要喘口气，请稍等几秒后重试😊",
    "RPH": "您本小时的额度已用完 ⏰ 我先去充个电，一小时后满格归来！🔋",
    "RP6H": "这6小时的额度已用完 ⏰ 我先去充个电，6小时后满格归来！🔋",
    "RPD": "今天的额度已经用完啦 🌙 辛苦了一天！明天额度刷新后我们再继续 ✨",
    "TPM": "信息量有点大哦 📚 我需要缓一缓，请稍等片刻再试～ ✨",
    "TPH": "这一小时咱们聊得真尽兴！🎉 我的小脑袋需要休息一下，一小时后满血回归！💡",
    "TP6H": "这段时间咱们聊得真充实！🎉 我需要休息一下，6小时后满血回归！💡",
    "TPD": ("您的请求消耗Token过快，已达每日{quota} Token上限，请24:00点后"
            "再试，或切换模型以继续。"),
}


def flow_control_from(text):
    """429 错误体 → flow-control 信息（type/quota/used）；不是则返回 None。

    服务端把 ``{"type","message","identity","quota","used"}`` 作为 **JSON
    字符串**塞在 ``error_msg`` 里（官方解析函数 ``i0()``），兼容 ``error``
    包一层与顶层两种包裹。type 不在官方八种之列的一律不当 flow-control。
    """
    body = str(text or "")
    candidates = []
    try:
        whole = json.loads(body)
    except Exception:
        whole = None
    if isinstance(whole, dict):
        # 官方 zod schema（ACn）兼容两种包裹：顶层 {error_code,error_msg} 与
        # {error:{error_code,error_msg}} —— error_detail 只认前者，这里自己认全。
        for holder in (whole, whole.get("error")):
            if isinstance(holder, dict):
                msg = holder.get("error_msg") or holder.get("message")
                if isinstance(msg, str):
                    candidates.append(msg)
    code, msg = error_detail(body)
    candidates.extend(x for x in (msg, body) if x)
    for candidate in candidates:
        if not candidate:
            continue
        try:
            data = json.loads(candidate)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        kind = str(data.get("type") or "")
        if kind in FLOW_CONTROL_TYPES:
            return {
                "type": kind,
                "quota": (data.get("quota")
                          if isinstance(data.get("quota"), (int, float)) else 0),
                "used": (data.get("used")
                         if isinstance(data.get("used"), (int, float)) else 0),
            }
    return None


def flow_control_message(info):
    """flow-control 信息 → 官方中文文案（TPD 的 {quota} 已替换）。"""
    text = FLOW_CONTROL_MESSAGES.get((info or {}).get("type")) or ""
    text = text.replace("{quota}", str(int((info or {}).get("quota") or 0)))
    # 日级配额（RPD/TPD）补滑动窗口的恢复语义；分钟级加等待即可。
    if (info or {}).get("type") in ("RPD", "TPD", "RPH", "TPH", "RP6H", "TP6H"):
        text += FLOW_CONTROL_HINT
    return text


def retryable(status, text):
    """这个失败值得等一下重试吗？

    码道有两种**瞬时限流**，看起来像「模型不可用」其实不是：
      · 429 ModelArts.81111 / 81114  —— TPM 打满（日额度 1000 万，瞬时限流）
      · 400 TM.00001041              —— 并发会话数已达上限（账号只给 3 个，
                                        上一个请求还没从上游释放就会撞上）
    网关连着发几个请求必然撞第二种，所以必须自己退避重试，
    否则用户侧看到的是「这个模型坏了」。

    **429 的 flow-control 分流**（官方 ``h_()``，2026-10-24 逆向）：APIG 层的
    429 把 ``{"type":RPM..TPD,...}`` 塞在 error_msg 里，只有**分钟级**的
    RPM/TPM 值得退避重试；小时/日配额（RPH/RP6H/RPD/TPH/TP6H/TPD）重试一
    万次也不会变，官方直接终止并展示配额文案。
    """
    fc = flow_control_from(text)
    if fc is not None and fc["type"] not in FLOW_CONTROL_RETRYABLE:
        return False
    if status == 429:
        return True
    body = text or ""
    # 这两类是**确定性拒绝**：再试一次还是同样的结果，重试只是白等。
    if ("00001054" in body or "00020005" in body
            or "tenant frozen" in body.lower()):
        return False
    if status and status >= 500:
        return True
    return ("TM.00001041" in body or "ModelArts.811" in body
            or "rate limit" in body.lower()
            or "too many requests" in body.lower()
            or "并发会话数已达上限" in body)


def concurrency_full(status, text):
    """这一发是不是撞了「账号并发会话已满」（TM.00001041）？

    单独认这个码，是因为它该用**短退避**：名额在别人（或上一轮没释放的会话）
    手里，通常几秒就让出来；按通用限流的 5/12/25/40 退避，82 秒全花在等一个
    早就没人要的答案上，客户端早就自己重试了。
    """
    body = text or ""
    return ("TM.00001041" in body or "并发会话数已达上限" in body)


def server_retry_after(text):
    """从错误文本里读出 open_chat 附加的服务端退避提示（秒）；没有返回 0。

    open_chat 在 429/503 的响应头里有 ``retry-after-ms``（毫秒）或
    ``retry-after``（秒）时，把它折算成秒并追加 ``[server-retry-after: Ns]``
    标记 —— 官方 rS 策略的读取顺序就是 ms 头优先、秒头次之；服务端说等多
    久比我们猜的 5/12/25/40 靠谱，取较大者用。
    """
    body = str(text or "")
    if "server-retry-after" not in body:
        return 0.0
    cut = body.rfind("[server-retry-after: ")
    if cut < 0:
        return 0.0
    tail = body[cut + len("[server-retry-after: "):]
    end = tail.find("s]")
    try:
        return float(tail[:end]) if end > 0 else 0.0
    except ValueError:
        return 0.0


def error_detail(text):
    """从码道的错误体里抠出 (错误码, 人能看的说明)。"""
    try:
        d = json.loads(text or "")
        detail = (d.get("error_msg") or d.get("message")
                  or (d.get("error") or {}).get("message") or "")
        code = (d.get("error_code")
                or (d.get("error") or {}).get("code") or "")
        return str(code), str(detail)
    except Exception:
        return "", (text or "")[:200]

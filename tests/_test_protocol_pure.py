# -*- coding: utf-8 -*-
"""ca_protocol 的纯层测试：只 import 它，不 import ca_proxy。

这是「协议层搬干净了」的硬证明——如果哪天有人把 socket、settings、日志
塞回 ca_protocol，这里会先红，而不是等到起服务器才发现。

    python tests/_test_protocol_pure.py
"""

import builtins
import json
import os
import symtable
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_protocol as Q  # noqa: E402

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


section("1. 只 import ca_protocol 也能跑（没有 ca_proxy 依赖）")
check("ca_proxy 没被顺手拉进来", "ca_proxy" not in sys.modules, sorted(sys.modules)[:0])
check("模块来源就是 ca_protocol.py", Q.__file__.endswith("ca_protocol.py"), Q.__file__)

_src = open(Q.__file__, encoding="utf-8").read()
_code = Q.re.sub(r'""".*?"""', "", _src, flags=Q.re.S) if hasattr(Q, "re") else _src
check("没有 import socket", "import socket" not in _src, None)
check("没有 open( / self.wfile", "open(" not in _code and "self.wfile" not in _code, None)
check("没有 log(（不许往日志里写）", "log(" not in _code and "logging" not in _code, None)
check("没有读 settings / 账号目录",
      "ca_settings" not in _code and "ACCOUNTS_DIR" not in _code, None)
_imports = set(Q.re.findall(r"^(?:import|from)\s+([\w.]+)", _code, Q.re.M))
check("只依赖 json / re / time / uuid 四个标准库模块",
      _imports <= {"json", "re", "time", "uuid"}, sorted(_imports))


section("2. 帧层")
_frame = Q.anthropic_sse_frame("content_block_delta",
                               {"index": 0, "delta": {"type": "text_delta", "text": "你好"}})
check("帧形状 event + data + 空行",
      _frame.startswith(b"event: content_block_delta\ndata: {") and _frame.endswith(b"}\n\n"),
      _frame[:48])
check("中文不转义", "你好".encode("utf-8") in _frame, None)
check("payload 的 type 被事件名覆盖",
      b'"type":"content_block_delta"' in _frame, _frame)
check("空 payload 也能出帧",
      Q.anthropic_sse_frame("ping", None) == b'event: ping\ndata: {"type":"ping"}\n\n', None)
check("stop_reason 映射：length/tool_calls/content_filter/未知",
      Q.anthropic_stop_reason("length") == "max_tokens"
      and Q.anthropic_stop_reason("tool_calls") == "tool_use"
      and Q.anthropic_stop_reason("content_filter") == "refusal"
      and Q.anthropic_stop_reason("whatever") == "end_turn", None)


section("3. 归一与清洗")
check("文本归一", (Q.anthropic_text(None), Q.anthropic_text("a"), Q.anthropic_text(3))
      == ("", "a", "3"), None)
check("角色归一 developer→system 且不动原对象",
      (lambda m: Q.normalize_roles(m)[0] is not m[0]
       and Q.normalize_roles(m)[0]["role"] == "system")(
          [{"role": "developer", "content": "x"}]), None)
_obj = {"function_call": {}, "tool_calls": [], "keep": 1}
check("空 function_call / tool_calls 被剔除且就地修改",
      Q.strip_empty_function_calls(_obj) is True and _obj == {"keep": 1}, _obj)
check("Responses 帧清洗保留 [DONE] 与坏 JSON",
      Q.clean_responses_frame(b"data: [DONE]\n\n") == b"data: [DONE]\n\n", None)
_dirty = Q.clean_responses_frame(
    b'event: response.output_item.added\n'
    b'data: {"item":{"type":"function_call","call_id":"","name":"","arguments":""}}\n\n')
check("清洗后的帧只留一个空行结尾（以前会多一个 \\n）",
      _dirty.endswith(b"}\n\n") and not _dirty.endswith(b"\n\n\n"), _dirty[-20:])
check("清洗不改 event: 行",
      _dirty.startswith(b"event: response.output_item.added\n"), _dirty[:40])

check("空对话/只有 system 会被拦下",
      Q.empty_conversation_error([]) is not None
      and Q.empty_conversation_error([{"role": "system", "content": "x"}]) is not None
      and Q.empty_conversation_error(
          [{"role": "developer", "content": "x"}]) is not None, None)
check("有一轮 user / assistant / tool 就放行",
      Q.empty_conversation_error([{"role": "system", "content": "x"},
                                  {"role": "user", "content": "hi"}]) is None
      and Q.empty_conversation_error([{"role": "assistant", "content": "a"}]) is None
      and Q.empty_conversation_error([{"role": "tool", "content": "t"}]) is None, None)
check("messages 不是列表时不在这里判（交给上游）",
      Q.empty_conversation_error(None) is None
      and Q.empty_conversation_error("x") is None, None)


section("4. 用量映射")
_u = Q.anthropic_usage({"prompt_tokens": 10, "completion_tokens": 3,
                        "prompt_tokens_details": {"cached_tokens": 7}})
check("Anthropic 口径字段齐全",
      # input_tokens 是「新读入」的部分：OpenAI 的 prompt_tokens 含缓存，
      # Anthropic 的 input_tokens 不含（缓存另列）。10 - 7 = 3。
      _u == {"input_tokens": 3, "output_tokens": 3,
             "cache_creation_input_tokens": 0, "cache_read_input_tokens": 7}, _u)
check("没有缓存计数时 input_tokens 原样照搬（不会把输入抹成 0）",
      Q.anthropic_usage({"prompt_tokens": 10, "completion_tokens": 3})["input_tokens"]
      == 10, None)
check("非 dict 用量给全零", Q.anthropic_usage(None)["input_tokens"] == 0, None)
check("缓存命中取值优先级（首个正数胜出）",
      Q.best_cached_tokens({"prompt_cache_hit_tokens": 2,
                            "prompt_tokens_details": {"cached_tokens": 5}}) == 5
      and Q.best_cached_tokens({"cached_tokens": 0, "prompt_cache_hit_tokens": 3}) == 3, None)
_r = Q.responses_usage({"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6})
check("Responses 口径字段齐全",
      _r["input_tokens"] == 4 and _r["output_tokens"] == 2
      and _r["output_tokens_details"] == {"reasoning_tokens": 0}, _r)


section("5. 请求翻译")
_chat = Q.messages_to_chat({"model": "m", "max_tokens": 8,
                            "system": [{"text": "a"}, {"text": "b"}],
                            "messages": [{"role": "user", "content": "hi"}]})
check("system 多段拼成一条", _chat["messages"][0] == {"role": "system", "content": "a\nb"},
      _chat["messages"][0] if _chat["messages"] else None)
check("不传默认值时不补 max_tokens",
      "max_tokens" not in Q.messages_to_chat(
          {"model": "m", "messages": [{"role": "user", "content": "hi"}]}), None)
check("注入默认值的写法生效",
      Q.messages_to_chat({"model": "m", "messages": [{"role": "user", "content": "hi"}]},
                         default_max_tokens=lambda _m: 123)["max_tokens"] == 123, None)
try:
    Q.messages_to_chat({"model": "m", "messages": [{"role": "robot", "content": "x"}]})
    check("非法 role 抛 ValueError", False)
except ValueError as exc:
    check("非法 role 抛 ValueError 且带下标", "messages[0].role" in str(exc), exc)

_msg = Q.chat_to_messages({"id": "c1", "model": "m",
                           "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
check("非流式回包骨架", _msg["type"] == "message" and _msg["content"] == [{"type": "text", "text": "hi"}]
      and _msg["stop_reason"] == "end_turn" and _msg["id"].startswith("msg_"), _msg)


section("6. SSE 读取")
class _R:
    def __init__(self, pieces):
        self.pieces = list(pieces)

    def read1(self, _n):
        return self.pieces.pop(0) if self.pieces else b""


_lines = list(Q.iter_sse_lines(_R([b'data: {"a":1}\n\ndata: {"b', b'":2}\n\ndata: [DONE]\n\n'])))
check("跨块断行接得上、空行照旧产出",
      _lines == [b'data: {"a":1}\n', b"\n", b'data: {"b":2}\n', b"\n",
                 b"data: [DONE]\n", b"\n"], _lines)
check("strip_data_prefix：data:/注释/双重前缀",
      Q.strip_data_prefix("data: {}") == "{}"
      and Q.strip_data_prefix(": ping") == ""
      and Q.strip_data_prefix("data: data: {}") == "{}", None)


section("7. 其它纯工具")
_calls, _clean = Q.parse_dsml_tool_calls(
    'A<|DSML|function_calls><|DSML|invoke name="f">'
    '<|DSML|parameter name="p">v</|DSML|parameter>'
    "</|DSML|invoke></|DSML|function_calls>B")
check("DSML 解析 + 正文清洗",
      _calls and _calls[0]["name"] == "f"
      and json.loads(_calls[0]["arguments"]) == {"p": "v"} and _clean == "A B", (_calls, _clean))
check("estimate_tokens", (Q.estimate_tokens(""), Q.estimate_tokens("中文"),
                          Q.estimate_tokens("abcdefghij")) == (0, 3, 2), None)
check("build_citations 只认来源里出现过的 URL",
      len(Q.build_citations("见 https://a/x", [{"url": "https://a/x"}])) == 1
      and Q.build_citations("https://nope", [{"url": "https://a/x"}]) == [], None)
check("namespace 还原", Q.resolve_namespaced_name("weather__get", {"get": "weather"})
      == ("get", "weather"), None)

check("stop 串只认结尾命中的那条（多命中取最长）",
      Q.matched_stop_sequence("abcEND", ["END", "D"]) == "END"
      and Q.matched_stop_sequence("abcXYZ", ["END"]) is None
      and Q.matched_stop_sequence("", ["END"]) is None
      and Q.matched_stop_sequence("abcEND", None) is None, None)

_ms_stop = Q.chat_to_messages({
    "id": "chatcmpl-1", "model": "m",
    "choices": [{"message": {"content": "结果：STOP"}, "finish_reason": "stop"}],
}, stop_sequences=["STOP"])
check("非流式回包回填 stop_sequence",
      _ms_stop["stop_sequence"] == "STOP"
      and _ms_stop["stop_reason"] == "end_turn", _ms_stop)
_ms_tool = Q.chat_to_messages({
    "choices": [{"message": {"content": "STOP", "tool_calls": [
        {"id": "c1", "function": {"name": "f", "arguments": "{}"}}]},
        "finish_reason": "tool_calls"}],
}, stop_sequences=["STOP"])
check("工具调用收尾不填 stop_sequence", _ms_tool["stop_sequence"] is None, _ms_tool)
_ms_plain = Q.chat_to_messages({"choices": [{"message": {"content": "STOP"},
                                            "finish_reason": "stop"}]})
check("不给 stop 列表时保持 null（旧调用方零改动）",
      _ms_plain["stop_sequence"] is None, _ms_plain)


section("8. 静态卫生：没有「用了但没定义/没 import」的名字")
_st = symtable.symtable(_src, Q.__file__, "exec")
_mod = {s.get_name() for s in _st.get_symbols()
        if s.is_assigned() or s.is_imported() or s.is_namespace()}
_bad = []


def _walk(table):
    for sym in table.get_symbols():
        if sym.is_global() and sym.get_name() not in _mod \
                and not hasattr(builtins, sym.get_name()):
            _bad.append((table.get_name(), sym.get_name()))
    for child in table.get_children():
        _walk(child)


_walk(_st)
check("没有未定义的全局引用", not _bad, _bad)

print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

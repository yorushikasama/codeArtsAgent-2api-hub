"""Deterministic tests for the three upstream-request repairs.

No network and no upstream account needed: the functions under test are pure
body transformations, so each case feeds a synthetic request and asserts the
shape that leaves for the upstream.

  1. deepseek thinking + effort  - thinking.type alone does not enable the trace
  2. tool-call pairing repair    - orphaned calls / split results kill a session
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _isolated_dirs import isolated_data_dirs  # noqa: E402  (its own data root)
# Its own directories, removed when this process exits. The suite used to point
# both at tests/_acc and tests/_use, which it shared with
# _test_namespace_tools.py, and every run left those directories in the checkout.
_TMP = isolated_data_dirs("wb-upstream-repairs-")

import ca_proxy as P
import ca_protocol as Q

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def assistant_with_calls(*ids):
    return {"role": "assistant", "content": "",
            "tool_calls": [{"id": i, "type": "function",
                            "function": {"name": "f", "arguments": "{}"}} for i in ids]}


def tool_result(tid):
    return {"role": "tool", "tool_call_id": tid, "content": "ok"}


print("[2] deepseek thinking 注入：随 WorkBuddy 路径退役，码道路径经")
print("    ca_codearts.thinking_extra_from 的档位白名单——行为由")
print("    _test_codearts.py 的 thinking_extra_from 映射表覆盖。")

print("[3] tool pairing: repack results, drop orphans")

split = [{"role": "user", "content": "go"},
         assistant_with_calls("c0", "c1"),
         tool_result("c0"),
         {"role": "developer", "content": "<image_resize_notice>"},
         tool_result("c1")]
fixed, changed = P.repack_tool_result_blocks(copy.deepcopy(split))
check("an interleaved message is reported as a change", changed)
check("results are now adjacent",
      [m.get("role") for m in fixed[1:5]] == ["assistant", "tool", "tool", "developer"],
      [m.get("role") for m in fixed[1:5]])
check("result order is preserved",
      [m.get("tool_call_id") for m in fixed if m.get("role") == "tool"] == ["c0", "c1"])
check("the intruder is kept, only moved",
      any(m.get("content") == "<image_resize_notice>" for m in fixed))

adjacent = [{"role": "user", "content": "go"},
            assistant_with_calls("c0"),
            tool_result("c0")]
unchanged, changed2 = P.repack_tool_result_blocks(copy.deepcopy(adjacent))
check("an already-correct batch is left alone", not changed2)
check("and returned as the same object", unchanged is not None)

two_batches = [assistant_with_calls("a0"),
               tool_result("a0"),
               assistant_with_calls("b0"),
               tool_result("b0")]
kept_batches, changed3 = P.repack_tool_result_blocks(copy.deepcopy(two_batches))
check("a second batch is not swallowed as an intruder", not changed3)
check("both batches survive",
      len([m for m in kept_batches if m.get("role") == "assistant"]) == 2)

orphan_call = [{"role": "user", "content": "go"},
               assistant_with_calls("c0", "c1"),
               tool_result("c0")]
cleaned, changed4 = P.cleanup_orphan_tool_calls(copy.deepcopy(orphan_call))
check("an unanswered call is reported as a change", changed4)
check("the unanswered call is dropped",
      [tc["id"] for tc in cleaned[1]["tool_calls"]] == ["c0"],
      cleaned[1].get("tool_calls"))
check("the answered call survives", cleaned[2]["tool_call_id"] == "c0")

orphan_result = [{"role": "user", "content": "go"},
                 {"role": "assistant", "content": "done"},
                 tool_result("ghost")]
cleaned2, changed5 = P.cleanup_orphan_tool_calls(copy.deepcopy(orphan_result))
check("a result with no call is reported as a change", changed5)
check("the orphan result is removed",
      [m.get("role") for m in cleaned2] == ["user", "assistant"],
      [m.get("role") for m in cleaned2])

all_orphan = [{"role": "user", "content": "go"},
              assistant_with_calls("c0"),
              {"role": "user", "content": "next"}]
cleaned3, changed6 = P.cleanup_orphan_tool_calls(copy.deepcopy(all_orphan))
check("a fully unanswered batch is reported as a change", changed6)
check("the empty tool_calls key is removed entirely",
      "tool_calls" not in cleaned3[1], cleaned3[1])
check("the rest of the conversation is intact", len(cleaned3) == 3)

no_tools = [{"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"}]
cleaned4, changed7 = P.cleanup_orphan_tool_calls(copy.deepcopy(no_tools))
check("a tool-free conversation is untouched", not changed7)
check("and keeps its length", len(cleaned4) == 2)

print()
print("[3b] split parallel batches merge; truncated arguments are dropped")

split_batch = [{"role": "user", "content": "go"},
               assistant_with_calls("c0"),
               assistant_with_calls("c1"),
               tool_result("c0"),
               tool_result("c1")]
merged, changed8 = P.merge_adjacent_tool_calls(copy.deepcopy(split_batch))
check("back-to-back tool_calls batches are reported as a change", changed8)
check("both calls now ride on one assistant",
      [tc["id"] for tc in merged[1].get("tool_calls", [])] == ["c0", "c1"],
      merged[1].get("tool_calls"))
check("the duplicate assistant is gone",
      len([m for m in merged if m.get("role") == "assistant"]) == 1)

empty_array = [assistant_with_calls("c0"),
               {"role": "assistant", "content": [],
                "tool_calls": assistant_with_calls("c1")["tool_calls"]},
               tool_result("c0"),
               tool_result("c1")]
merged_arr, changed9 = P.merge_adjacent_tool_calls(copy.deepcopy(empty_array))
check("content: [] counts as empty and merges", changed9)
check("empty-array batch keeps both calls",
      [tc["id"] for tc in merged_arr[0].get("tool_calls", [])] == ["c0", "c1"])

reasoned = [{"role": "assistant", "content": None, "reasoning_content": "first",
             "tool_calls": assistant_with_calls("c0")["tool_calls"]},
            {"role": "assistant", "content": "",
             "reasoning_content": "second",
             "tool_calls": assistant_with_calls("c1")["tool_calls"]}]
merged_r, changed10 = P.merge_adjacent_tool_calls(copy.deepcopy(reasoned))
check("reasoning traces are preserved on merge",
      merged_r[0].get("reasoning_content") == "first\nsecond",
      merged_r[0].get("reasoning_content"))

text_then_calls = [{"role": "assistant", "content": "",
                    "tool_calls": assistant_with_calls("c0")["tool_calls"]},
                   {"role": "assistant", "content": "done"}]
merged_t, changed11 = P.merge_adjacent_tool_calls(copy.deepcopy(text_then_calls))
check("a trailing plain assistant folds into the content-less call message",
      changed11 and merged_t[0].get("content") == "done" and len(merged_t) == 1)

not_empty = [assistant_with_calls("c0"),
             {"role": "assistant", "content": "kept",
              "tool_calls": assistant_with_calls("c1")["tool_calls"]}]
_, changed12 = P.merge_adjacent_tool_calls(copy.deepcopy(not_empty))
check("a trailing batch with real content is not merged", not changed12)

separated = [assistant_with_calls("c0"),
             {"role": "user", "content": "hi"},
             assistant_with_calls("c1")]
_, changed13 = P.merge_adjacent_tool_calls(copy.deepcopy(separated))
check("non-adjacent batches are never merged", not changed13)

check("an empty string is a legal no-argument call",
      not Q.is_truncated_arguments(""))
check("whitespace is a legal no-argument call",
      not Q.is_truncated_arguments("   "))
check("valid JSON object is complete", not Q.is_truncated_arguments('{"a":1}'))
check("valid JSON scalar is complete", not Q.is_truncated_arguments("null"))
check("half-written JSON is truncated", Q.is_truncated_arguments('{"a":'))
check("plain text is not silently accepted", Q.is_truncated_arguments("not json"))

def sse_line(obj):
    return ("data: " + json.dumps(obj) + "\n\n").encode("utf-8")


resp_stream = [
    sse_line({"choices": [{"delta": {"tool_calls": [
        {"index": 0, "id": "call_r", "function": {"name": "f",
                                                  "arguments": '{"a":'}}]},
        "finish_reason": "tool_calls"}]}),
]
resp_raw = b"".join(P.stream_responses_events(
    iter(resp_stream), "m", {"usage": None})).decode("utf-8")
check("stream_responses_events drops the truncated done event",
      "function_call_arguments.done" not in resp_raw, resp_raw[-400:])
check("stream_responses_events marks the response incomplete",
      '"status": "incomplete"' in resp_raw)

print()
print("[4] integration: repair_messages_for_upstream applies the repairs（build_upstream_body 退役后）")

broken_msgs = [{"role": "user", "content": "go"},
               assistant_with_calls("c0", "c1"),
               tool_result("c0")]
built = P.repair_messages_for_upstream([dict(m) for m in broken_msgs],
                                       "deepseek-v4.1-flash")
check("the orphaned call is gone from the outbound messages",
      [tc["id"] for tc in built[1]["tool_calls"]] == ["c0"],
      built[1].get("tool_calls"))
check("the caller's payload is not mutated",
      len(broken_msgs[1]["tool_calls"]) == 2)

split_msgs = [{"role": "user", "content": "go"},
              assistant_with_calls("c0"),
              assistant_with_calls("c1"),
              tool_result("c0"),
              tool_result("c1")]
built_split = P.repair_messages_for_upstream([dict(m) for m in split_msgs],
                                             "deepseek-v4.1-flash")
split_assistants = [m for m in built_split if m.get("role") == "assistant"]
check("a split parallel batch leaves as one assistant",
      len(split_assistants) == 1, len(split_assistants))
check("both calls survive the merge",
      [tc["id"] for tc in split_assistants[0].get("tool_calls", [])] == ["c0", "c1"],
      split_assistants[0].get("tool_calls"))

print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

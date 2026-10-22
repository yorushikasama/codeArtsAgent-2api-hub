# -*- coding: utf-8 -*-
"""协议层的逐字节 golden：同一串上游 delta 必须产出同一串 SSE 帧。

为什么单独一个套件：`_test_protocol_pure.py` 管「函数能算对」，这里管
「帧序列没变」。Codex CLI / Claude Code 对事件顺序很敏感，而顺序这种东西
用断言一条条写既写不全、也看不出差异 —— 存一份 golden，改完一 diff 就知道。

golden 只在**确认行为变化是想要的**时重录：

    python tests/record_protocol_golden.py

其它时候对拍失败就是回归，别改 golden 去迁就代码。
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _golden_cases as G  # noqa: E402

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


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def first_diff(want_frames, got_frames):
    """给出一条能直接贴进 issue 的差异说明。"""
    for i in range(max(len(want_frames), len(got_frames))):
        want = want_frames[i] if i < len(want_frames) else "<缺少这一帧>"
        got = got_frames[i] if i < len(got_frames) else "<多出这一帧>"
        if want != got:
            return i, want, got
    return None


def compare(protocol, golden_path, got_cases):
    if not os.path.exists(golden_path):
        check("%s：golden 存在" % protocol, False,
              "%s 不存在；先跑 tests/record_protocol_golden.py" % golden_path)
        return
    want_cases = load(golden_path)
    check("%s：场景数一致" % protocol, len(want_cases) == len(got_cases),
          "golden %d / 现在 %d" % (len(want_cases), len(got_cases)))
    check("%s：golden 不是空壳" % protocol,
          bool(want_cases) and all(c.get("frames") for c in want_cases),
          [c.get("name") for c in want_cases if not c.get("frames")])
    by_name = {c["name"]: c for c in want_cases}
    for case in got_cases:
        want = by_name.get(case["name"])
        if want is None:
            check("%s / %s：golden 里有这个场景" % (protocol, case["name"]),
                  False, "新增场景请重录 golden")
            continue
        diff = first_diff(want["frames"], case["frames"])
        if diff is None:
            check("%s / %s（%d 帧）" % (protocol, case["name"], len(case["frames"])),
                  True)
            continue
        idx, w, g = diff
        check("%s / %s：帧序列逐字节一致" % (protocol, case["name"]), False,
              "\n    第 %d 帧\n    golden: %r\n    现在:   %r"
              % (idx, w[:400], g[:400]))


section("1. Anthropic Messages 帧序列")
_got = G.collect()
compare("anthropic", G.ANTHROPIC_GOLDEN, _got["anthropic"])

section("2. Responses 事件序列")
compare("responses", G.RESPONSES_GOLDEN, _got["responses"])

section("3. 采集本身是确定性的")
# 如果哪天有人在 ca_protocol 里加了未打桩的随机/时钟，这里先红：
# 否则 golden 会变成「每次都不一样」，维护者只会重录了事。
_again = G.collect()
check("连跑两次结果完全相同", _again == _got, None)
_blob = "".join(f for c in _got["responses"] for f in c["frames"])
check("id 已打桩（形如 resp_0006，不是 32 位 uuid）",
      bool(re.search(r'"id": "resp_\d{4}"', _blob))
      and not re.search(r'"resp_[0-9a-f]{32}"', _blob), None)

print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

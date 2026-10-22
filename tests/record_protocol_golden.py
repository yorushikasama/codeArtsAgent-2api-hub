# -*- coding: utf-8 -*-
"""重新录制协议层 golden（只有「行为变化是想要的」时才跑）。

    python tests/record_protocol_golden.py            # 两个协议都重录
    python tests/record_protocol_golden.py anthropic  # 只重录一个

录完必须 review ``git diff tests/golden/``：它应该只反映你有意改的那几帧。
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import _golden_cases as G  # noqa: E402


def write(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    cases = len(payload)
    frames = sum(len(c["frames"]) for c in payload)
    print("wrote %-42s %d 个场景 / %d 帧" % (os.path.basename(path), cases, frames))


def main(argv):
    which = set(a.lower() for a in argv[1:]) or {"anthropic", "responses"}
    data = G.collect()
    if "anthropic" in which:
        write(G.ANTHROPIC_GOLDEN, data["anthropic"])
    if "responses" in which:
        write(G.RESPONSES_GOLDEN, data["responses"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

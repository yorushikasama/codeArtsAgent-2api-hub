#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性迁移：usage.jsonl 里的历史模型名归一成上游真名。

背景（2026-10-25）：入口归一上线之前，客户端大小写混写（GLM-5.3 / glm /
GLM-5.2）把按模型的统计、限额、降级链打散成多个桶。看板历史要合并成
一个模型一个桶，就把历史行的 model 字段也过一遍 resolve_model。

行为：
  · 只改 ``model`` 字段，行的顺序与其他字段逐字保留；
  · 先备份为 usage.jsonl.bak-modelnorm-<时间戳>；
  · 认不出的名字原样保留（resolve_model 契约：不编近似名）；
  · 幂等：重跑不会再改任何行。

用法（在仓库根目录）：
  python3 scripts/normalize_usage_models.py            # 实际执行
  python3 scripts/normalize_usage_models.py --dry-run  # 只看会改什么
可加 --file <path> 指定别的 usage.jsonl（默认 <repo>/usage/usage.jsonl）。
"""
import argparse
import collections
import os
import shutil
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import ca_codearts  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=os.path.join(REPO, "usage", "usage.jsonl"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    path = args.file
    if not os.path.isfile(path):
        print("no usage file at %s" % path)
        return 1

    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            rows.append(line)

    import json
    before = collections.Counter()
    after = collections.Counter()
    changed = 0
    out_lines = []
    for line in rows:
        try:
            row = json.loads(line)
        except ValueError:
            out_lines.append(line)          # 坏行原样保留，不做裁判
            continue
        old = row.get("model")
        new = ca_codearts.resolve_model(old)
        before[str(old)] += 1
        after[str(new)] += 1
        if new != old:
            row["model"] = new
            changed += 1
            out_lines.append(json.dumps(row, ensure_ascii=False) + "\n")
        else:
            out_lines.append(line)          # 未动的行保留原始字节

    print("rows: %d  changed: %d" % (len(rows), changed))
    for name in sorted(set(before) | set(after), key=lambda n: -after[n]):
        mark = "" if before[name] == after[name] else \
            "  (%d -> %d)" % (before[name], after[name])
        print("  %-28s %d%s" % (name, after[name], mark))

    if args.dry_run or not changed:
        print("dry-run" if args.dry_run else "nothing to change")
        return 0

    backup = "%s.bak-modelnorm-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.writelines(out_lines)
    print("backup: %s" % backup)
    return 0


if __name__ == "__main__":
    sys.exit(main())

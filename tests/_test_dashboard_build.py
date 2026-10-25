"""dashboard.html is exactly the concatenation of dashboard_src/, byte for byte.

The 10k-line page now lives as 11 fragments; the served file is built from
them by scripts/build_dashboard.py with no transform. This suite is the
no-drift guarantee: edit a fragment without rebuilding (or rebuild without
committing) and the suite fails, naming the side that moved.

It also pins the hygiene the build depends on: fragment names are unique and
order-carrying (numeric prefixes sort before any letter), no fragment is
empty, and the rebuilt bytes contain the landmarks that say the boundaries
were chosen at element edges rather than mid-tag.

    python tests/_test_dashboard_build.py
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "dashboard_src")
OUT = os.path.join(ROOT, "dashboard.html")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import build_dashboard as BD  # noqa: E402

PASS = 0
FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s  %s" % (label, extra))


names = sorted(n for n in os.listdir(SRC) if not n.startswith("."))

print("1. 片段卫生")
check("片段数与预期一致（增删片段要同步 build_dashboard.py 的文档）",
      len(names) == 11, names)
check("片段名唯一且非空", len(set(names)) == len(names)
      and all(os.path.getsize(os.path.join(SRC, n)) > 0 for n in names), None)
check("数字前缀排序即文档顺序（不能出现字母开头混排）",
      all(n[0].isdigit() for n in names), names)

print("2. 构建产物 == 片段拼接（字节级）")
data, _ = BD.built_bytes()
with open(OUT, "rb") as f:
    current = f.read()
check("逐字节相等", current == data,
      "built=%d committed=%d" % (len(data), len(current)))

print("3. 拼回的页面含全部元素边界（切缝在元素边缘，不在标签中间）")
for landmark in (b"<style>", b"</style>", b"<body>", b"</body>",
                 b"</html>", b"__WB_UI_LANGUAGE__"):
    check("含 %s" % landmark.decode("ascii", "replace"),
          landmark in data, None)
check("script 开闭标签数量成对",
      data.count(b"<script>") == data.count(b"</script>"),
      (data.count(b"<script>"), data.count(b"</script>")))

print("4. 行数守恒（拼回的行数 == 各片段行数之和）")
total = 0
for name in names:
    with io.open(os.path.join(SRC, name), "rb") as f:
        total += f.read().count(b"\n")
check("行数守恒", data.count(b"\n") == total,
      (data.count(b"\n"), total))

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

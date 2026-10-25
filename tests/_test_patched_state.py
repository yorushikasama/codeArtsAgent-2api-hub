"""`patched_state` swaps module globals and hands the originals back.

The hand-written pattern it replaces is two lines that must stay in step:

    _saved = P.ACCOUNTS_DIR
    P.ACCOUNTS_DIR = tmp
    ... check ...
    P.ACCOUNTS_DIR = _saved      # the line a growing suite forgets

A forgotten half leaves the swapped value live for every later check in the
same process - the usage.jsonl pollution of 2026-10-24 came from exactly this
class. These checks pin the contract on a throwaway module plus the real
gateway module (one harmless numeric setting), because the helper exists to be
used on `ca_proxy` and must be proven there.

    python tests/_test_patched_state.py
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_proxy as P  # noqa: E402
from _isolated_dirs import isolated_data_dirs, patched_state  # noqa: E402

isolated_data_dirs("wb-patched-state-")

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


_scratch = types.ModuleType("scratch")
_scratch.token = "real"
_scratch.depth = 3

print("1. 替换与还原")
with patched_state(_scratch, token="fake", depth=99):
    ok_inside = _scratch.token == "fake" and _scratch.depth == 99
check("with 块内读到替换值", ok_inside,
      (_scratch.token, _scratch.depth))
check("with 块外两个属性都还原",
      _scratch.token == "real" and _scratch.depth == 3,
      (_scratch.token, _scratch.depth))

print("2. 异常路径也还原")
_raised = False
try:
    with patched_state(_scratch, token="doomed"):
        raise RuntimeError("boom")
except RuntimeError:
    _raised = True
check("with 块抛异常后属性还原",
      _raised and _scratch.token == "real", _scratch.token)

print("3. 写入前先读全部原值（名字打错在入口就炸，不会改一半）")
try:
    with patched_state(_scratch, token="x", no_such_attr=1):
        pass
    _typo_failed = False
except AttributeError:
    _typo_failed = True
check("不存在的属性在入口报 AttributeError",
      _typo_failed and _scratch.token == "real",
      (_typo_failed, _scratch.token))

print("4. 嵌套：内层退出后回到外层的替换值")
with patched_state(_scratch, depth=10):
    with patched_state(_scratch, depth=20):
        ok_inner = _scratch.depth == 20
    ok_mid = _scratch.depth == 10
check("内层生效", ok_inner, _scratch.depth)
check("内层退出回到外层值", ok_mid, _scratch.depth)
check("外层退出回到真值", _scratch.depth == 3, _scratch.depth)

print("5. 真的用在 ca_proxy 上")
_saved_max = P.CODEARTS_DUMP_MAX
with patched_state(P, CODEARTS_DUMP_MAX=7):
    ok_host = P.CODEARTS_DUMP_MAX == 7
check("宿主模块块内生效、块外还原",
      ok_host and P.CODEARTS_DUMP_MAX == _saved_max,
      (ok_host, P.CODEARTS_DUMP_MAX))

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

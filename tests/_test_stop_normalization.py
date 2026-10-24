"""stop 字段的出站形状回归（上游 code 11101：Go 端只收 []string）。

原修复钉在 WorkBuddy 路径的 normalize_stop 上；路径退役后活入口是
ca_codearts.sampling_extra_from（还多一条「最多 4 条」的上游限制）。
这些断言改打活函数：单字符串包成数组、数组保序过滤、垃圾值不发、
没带 stop 不发明。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def extra_with(stop):
    return C.sampling_extra_from({"stop": stop}) or {}


print('[1] 单字符串包成单元素数组（Go 客户端 stop 单字符串曾整站 400）')
e = extra_with("END")
check("string wrapped", e.get("stop") == ["END"], e)
e = extra_with(chr(10) + chr(10))
check("whitespace string survives", e.get("stop") == [chr(10) + chr(10)], e)

print("[2] 数组保序 + 过滤垃圾元素 + 最多 4 条")
e = extra_with(["END", "STOP"])
check("order kept", e.get("stop") == ["END", "STOP"], e)
e = extra_with(["END", "", 7, None, "STOP"])
check("junk dropped, strings kept", e.get("stop") == ["END", "STOP"], e)
e = extra_with(["a", "b", "c", "d", "e", "f"])
check("capped at four", e.get("stop") == ["a", "b", "c", "d"], e)

print("[3] 空值 / 非法值不转发")
for label, v in (("empty string", ""), ("empty array", []), ("null", None),
                 ("number", 7), ("bool", True), ("object", {"a": 1})):
    e = extra_with(v)
    check("%s -> no stop key" % label, "stop" not in e, e)

print("[4] 不带 stop 不发明")
e = C.sampling_extra_from({"temperature": 0.5}) or {}
check("no stop invented", "stop" not in e, e)

print("SUMMARY: PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

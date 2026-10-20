"""看板内联脚本的作用域检查：数据看板那段是 (function(){...})() 包起来的，
里面的函数是私有的。外层代码若直接调用它们，运行时必然 ReferenceError，
而且表现为「功能静默失效」——页面不报错、不弹窗，只是永远停在加载态。

真实事故（2026-10-20）：账号列表调用了数据看板那段的 fmtTime()，
map 回调一抛错 set() 就不执行，账号页永远显示「正在读取…」。

这里做静态检查：把 IIFE 内声明的函数名收集起来，再找外层有没有直接调用它们。
短名（map/step/max…）常是别处的参数或局部变量，用「调用点所在函数是否自己
声明了同名形参/局部」来排除。
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# 允许用环境变量指向别处的副本 —— 反向验证（故意引入坏的跨作用域调用）时用
HTML = os.environ.get("DASHBOARD_HTML") or os.path.join(os.path.dirname(HERE),
                                                       "dashboard.html")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "  <- " + str(detail)))
    if not ok:
        FAILS.append(name)


def strip_noise(text):
    """把字符串/注释抹成空格，保留长度（用于括号配对与定位）。"""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i + 1 < n:
                out[i] = out[i + 1] = " "
                i += 2
        elif c in "\"'`":
            q = c
            out[i] = " "
            i += 1
            while i < n:
                if text[i] == "\\":
                    out[i] = " "
                    if i + 1 < n and text[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == q:
                    out[i] = " "
                    i += 1
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def iife_blocks(clean):
    """找出 (function ... (){...})() 形态的块，返回 [(start, end, 内部函数名集合)]。"""
    out = []
    for m in re.finditer(r"\(\s*(?:async\s+)?function\s*\w*\s*\([^)]*\)\s*\{", clean):
        i = clean.index("{", m.end() - 1)
        depth, j = 0, i
        while j < len(clean):
            if clean[j] == "{":
                depth += 1
            elif clean[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = clean[i:j]
        names = set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", body))
        out.append((m.start(), j + 1, names))
    return out


def enclosing_decl(clean, pos):
    """调用点所在的最近函数体区间（用于判断是否自己声明了同名）。"""
    head = clean.rfind("function", 0, pos)
    if head < 0:
        return ""
    brace = clean.find("{", head)
    if brace < 0 or brace > pos:
        return ""
    depth, j = 0, brace
    while j < len(clean):
        if clean[j] == "{":
            depth += 1
        elif clean[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return clean[head:j]


def main():
    html = io.open(HTML, encoding="utf-8").read()
    clean = strip_noise(html)
    blocks = iife_blocks(clean)
    check("看板里存在 IIFE 包裹的脚本段", blocks, "没找到 (function(){...})()")

    if not blocks:
        return 1

    # 外层 = IIFE 之外的全部文本
    outside_parts, last = [], 0
    for s, e, _ in blocks:
        outside_parts.append(clean[last:s])
        last = e
    outside_parts.append(clean[last:])
    outside = "\n".join(outside_parts)

    # 每个 IIFE 只检查「自己区间之外」的调用；外面另有同名全局定义的也不算
    private_calls = []
    for s, e, names in blocks:
        outside = clean[:s] + "\n" * clean.count("\n", s, e) + clean[e:]
        for name in sorted(names):
            if re.search(r"^\s*(?:async\s+)?function\s+%s\s*\(" % re.escape(name), outside, re.M):
                continue          # 外面自己也有同名函数
            if re.search(r"^\s*(?:const|let|var)\s+%s\s*=" % re.escape(name), outside, re.M):
                continue          # 外面有同名全局变量/箭头函数
            for m in re.finditer(r"(?<![\w$.])%s\s*\(" % re.escape(name), outside):
                # 调用点所在函数若自己声明了同名形参/局部，是遮蔽，不是漏引用
                body = enclosing_decl(outside, m.start())
                if re.search(r"\bfunction\s*\([^)]*\b%s\b" % re.escape(name), body):
                    continue
                if re.search(r"\b(?:const|let|var)\s+%s\s*=" % re.escape(name), body):
                    continue
                line = outside[:m.start()].count("\n") + 1
                private_calls.append("%s() 在 IIFE 外被调用（外层第 %d 行）" % (name, line))

    check("没有调用 IIFE 私有函数", not private_calls, private_calls)

    # 账号区块专项：它的渲染函数必须是全局的
    for fn in ("loadCodeartsAccounts", "caBalanceHtml", "caLeft", "caStamp"):
        check("函数 %s 是全局的（不在 IIFE 内）" % fn,
              re.search(r"^(?:async\s+)?function\s+%s\s*\(" % re.escape(fn), clean, re.M) is not None,
              "找不到顶层定义")

    print()
    if FAILS:
        print("失败 %d 项" % len(FAILS))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

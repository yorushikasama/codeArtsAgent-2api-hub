# -*- coding: utf-8 -*-
"""Dead-code sweep: top-level names in ca_*.py with references only at their
own definition site. Manual verification still required (dynamic refs,
framework entry points, string-built calls)."""
import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = [f for f in os.listdir(ROOT)
           if f.startswith("ca_") and f.endswith(".py")]

SOURCES = {}
for name in MODULES + ["dashboard.html"]:
    path = os.path.join(ROOT, name)
    if os.path.isfile(path):
        SOURCES[name] = open(path, encoding="utf-8", errors="replace").read()
TESTS = {}
tdir = os.path.join(ROOT, "tests")
for name in os.listdir(tdir):
    if name.endswith(".py"):
        TESTS[name] = open(os.path.join(tdir, name),
                           encoding="utf-8", errors="replace").read()


def top_level_names(path):
    tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((node.name, node.lineno, type(node).__name__))
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and re.match(r"^[A-Z_][A-Z0-9_]+$", t.id):
                    out.append((t.id, node.lineno, "CONST"))
    return out


FRAMEWORK = {"do_GET", "do_POST", "do_HEAD", "do_OPTIONS", "main", "run",
             "log_message", "version_string", "address_string"}


def count_refs(name, texts):
    """Occurrences of the bare name outside its own module definition lines."""
    pattern = re.compile(r"\b%s\b" % re.escape(name))
    total = 0
    for text in texts:
        total += len(pattern.findall(text))
    return total


report = []
for mod in MODULES:
    for name, lineno, kind in top_level_names(os.path.join(ROOT, mod)):
        if name.startswith("__") or name in FRAMEWORK:
            continue
        # references in all sources minus its own definition occurrence
        src_refs = count_refs(name, SOURCES.values()) - 1
        test_refs = count_refs(name, TESTS.values())
        if src_refs == 0:
            report.append((mod, lineno, kind, name, test_refs))

print("== 生产代码零引用（定义处除外）==")
for mod, lineno, kind, name, trefs in sorted(report):
    print("%s:%d  %-8s %-38s test_refs=%d"
          % (mod, lineno, kind, name, trefs))
print("total:", len(report))

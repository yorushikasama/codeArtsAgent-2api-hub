"""Real-scenario smoke tests against a LIVE gateway - run by hand, not by run_all.

    WB_HUB_DIR=<gateway dir with accounts/settings.json> WB_BASE_URL=http://127.0.0.1:9000         python3 tests/_realtest_live.py

Three sessions against the configured gateway (uses real credits):
  A: repo-reading multi-turn conversation on /v1/messages - the Claude Code
     pattern (system + tools + full resent history each turn), checks the
     usage the bridge reports (input vs cache_read / cache_creation).
  B: webpage-building multi-turn conversation on /v1/chat/completions.
  C: 4 parallel streams against the account's concurrency cap.

File is named _realtest_* on purpose: run_all only picks up _test_*, so this
costly probe never runs as part of the suite. Never point it at an account
you are not prepared to spend credits on.
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = os.environ.get("WB_BASE_URL") or "http://127.0.0.1:9000"
HUB = os.environ.get("WB_HUB_DIR") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
START = time.time()


def load_key():
    d = json.load(open(os.path.join(HUB, "accounts/settings.json")))
    for e in d.get("api_keys") or []:
        if e.get("key"):
            return e["key"]
    return ""


KEY = load_key()
if not KEY:
    print("FATAL: no api key configured")
    sys.exit(2)


def headers():
    return {"Content-Type": "application/json",
            "Authorization": "Bearer " + KEY,
            "x-api-key": KEY,
            "anthropic-version": "2023-06-01"}


def get(path, timeout=30):
    req = urllib.request.Request(BASE + path, headers=headers())
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, time.time() - t0, r.read()
    except urllib.error.HTTPError as e:
        return e.code, time.time() - t0, e.read()


def post(path, payload, timeout=180):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 headers=headers())
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        body = r.read()
        return r.status, time.time() - t0, None, body
    except urllib.error.HTTPError as e:
        return e.code, time.time() - t0, None, e.read()


def post_stream(path, payload, timeout=180):
    """Returns (status, ttft, elapsed, text, think, usage, n_events)."""
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 headers=headers())
    t0 = time.time()
    ttft = None
    text = []
    think = []
    usage = {}
    n_events = 0
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        for raw in r:
            if ttft is None:
                ttft = time.time() - t0
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            n_events += 1
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            try:
                obj = json.loads(data)
            except ValueError:
                continue
            if obj.get("type"):                       # anthropic shape
                if obj.get("type") == "content_block_delta":
                    d = obj.get("delta") or {}
                    if d.get("type") == "text_delta":
                        text.append(d.get("text") or "")
                    elif d.get("type") == "thinking_delta":
                        think.append(d.get("thinking") or "")
                u = obj.get("message", {}).get("usage") or obj.get("usage")
                if isinstance(u, dict) and u:
                    usage.update({k: v for k, v in u.items() if v})
            else:                                    # openai shape
                ch = (obj.get("choices") or [{}])[0]
                d = ch.get("delta") or {}
                if d.get("content"):
                    text.append(d["content"])
                if d.get("reasoning_content"):
                    think.append(d["reasoning_content"])
                if isinstance(obj.get("usage"), dict):
                    usage.update(obj["usage"])
        return r.status, ttft, time.time() - t0, "".join(text), "".join(think), usage, n_events
    except urllib.error.HTTPError as e:
        return e.code, ttft, time.time() - t0, e.read()[:300].decode("utf-8", "replace"), "", {}, 0


def line(label, ok, **kv):
    parts = ["[OK] " if ok else "[XX] ", label]
    for k, v in kv.items():
        if v is not None:
            parts.append("%s=%s" % (k, v))
    print(" ".join(parts), flush=True)


print("== models ==")
st, el, body = get("/v1/models")
models = [m.get("id") for m in json.loads(body).get("data", [])] if st == 200 else []
line("GET /v1/models", st == 200 and "glm-5.3" in models,
     status=st, n=len(models), glm53=("glm-5.3" in models))

MODEL = "glm-5.3"
MAXT = 8000

# ---------------------------------------------------------------- session A
print("\n== session A: repo reading via /v1/messages (claude-code pattern) ==")
sysprompt = (
    "你是资深 Python 后端工程师，正在帮我维护一个叫 codearts-hub 的本地网关项目"
    "（把华为云 CodeArts 的 agent 接口转成 OpenAI/Anthropic 协议）。"
    "回答用中文，简洁、直接引用函数名与行为；涉及取舍时先给结论再给依据。"
    "你只能基于我贴出的文件内容回答，不要臆测未贴出的代码。")
tools = [
    {"name": "read_file",
     "description": "读取仓库中一个文件的内容",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "list_dir",
     "description": "列出目录下的文件",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "grep",
     "description": "在仓库里正则搜索",
     "input_schema": {"type": "object",
                      "properties": {"pattern": {"type": "string"}},
                      "required": ["pattern"]}},
]
f1 = open(os.path.join(HUB, "ca_env.py"), encoding="utf-8", errors="replace").read()[:6000]
f2 = open(os.path.join(HUB, "ca_stream.py"), encoding="utf-8", errors="replace").read()[:6000]

history = []
turns = [
    "下面是 ca_env.py 的开头部分：\n```python\n" + f1 + "\n```\n请总结它的职责、主要函数与约定。",
    "再给 ca_stream.py 的开头：\n```python\n" + f2 + "\n```\n对比这两个文件的职责差异，并指出 ca_stream 可能依赖 ca_env 的哪些行为。",
    "基于上面两个文件：如果要给 ca_env 新增一个 number_list(name, default, minimum) 解析逗号分隔的环境变量数组，需要遵守哪些既有约定？给出实现和理由。",
]
for i, q in enumerate(turns, 1):
    history.append({"role": "user",
                    "content": [{"type": "text", "text": q}]})
    payload = {"model": MODEL, "max_tokens": MAXT, "stream": True,
               "system": sysprompt, "tools": tools, "messages": history}
    st, ttft, el, text, think, usage, nev = post_stream("/v1/messages", payload)
    u = ("in=%s cache_read=%s cache_create=%s out=%s"
         % (usage.get("input_tokens"), usage.get("cache_read_input_tokens"),
            usage.get("cache_creation_input_tokens"), usage.get("output_tokens")))
    line("A turn %d" % i, st == 200 and len(text) > 50, status=st,
         ttft=("%.1fs" % ttft) if ttft else None, elapsed="%.1fs" % el,
         chars=len(text), think_chars=len(think), **{"usage": u})
    if st != 200 or len(text) <= 50:
        print("   body:", str(text)[:200])
        break
    history.append({"role": "assistant",
                    "content": [{"type": "text", "text": text}]})
    time.sleep(2)   # turn gap: a real client thinks between turns

# ---------------------------------------------------------------- session B
print("\n== session B: webpage building via /v1/chat/completions ==")
bhist = [{"role": "system", "content": "你是前端工程师，输出可直接保存使用的完整代码。"}]
bturns = [  # t2/t3 use 6000 via per-turn override below
    ("请写一个单文件落地页 index.html：产品『CodeArts Hub』(API 网关看板)，包含 hero、三档定价卡、FAQ 手风琴、页脚。页面精简（全文件 300 行内）。只输出完整 HTML 文件，不要解释。", False),
    ("加上：深色模式切换按钮（localStorage 记住偏好）和滚动渐入动画。只输出需要追加的 <style> 与 <script> 完整块。", True),
    ("把定价表改成带 月付/年付 切换（年付 8 折），并输出最终的完整 HTML 文件。", True),
]
for i, (q, do_stream) in enumerate(bturns, 1):
    bhist.append({"role": "user", "content": q})
    payload = {"model": MODEL, "max_tokens": 16000 if i == 1 else 6000, "messages": bhist,
               "stream": do_stream}
    think = ""
    if do_stream:
        st, ttft, el, text, think, usage, nev = post_stream("/v1/chat/completions", payload)
    else:
        st, el2, _, body = post("/v1/chat/completions", payload)
        el = el2
        ttft = None
        text = ""
        if st == 200:
            try:
                msg = json.loads(body)["choices"][0]["message"]
                text = msg.get("content") or ""
                think = msg.get("reasoning_content") or ""
            except Exception:
                pass
    has_html = "</html>" in text.lower() or "<html" in text.lower() or "<style" in text.lower()
    line("B turn %d" % i, st == 200 and len(text) > 200, status=st,
         ttft=("%.1fs" % ttft) if ttft else None, elapsed="%.1fs" % el,
         chars=len(text), think_chars=len(think), html=has_html)
    if st != 200 or len(text) <= 200:
        print("   body:", str(text)[:300])
        break
    if i == 1:
        open("/tmp/realtest-page-v1.html", "w", encoding="utf-8").write(text)
    bhist.append({"role": "assistant", "content": text[-4000:]})
    time.sleep(2)

# ---------------------------------------------------------------- session C
print("\n== session C: 4 parallel streams vs concurrency cap 3 ==")
results = [None] * 4


def worker(idx):
    payload = {"model": "glm-5.3-flash", "max_tokens": 800, "stream": True,
               "reasoning_effort": "low",
               "messages": [{"role": "user", "content": "用一句话介绍你自己。"}]}
    st, ttft, el, text, think, usage, nev = post_stream("/v1/chat/completions", payload)
    results[idx] = (st, ttft, el, len(text), len(think))


threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
t0 = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join(200)
for i, r in enumerate(results):
    if r is None:
        line("C req %d" % i, False, status="timeout")
        continue
    st, ttft, el, n, nt = r
    line("C req %d" % i, st == 200, status=st,
         ttft=("%.1fs" % ttft) if ttft else None, elapsed="%.1fs" % el, chars=n, think_chars=nt)

# ---------------------------------------------------------------- usage readback
print("\n== gateway usage rows written during this test ==")
time.sleep(2)
rows = []
for ln in open(os.path.join(HUB, "usage/usage.jsonl"), encoding="utf-8", errors="replace"):
    try:
        d = json.loads(ln)
    except ValueError:
        continue
    if d.get("at", 0) >= START - 1:
        rows.append(d)
tp = sum(r.get("prompt_tokens") or 0 for r in rows)
tc = sum(r.get("cached_tokens") or 0 for r in rows)
tcomp = sum(r.get("completion_tokens") or 0 for r in rows)
for r in rows:
    line("usage %s" % r.get("iso", "?")[11:19],
         r.get("outcome") == "completed", model=r.get("model"),
         outcome=r.get("outcome"), status=r.get("status"),
         prompt=r.get("prompt_tokens"), cached=r.get("cached_tokens"),
         hit_pct=r.get("cache_hit_pct"))
line("TOTAL", True, reqs=len(rows), prompt=tp, cached=tc,
     hit_pct=round(100.0 * tc / tp, 1) if tp else 0, completion=tcomp)
print("\nDONE in %.1fs" % (time.time() - START))

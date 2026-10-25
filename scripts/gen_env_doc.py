"""Regenerate docs/ENV.md from the source: AST-extract every ca_env.* call and
raw os.environ read, emit the authoritative env reference.

Run from the repo root after changing a default, a bound, or adding a variable:

    python scripts/gen_env_doc.py

The panel-overridable set (✅ column) and the section-B prose are maintained by
hand in this script — they encode cross-module knowledge (which settings keys
override which env default) that no single call site states.
"""
import ast
import io
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "ENV.md")
SCAN = ("ca_proxy.py", "ca_usage.py", "ca_codearts.py")

#: 这些 env 只是启动默认：面板设置保存过就以面板为准（settings key 同名）
PANEL = {"CODEARTS_CONCURRENCY", "CODEARTS_STREAM_IDLE", "CODEARTS_STREAM_MAX_IDLE",
         "CODEARTS_BUSY_COOLDOWN", "CODEARTS_SESSION_PING", "CODEARTS_TPM_COOLDOWN"}

#: 表格里注释缺失/需要精确语义的条目（人工维护）
FILL = {
    "CODEARTS_AFFINITY_SAVE_EVERY": "会话粘性表落盘的节流间隔（秒）；0=不落盘",
    "CODEARTS_DUMP_MAX_AGE": "失败请求快照的最老保留年龄（秒，默认 7 天），超龄随新快照落盘时清理",
    "CODEARTS_MODEL_BREAKER_COOLDOWN": "模型熔断的冷却时长（秒）：连败达阈值后该模型晾这么久，期间走降级链",
    "CODEARTS_QUEUE_MAX_WAIT": "上游官方排队（queue-max-wait）的截止时间（秒）：跟队列拿号最多等这么久",
    "PORT": "监听端口（启动参数 --port 优先）",
    "WB_CHAT_SLOT_WAIT": "网关本地 chat 信号量的排队等待（秒），等不到回 503",
    "WB_STATS_TTL": "用量统计接口的结果缓存时长（秒）；0=关缓存",
    "WB_USAGE_CACHE_MIN_BYTES": "聚合缓存重建前 usage.jsonl 需要增长的最小字节数",
    "WB_USAGE_CACHE_MIN_SECONDS": "两次聚合缓存重建之间的最小间隔（秒）",
    "WB_RECENT_INDEX_MIN_BYTES": "近期索引重建前 usage.jsonl 需要增长的最小字节数",
    "WB_RECENT_INDEX_MIN_SECONDS": "两次近期索引重建之间的最小间隔（秒）",
}

#: 直读变量（绕过 ca_env 的 os.environ）：部署形态与功能开关
RAW = [
    ("ACCOUNTS_DIR", "数据目录（账号、设置）。启动参数 --accounts-dir / 环境变量都行；测试沙箱走 WB_PROXY_ACCOUNTS_DIR"),
    ("API_KEY", "启动默认 API key；面板「设置」里配置过的 key 一律优先，此项被忽略"),
    ("CODEARTS_CHECKIN_AT", "每日签到的本地时刻 HH:MM（默认 00:05）。错过补偿：HH:MM 后每个巡检节拍都会补，当天成功/已签的账号跳过"),
    ("HOST", "监听地址（默认 127.0.0.1；Docker 里设 0.0.0.0）"),
    ("PANEL_PASSWORD_FILE", "面板密码摘要的外部文件（部署工具注入用）"),
    ("WB_BACKGROUND_MODEL_TARGET", "后台刷新（目录/续期）使用的模型目标，留空跟随主配置"),
    ("WB_DUMP_FAILED_TOOLS", "设 1 时失败请求快照附带完整工具 schema（排障用，文件会变大）"),
    ("WB_ENABLE_ANTHROPIC_MESSAGES", "启动时强制启用 /v1/messages（面板开关的默认值来源之一；设 1 等于知晓缓存语义差异后自担成本）"),
    ("WB_MAX_CONCURRENT_CHAT", "网关本地 chat 并发上限（与账号并发是两层闸）"),
    ("WB_PROXY_ACCOUNTS_DIR / WB_PROXY_USAGE_DIR", "测试沙箱专用：把账号/用量指向临时目录。人不要设"),
    ("WB_PROXY_KEY", "测试沙箱专用 API key。人不要设"),
    ("WB_RECENT_INDEX", "设 1 启用近期请求索引（大 usage.jsonl 下 /usage/recent 提速；索引损坏自动从零重建）"),
    ("WB_TRUSTED_PROXIES", "受信反向代理网段（用于取真实客户端地址）"),
    ("WB_USAGE_CACHE", "设 0 关闭用量聚合缓存（测试用；生产别关）"),
    ("WB_USAGE_DAY_BUCKETS", "设 0 停用按天分桶聚合"),
    ("WB_USAGE_DAY_KEEP_DAYS / WB_USAGE_HOUR_KEEP_DAYS / WB_USAGE_HOUR_KEEP_HOURS", "分桶数据的留存窗口（天/天/小时），超窗桶在重整时丢弃"),
    ("WB_WEB_ENGINES", "web_search 可用引擎清单（逗号分隔，留空全部）"),
    ("WB_WEB_TOOLS_PROXY", "web_search / web_fetch 的出站代理"),
]


def value_of(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return ast.unparse(node)


def extract():
    rows = []
    for path in SCAN:
        src = io.open(os.path.join(ROOT, path), encoding="utf-8").read()
        lines = src.splitlines()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "ca_env"
                    and node.func.attr in ("string", "number", "boolean")):
                continue
            name = ast.literal_eval(node.args[0])
            default = value_of(node.args[1]) if len(node.args) > 1 else None
            kw = {k.arg: value_of(k.value) for k in node.keywords}
            i = node.lineno - 2
            comments = []
            while i >= 0 and lines[i].lstrip().startswith("#"):
                comments.insert(0, lines[i].strip().lstrip("#").strip())
                i -= 1
            rows.append({"name": name, "kind": node.func.attr, "default": default,
                         "kw": kw, "comment": " ".join(comments)})
    rows.sort(key=lambda r: r["name"])
    return rows


def clean_comment(c):
    c = c.replace(" : ", " ").replace(": ", " ")
    return re.sub(r"\s+", " ", c).strip()


def purpose(r):
    if r["name"] in FILL:
        return FILL[r["name"]]
    p = clean_comment(r["comment"]).replace("|", "，")
    if len(p) > 110:
        cut = p[:110]
        sp = max(cut.rfind("；"), cut.rfind("，"), cut.rfind(" "), 60)
        return cut[:sp] + "…"
    return p


def fmt_default(v):
    return str(v).replace(" * ", "×")


def fmt_kw(kw):
    parts = []
    if "minimum" in kw:
        parts.append("≥%s" % fmt_default(kw["minimum"]))
    if kw.get("integer"):
        parts.append("整数")
    if kw.get("zero_ok"):
        parts.append("0=关闭该功能")
    return "，".join(parts)


def main():
    rows = extract()
    L = ["# 环境变量参考\n",
         "运行参数的**权威清单**：A 表是 `ca_env` 统一解析的运行参数（%d 项），" % len(rows),
         "B 表是直读的部署与开关变量（%d 项）。\n" % len(RAW),
         "优先级与通用规则：\n",
         "- **面板设置 > 环境变量**：标「面板可调」的项，设置页保存过就以面板为准，env 只是启动默认值。",
         "- 未标「面板可调」的项 env 即最终配置，改完重启生效。",
         "- `WB_PROXY_*` 是 run_all 测试沙箱的内部分工，人不要设。",
         "- 非法值由 `ca_env` 统一回退默认并在启动日志告警；标了「0=关闭该功能」的项设 0 才是关闭，",
         "  设别的负数/坏值也一样回退默认。\n",
         "## A. 运行参数\n",
         "| 变量 | 默认 | 约束 | 面板 | 作用 |",
         "|---|---|---|---|---|"]
    for r in rows:
        L.append("| `%s` | `%s` | %s | %s | %s |" % (
            r["name"], fmt_default(r["default"]), fmt_kw(r["kw"]) or "—",
            "✅" if r["name"] in PANEL else "", purpose(r)))
    L += ["\n## B. 部署与开关\n", "| 变量 | 作用 |", "|---|---|"]
    for name, p in RAW:
        L.append("| `%s` | %s |" % (name, p))
    L += ["\n> 本表由 `scripts/gen_env_doc.py` 从源码 AST 提取生成；改默认值/约束/新增",
          "> 变量后重跑该脚本再提交。"]
    io.open(OUT, "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")
    print("ENV.md: %d ca_env rows + %d raw rows" % (len(rows), len(RAW)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

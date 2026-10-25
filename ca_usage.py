# -*- coding: utf-8 -*-
"""ca_usage.py - 用量记录的**读取与聚合**域（2026-10-24 自 ca_proxy 拆出）。

边界：usage.jsonl 的扫描、窗口折叠、快照/分析/时序/近期索引/性能环、
估算与剩余额度载荷、积分计费。**写侧不在这里**：record_usage / record_error
/ _persist_usage 留在 ca_proxy（它们和账号池、模型熔断、log 同生命周期）。

对宿主（ca_proxy）的依赖全部走 `bind()` 注入的钩子，且都是**调用时求值**：
测试 patch `P.ACCOUNTS_DIR / P.log / P.USAGE_DIR / P.CURRENT_REALM` 以及
15 个 `_bind_*` 包装的函数，行为与拆分前一致。
"""
import bisect
import calendar
import collections
from collections import deque
import heapq
import datetime
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse

import ca_env
import ca_protocol
import ca_settings

#: 宿主绑定。ca_proxy 导入后立即 bind()；未绑定时给安全默认（独立可用）。
_BINDINGS = {
    "log": lambda *a, **k: None,
    "accounts_dir": lambda: ".",
    "usage_dir": lambda: ".",
    "usage_log": lambda: os.path.join(_usage_dir(), "usage.jsonl"),
    "usage_cache_last_attempt": lambda: 0.0,
    "_set_usage_cache_last_attempt": lambda v: None,
    "current_realm": lambda: "codearts",
    "open": open,
    "RECENT_INDEX_FILE": lambda: os.path.join(_usage_dir(),
                                              "usage-recent-index.json"),
    "ESTIMATE_DAILY_FILE": lambda: os.path.join(_usage_dir(),
                                                "estimate-daily.json"),
}


def bind(**kw):
    _BINDINGS.update(kw)


def _bind__line_outside_window(*a, **k):
    return _BINDINGS['_line_outside_window'](*a, **k)

def _bind__line_outside_window_bytes(*a, **k):
    return _BINDINGS['_line_outside_window_bytes'](*a, **k)

def _bind__row_cost(*a, **k):
    return _BINDINGS['_row_cost'](*a, **k)

def _bind__scan_usage_snapshot_window(*a, **k):
    return _BINDINGS['_scan_usage_snapshot_window'](*a, **k)

def _bind__scan_usage_snapshot_window_days(*a, **k):
    return _BINDINGS['_scan_usage_snapshot_window_days'](*a, **k)

def _bind__scan_usage_snapshot_window_hours(*a, **k):
    return _BINDINGS['_scan_usage_snapshot_window_hours'](*a, **k)

def _bind__scan_usage_analytics_window(*a, **k):
    return _BINDINGS['_scan_usage_analytics_window'](*a, **k)

def _bind__scan_usage_analytics_window_days(*a, **k):
    return _BINDINGS['_scan_usage_analytics_window_days'](*a, **k)

def _bind__scan_usage_analytics_window_hours(*a, **k):
    return _BINDINGS['_scan_usage_analytics_window_hours'](*a, **k)

def _bind__fold_usage_snapshot(*a, **k):
    return _BINDINGS['_fold_usage_snapshot'](*a, **k)

def _bind__fold_usage_analytics(*a, **k):
    return _BINDINGS['_fold_usage_analytics'](*a, **k)

def _bind__usage_cache_kind_path(*a, **k):
    return _BINDINGS['_usage_cache_kind_path'](*a, **k)

def _bind__usage_cache_last_attempt():
    return _BINDINGS['usage_cache_last_attempt']()


def _set_usage_cache_last_attempt(v):
    _BINDINGS['_set_usage_cache_last_attempt'](v)

def _bind__usage_cache_path(*a, **k):
    return _BINDINGS['_usage_cache_path'](*a, **k)

def _bind__usage_cache_read_kind(*a, **k):
    return _BINDINGS['_usage_cache_read_kind'](*a, **k)

def _bind__usage_cache_read_legacy_file(*a, **k):
    return _BINDINGS['_usage_cache_read_legacy_file'](*a, **k)

def _bind__usage_timeseries_scan(*a, **k):
    return _BINDINGS['_usage_timeseries_scan'](*a, **k)

def _bind__STATS_TTL(*a, **k):
    return _BINDINGS['_STATS_TTL'](*a, **k)


def _bind__series_credit_entry(*a, **k):
    return _BINDINGS["_series_credit_entry"](*a, **k)


def _log(*a, **k):
    return _BINDINGS["log"](*a, **k)


def _accounts_dir():
    return _BINDINGS["accounts_dir"]()


def _usage_dir():
    return _BINDINGS["usage_dir"]()


def _usage_log_path():
    return _BINDINGS["usage_log"]()


def _current_realm():
    return _BINDINGS["current_realm"]()


def _open(*a, **k):
    """文件打开走宿主绑定：测试 patch `P.open` 装计数桩时必须能看到。"""
    return _BINDINGS["open"](*a, **k)


def _recent_index_file():
    return _BINDINGS["RECENT_INDEX_FILE"]()


def _estimate_daily_file():
    return _BINDINGS["ESTIMATE_DAILY_FILE"]()




DEFAULT_REALM = "codearts"

def normalize_realm(realm):
    """把任何来源的 region 归一成当前存在的那个出口名。

    历史行里写着 `cn`（WorkBuddy 国内出口）与 `intl`（已删的国际出口）的那些
    流量确实被花掉过，按原值返回会让它们在唯一的码道视图里整批消失，用量与
    花费对不上账——比贴错区域名更糟。所以这里是无条件归一，不是「认不出来才
    兜底」：只要网关只有一条上游，任何区域名都指同一条上游。
    """
    return DEFAULT_REALM

def match_realm(realm):
    """把「请求要哪个出口」归一成真正存在的区域名。

    None / 空 / "all" 原样返回（调用方当「不过滤」处理）；`cn` / `intl` 与
    任何其它写法一并归一到现存出口 —— 老客户端还在发 `X-Realm: intl`，而
    网关只有码道一条上游，按原值比只会一条都匹配不到。
    """
    text = str(realm or "").strip().lower()
    if text in ("", "all"):
        return text or None
    return normalize_realm(text)

def detect_model_realm(model_id):
    """模型归属哪个出口。国际版已移除，恒为当前出口。

    参数保留：调用方仍按「模型 → 出口」的语义传值，将来换上游时这里要重新划界。
    _current_realm() 从环境变量读进来，值本身也可能是历史遗留的已删区域，所以
    出口名一律过一遍归一——否则 row_realm 会把整批行贴上一个不存在的区域。
    """
    return normalize_realm(_current_realm())

USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "reasoning_tokens",
                "cached_tokens", "total_tokens", "credit")

def _empty_stats():
    return {"requests": 0, "errors": 0, "prompt_tokens": 0, "completion_tokens": 0,
            "reasoning_tokens": 0, "cached_tokens": 0, "total_tokens": 0,
            "credit": 0.0,
            "started": time.time(), "by_model": {},
            # Same aggregation keyed by (model, realm), so the metrics table
            # can show one row per exit for a model that ran through both.
            "by_model_realm": {},
            # And again keyed by (model, realm, account), so a model served
            # by two accounts on the same exit can be split per account.
            "by_model_acct": {},
            # latency accumulators (averages; percentiles come from the JSONL)
            "ttft_ms_sum": 0, "ttft_samples": 0,
            "gen_ms_sum": 0, "gen_samples": 0,
            "wall_ms_sum": 0, "wall_samples": 0}

_usage = {"started": time.time()}

def _extract_usage(usage):
    """Normalize the upstream usage block into the fields we track."""
    if not usage:
        return {}
    details = usage.get("completion_tokens_details") or {}
    return {
        "prompt_tokens": usage.get("prompt_tokens") or 0,
        "completion_tokens": usage.get("completion_tokens") or 0,
        "reasoning_tokens": details.get("reasoning_tokens") or 0,
        "cached_tokens": ca_protocol.best_cached_tokens(usage),
        "total_tokens": usage.get("total_tokens") or 0,
        "credit": usage.get("credit") or 0,
    }

def row_realm(row):
    """The realm a log row belongs to.

    Rows written since the field was added carry it directly. Older rows are
    attributed by their account, then by the model's home realm - the same
    order row_matches_realm used, so a filter and a per-realm breakdown can
    never disagree about the same row.

    历史行里写着已删区域的（intl），一律归一到现存出口：那些流量确实是这些
    账号花掉的，按原值返回会让它们在「国内版」视图里整批消失，用量与花费对
    不上账——比贴错区域名更糟。
    """
    r = row.get("realm")
    if r:
        return normalize_realm(r)
    model = row.get("model")
    if model:
        return detect_model_realm(model)
    return DEFAULT_REALM

def row_matches_realm(row, realm):
    # None means every realm. "all" is accepted here as well so that a caller
    # that forwards the literal cannot silently match nothing: the previous
    # behaviour compared every row's realm against the string "all".
    if not realm or realm == "all": return True
    # 请求侧的已删区域也归一到现存出口：只归一 row_realm 而不归一比较值，
    # 结果是「filter 说 cn、行也说 cn，却永远不相等」。
    return row_realm(row) == match_realm(realm)

def realm_scope(realm, fallback=None):
    """Map a caller-supplied realm onto a log filter.

    "all" means every realm, so it becomes None and disables filtering
    entirely: passing the literal through would make row_matches_realm
    compare every row against "all" and match nothing at all. An empty
    or missing value falls back to the second argument: _current_realm() for
    the endpoints whose clients expect the global switch, None (everything)
    for the analytics payload, which has always reported both realms
    combined.

    已删区域（老客户端还会带 realm=intl）归一到现存出口，而不是原样当成过滤
    条件——那会让一个合法的历史视图显示 0 条，看起来像数据丢了。
    """
    if realm == "all":
        return None
    if not realm:
        return fallback
    return match_realm(realm)

def _local_midnight(ts=None, days_back=0):
    """Local midnight `days_back` days before `ts` (default: now).

    mktime normalises an out-of-range day, so stepping back past the 1st of a
    month still lands on a real local midnight instead of raising.
    """
    lt = time.localtime(ts if ts is not None else time.time())
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday - days_back, 0, 0, 0, 0, 0, -1))

def _local_hour_start(ts):
    """ts 所属的本地整点（分/秒归零）的 epoch。

    与 _local_midnight 同一套构造：mktime 把本地墙上时间换算回 epoch，
    分/秒归零就是「本地整点」。夏令时切换小时里的时间会被 mktime 规整到
    相邻的真实时刻，所以调用方还要比对返回值是否等于原值——只有能原样
    还原的 ts 才是真的落在整点上（见 _hour_window_key）。
    """
    lt = time.localtime(ts)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour, 0, 0, 0, 0, -1))

def _epoch_or_none(value):
    """A panel-supplied epoch second, or None when it cannot be trusted.

    A negative or unparseable bound is dropped rather than clamped. The panel
    rejects those before they are ever sent, so one arriving here means a
    hand-written URL, and "no bound on this side" is a much smaller surprise
    than silently slicing the log at 1970.
    """
    if value in (None, "", False):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None

def range_window(value, since=None, until=None):
    """Resolve the dashboard's time-range selector into a (since, until) pair.

    Both bounds are cutoffs on a row's `at`; None means "unbounded on that
    side", and (None, None) - an unknown, empty or missing range - disables
    filtering entirely, which is what every caller did before windows existed,
    so an older panel keeps receiving the full history it used to get.

    today/week/month are calendar windows anchored to local midnight, matching
    the definition the analytics payload has always used for its Today
    figures: two different meanings of "today" on one page would be worse than
    either. The week starts on Monday. Rolling aliases ("7d", "30d") are
    deliberately absent - they would mean "the last seven days", which is a
    different window from "this week" and would make the button's label wrong
    on six days out of seven.

    custom takes the two epochs the panel sends. Either side may be missing
    ("from this date onwards" / "up to this date"), and reversed bounds are
    swapped rather than rejected, because the two inputs are independent and
    an empty end is the normal case.
    """
    v = str(value or "").strip().lower()
    if v in ("today", "day", "1d"):
        return _local_midnight(), None
    if v in ("week", "w"):
        return _local_midnight(days_back=time.localtime().tm_wday), None
    if v in ("month", "m"):
        lt = time.localtime()
        return time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1)), None
    if v == "custom":
        lo, hi = _epoch_or_none(since), _epoch_or_none(until)
        if lo is not None and hi is not None and hi < lo:
            lo, hi = hi, lo
        return lo, hi
    return None, None

def row_outcome(row):
    """Terminal state of a request row.

    Rows written before the outcome field existed only carry error/status,
    so they fall back to that: an error row is a failure, anything else is a
    completed request. One helper keeps every reader agreeing on the answer.
    """
    o = row.get("outcome")
    if o:
        return o
    return "failed" if row.get("error") else "completed"

def _perf_block(vals):
    """One metric's summary block, straight from the raw samples.

    D6 要求分位永远从原始样本算（不许聚合近似），所以这里收的是一串原始数值
    ——list 或 deque 都行（增量样本用 deque 做并入/滑出）。排序一次喂三个分位；
    avg 与 max 仍读原序列，于是浮点求和的顺序、以及 avg 的最后一位，与逐次
    排序的旧写法逐位相同。
    """
    if not vals:
        return None
    ordered = sorted(vals)
    count = len(ordered)

    def rank(q):
        idx = int(round((q / 100.0) * (count - 1)))
        return ordered[max(0, min(count - 1, idx))]

    return {
        "avg": round(sum(vals) / count, 1),
        "p50": rank(50),
        "p90": rank(90),
        "p99": rank(99),
        "max": max(vals),
        "samples": count,
    }

_perf_cache = {}

_perf_lock = threading.Lock()

def _perf_stats_scope(sample, realm, range, since, until):
    """(过滤用的 realm, since, until, 缓存键) —— perf_stats() 与它的 ETag 共用。

    抽出来只为一件事：取数和派生 ETag 必须走**同一套**键。两边各写一份的话，
    只要有一处不同（比如一处 realm_scope、一处原始 realm），tag 就会落到另一条
    缓存条目上，客户端拿到的是一个不描述当前响应体的校验符。
    """
    r = realm_scope(realm, _current_realm())
    lo, hi = range_window(range, since, until)
    try:
        # The key carries the resolved bounds rather than a today/all flag:
        # this week and this month overlap, so a flag cannot tell them apart
        # and one window's latency would be served under the other's label.
        key = (int(sample), r or "all",
               lo if lo is not None else -1, hi if hi is not None else -1)
    except Exception:
        key = (5000, r or "all",
               lo if lo is not None else -1, hi if hi is not None else -1)
    return r, lo, hi, key

def _perf_stats_uncached(sample=5000, realm=None, since=None, until=None):
    """Latency percentiles + derived rates, computed from the JSONL log."""
    # 与 count_usage_rows / usage_snapshot 走同一套归一：已删区域（老调用方
    # 还会传 intl）落到现存出口，而不是拿一个不存在的名字去比 row_realm，
    # 那样只会数出 0 条，看起来像「这段窗口没有数据」。
    realm = realm_scope(realm)
    ttfts, gens, walls, rates, hits, tok_rates = [], [], [], [], [], []
    total = ok = err = aborted = 0
    # 按模型聚合性能指标
    m_buckets = {}
    # Same aggregation keyed by (model, realm), so the metrics table can
    # report a model's latency per exit when it ran through both.
    mr_buckets = {}
    # And keyed by (model, realm, account), so two accounts on one exit can
    # be shown as separate rows.
    ma_buckets = {}
    # 只读日志末尾 sample 行：原先 readlines() 会把整个日志读成字符串列表
    rows = [raw.decode("utf-8", "replace") for raw in _tail_lines(_usage_log_path(), sample)]
    # The tail read stops at `sample` lines, so a window wider than the sample
    # is only described by its newest requests. Both facts are reported so the
    # matrix can say the latency columns cover a partial slice instead of
    # presenting them as the whole window.
    sample_capped = len(rows) >= sample
    sample_from = None
    for line in rows:
        line = line.strip()
        if not line:
            continue
        # 廉价窗口预过滤（复用 _bind__line_outside_window）：解析前的子串检查就能
        # 证明落在窗口外的行不再付 json.loads 的钱。它只丢「下面的窗口判断
        # 本来也会丢」的行，聚合口径一个数都不变；无窗口的调用（since/until
        # 全空）连检查都不做，因此一分钱都不多花。sample_from 还没定下来的
        # 时候也不过滤——第一行解析出来的 at 就是 sample_from 的值，跳过解析
        # 会让它变成窗口内第一行的时间戳，报告的范围就跟着变了。
        if (since or until) and sample_from is not None and \
                _bind__line_outside_window(line, since or None, until or None):
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if sample_from is None:
            sample_from = r.get("at")
        if realm and not row_matches_realm(r, realm):
            continue
        # Same window as the usage snapshot, so the latency and speed columns
        # of the matrix describe the same requests as its token columns.
        at = r.get("at") or 0
        if since and at < since:
            continue
        if until and at > until:
            continue
        total += 1
        outcome = row_outcome(r)
        # Every row reaches the model bucket, whatever its outcome, so a model
        # that only ever saw cancellations still shows up with a zero success
        # count instead of silently vanishing from the per-model table.
        m_id = r.get("model") or "unknown"
        r_realm = row_realm(r)
        mb = m_buckets.setdefault(m_id, {"total": 0, "ok": 0, "err": 0, "aborted": 0,
                                        "ttfts": [], "gens": [], "walls": [],
                                        "tok_rates": [], "hits": []})
        rb = mr_buckets.setdefault(m_id, {}).setdefault(
            r_realm, {"total": 0, "ok": 0, "err": 0, "aborted": 0,
                      "ttfts": [], "gens": [], "walls": [],
                      "tok_rates": [], "hits": []})
        ab = ma_buckets.setdefault(m_id, {}).setdefault(r_realm, {}).setdefault(
            r.get("account") or "(unattributed)",
            {"total": 0, "ok": 0, "err": 0, "aborted": 0,
             "ttfts": [], "gens": [], "walls": [],
             "tok_rates": [], "hits": []})
        mb["total"] += 1
        rb["total"] += 1
        ab["total"] += 1
        # A client that walks away is not a gateway failure, so it counts as
        # neither ok nor err - it gets its own bucket instead of silently
        # dragging the success rate down.
        if outcome == "client_aborted":
            aborted += 1
            for b in (mb, rb, ab):
                b["aborted"] += 1
                if r.get("elapsed_ms"):
                    b["walls"].append(r["elapsed_ms"])
            if r.get("elapsed_ms"):
                walls.append(r["elapsed_ms"])
            continue
        if outcome != "completed":
            err += 1
            for b in (mb, rb, ab):
                b["err"] += 1
                if r.get("elapsed_ms"):
                    b["walls"].append(r["elapsed_ms"])
            if r.get("elapsed_ms"):
                walls.append(r["elapsed_ms"])
            continue
        ok += 1
        for b in (mb, rb, ab):
            b["ok"] += 1
        if r.get("ttft_ms") is not None:
            ttfts.append(r["ttft_ms"])
            for b in (mb, rb, ab):
                b["ttfts"].append(r["ttft_ms"])
        if r.get("gen_ms") is not None:
            gens.append(r["gen_ms"])
            for b in (mb, rb, ab):
                b["gens"].append(r["gen_ms"])
        if r.get("elapsed_ms") is not None:
            walls.append(r["elapsed_ms"])
            for b in (mb, rb, ab):
                b["walls"].append(r["elapsed_ms"])
        if r.get("tokens_per_sec"):
            tok_rates.append(r["tokens_per_sec"])
            for b in (mb, rb, ab):
                b["tok_rates"].append(r["tokens_per_sec"])
        if r.get("cache_hit_pct") is not None:
            hits.append(r["cache_hit_pct"])
            for b in (mb, rb, ab):
                b["hits"].append(r["cache_hit_pct"])
    block = _perf_block
    return {
        "sampled": total,
        # Where the sampled slice starts and whether it was cut short, so a
        # week/month view can admit that its latency columns do not reach back
        # to the window's own start.
        "sample_from": sample_from,
        "sample_capped": sample_capped,
        "success": ok,
        "errors": err,
        "client_aborted": aborted,
        # Success rate is measured against requests the gateway actually
        # finished; client cancellations are reported separately rather than
        # being counted as failures.
        "success_rate_pct": round(ok * 100.0 / (ok + err), 1) if (ok + err) else None,
        "ttft_ms": block(ttfts),
        "generation_ms": block(gens),
        "wall_ms": block(walls),
        "tokens_per_sec": block(tok_rates),
        "cache_hit_pct": block(hits),
        "by_model": {
            mid: {
                "requests": mb["total"],
                "errors": mb["err"],
                "client_aborted": mb.get("aborted", 0),
                "success_rate_pct": round(mb["ok"] * 100.0 / (mb["ok"] + mb["err"]), 1)
                                     if (mb["ok"] + mb["err"]) else None,
                "ttft_ms": block(mb["ttfts"]),
                "generation_ms": block(mb["gens"]),
                "wall_ms": block(mb["walls"]),
                "tokens_per_sec": block(mb["tok_rates"]),
                "cache_hit_pct": block(mb["hits"]),
            } for mid, mb in m_buckets.items()
        },
        "by_model_realm": {
            mid: {
                realm: {
                    "requests": rb["total"],
                    "errors": rb["err"],
                    "client_aborted": rb.get("aborted", 0),
                    "success_rate_pct": round(rb["ok"] * 100.0 / (rb["ok"] + rb["err"]), 1)
                                         if (rb["ok"] + rb["err"]) else None,
                    "ttft_ms": block(rb["ttfts"]),
                    "generation_ms": block(rb["gens"]),
                    "wall_ms": block(rb["walls"]),
                    "tokens_per_sec": block(rb["tok_rates"]),
                    "cache_hit_pct": block(rb["hits"]),
                } for realm, rb in realms.items()
            } for mid, realms in mr_buckets.items()
        },
        "by_model_acct": {
            mid: {
                realm: {
                    acct: {
                        "requests": ab["total"],
                        "errors": ab["err"],
                        "client_aborted": ab.get("aborted", 0),
                        "success_rate_pct": round(ab["ok"] * 100.0 / (ab["ok"] + ab["err"]), 1)
                                             if (ab["ok"] + ab["err"]) else None,
                        "ttft_ms": block(ab["ttfts"]),
                        "generation_ms": block(ab["gens"]),
                        "wall_ms": block(ab["walls"]),
                        "tokens_per_sec": block(ab["tok_rates"]),
                        "cache_hit_pct": block(ab["hits"]),
                    } for acct, ab in accts.items()
                } for realm, accts in realms.items()
            } for mid, realms in ma_buckets.items()
        }
    }

_perf_state = {}

_PERF_STATE_MAX = 4

_PERF_REC_LEN = 10

def _perf_new_bucket():
    return {"total": 0, "ok": 0, "err": 0, "aborted": 0,
            "ttfts": deque(), "gens": deque(), "walls": deque(),
            "tok_rates": deque(), "hits": deque()}

def _perf_new_agg():
    return {"total": 0, "ok": 0, "err": 0, "aborted": 0,
            "ttfts": deque(), "gens": deque(), "walls": deque(),
            "tok_rates": deque(), "hits": deque(),
            "m": {}, "mr": {}, "ma": {}}

def _perf_put(vals, value, add, front):
    """一个数值贡献：并入 append，撤销时从对应的那一头弹出。

    环里的行严格按日志顺序进出：滑出样本的是最旧的一行（front），上一轮末尾
    的半行被重折时摘掉的是最新的一行（back）。同一张表的每一头都只对应同一
    行——这正是撤销能 O(1) 做完的原因。
    """
    if add > 0:
        vals.append(value)
    elif front:
        vals.popleft()
    else:
        vals.pop()

def _perf_apply(state, entry, add, front):
    """并入（add=1）或撤销（add=-1）一行对聚合的贡献。

    撤销只做并入做过的那些事：计数减回去、数值表从并进的那一头弹出、桶的
    total 归零就把桶删掉——重建时一个桶存在与否只看样本里还有没有它的行，
    所以"删空桶"正是重建的输出形状；删掉的桶后来再有行进来会重新建在末尾，
    位置与重建时的"第一次出现"一致（旧行都滑出去了，新行就是它现在最早的
    一行）。判定条件与 _perf_stats_uncached 的逐行循环逐句对应：
    elapsed 走真值判断、ttft/cache_hit 走 is not None、tokens_per_sec 走真值。
    """
    if entry is None or len(entry) < _PERF_REC_LEN:
        return
    _at, m_id, r_realm, acct, outcome, elapsed, ttft, gen, tps, hit = entry
    agg = state["agg"]
    if add > 0:
        mb = agg["m"].get(m_id)
        if mb is None:
            mb = agg["m"][m_id] = _perf_new_bucket()
        realms = agg["mr"].get(m_id)
        if realms is None:
            realms = agg["mr"][m_id] = {}
        rb = realms.get(r_realm)
        if rb is None:
            rb = realms[r_realm] = _perf_new_bucket()
        accts = agg["ma"].get(m_id)
        if accts is None:
            accts = agg["ma"][m_id] = {}
        by_realm = accts.get(r_realm)
        if by_realm is None:
            by_realm = accts[r_realm] = {}
        ab = by_realm.get(acct)
        if ab is None:
            ab = by_realm[acct] = _perf_new_bucket()
    else:
        mb = agg["m"][m_id]
        rb = agg["mr"][m_id][r_realm]
        ab = agg["ma"][m_id][r_realm][acct]
    agg["total"] += add
    for b in (mb, rb, ab):
        b["total"] += add
    # A client that walks away is not a gateway failure: it gets its own
    # bucket instead of dragging the success rate down (same split as the
    # full-scan path).
    if outcome == "client_aborted":
        agg["aborted"] += add
        for b in (mb, rb, ab):
            b["aborted"] += add
            if elapsed:
                _perf_put(b["walls"], elapsed, add, front)
        if elapsed:
            _perf_put(agg["walls"], elapsed, add, front)
    elif outcome != "completed":
        agg["err"] += add
        for b in (mb, rb, ab):
            b["err"] += add
            if elapsed:
                _perf_put(b["walls"], elapsed, add, front)
        if elapsed:
            _perf_put(agg["walls"], elapsed, add, front)
    else:
        agg["ok"] += add
        for b in (mb, rb, ab):
            b["ok"] += add
        if ttft is not None:
            _perf_put(agg["ttfts"], ttft, add, front)
            for b in (mb, rb, ab):
                _perf_put(b["ttfts"], ttft, add, front)
        if gen is not None:
            _perf_put(agg["gens"], gen, add, front)
            for b in (mb, rb, ab):
                _perf_put(b["gens"], gen, add, front)
        if elapsed is not None:
            _perf_put(agg["walls"], elapsed, add, front)
            for b in (mb, rb, ab):
                _perf_put(b["walls"], elapsed, add, front)
        if tps:
            _perf_put(agg["tok_rates"], tps, add, front)
            for b in (mb, rb, ab):
                _perf_put(b["tok_rates"], tps, add, front)
        if hit is not None:
            _perf_put(agg["hits"], hit, add, front)
            for b in (mb, rb, ab):
                _perf_put(b["hits"], hit, add, front)
    if add < 0:
        if not mb["total"]:
            del agg["m"][m_id]
        if not rb["total"]:
            del agg["mr"][m_id][r_realm]
            if not agg["mr"][m_id]:
                del agg["mr"][m_id]
        if not ab["total"]:
            del agg["ma"][m_id][r_realm][acct]
            if not agg["ma"][m_id][r_realm]:
                del agg["ma"][m_id][r_realm]
            if not agg["ma"][m_id]:
                del agg["ma"][m_id]

def _perf_at_token(line):
    """预过滤认可的写法里 at 的浮点值（读不到就 None）。

    _bind__line_outside_window 判定为"窗外"的行，其形状已经被它逐条核过：以
    `{"at": ` 开头、值以逗号收尾、值是浮点字面量、后面没有第二个 "at" 键。
    所以这里读到的值与 json.loads 会给的值相同（json 对带小数点/指数的记号
    也走 float()）。只给窗口预过滤跳过的行记 sample_from 用——那些行不解析，
    但旧实现里"样本最老的那一行"会被解析，它的 at 就是 sample_from。
    """
    if not line.startswith(_AT_PREFIX):
        return None
    end = line.find(",", len(_AT_PREFIX))
    if end < 0:
        return None
    token = line[len(_AT_PREFIX):end]
    if "." not in token and "e" not in token and "E" not in token:
        return None
    try:
        return float(token)
    except ValueError:
        return None

def _perf_line_entry(state, line):
    """把一行日志折成 ring 条目（与 _perf_stats_uncached 的逐行循环逐句对应）。

    返回：
      None      这一行没有可用的行数据（坏 JSON，或被窗口预过滤掉且读不出 at）
      (at,)     解析成功但被 realm / 窗口过滤掉——或被窗口预过滤跳过（at 取自
                它自己声明的值）：不贡献聚合，但仍决定 sample_from。旧实现里
                样本最老的那一行无论窗口如何都会被解析，所以被预过滤掉的行也
                要留下 at。
      (at, model, realm, account, outcome, elapsed, ttft, gen, tps, hit)
                通过全部过滤，计入聚合（10 元组，_PERF_REC_LEN）
    """
    since = state["since"]
    until = state["until"]
    realm = state["realm"]
    # 与旧实现同一道廉价预过滤：它只丢"下面的窗口判断本来也会丢"的行。
    # 旧实现的开关是 sample_from is not None（= 样本里已经有一行的 at 非空），
    # 这里用环里 at 非空的行数 n_at 表达同一件事。
    #
    # 多一道 line.endswith("}")：预过滤跳过的行也要记下它声明的 at（供
    # sample_from 用），但一条写了一半的行（尾部没换行、JSON 也没写完）不该
    # 因此报出一个旧实现给不出的 sample_from——完整行才走跳过分支，其余照旧
    # 落到 json.loads 上（坏 JSON 仍然是 None）。完整对象行总是以 } 收尾，
    # 所以这道判断不改变任何合法行省下的解析。
    if (since or until) and state["n_at"] and line.endswith("}") and \
            _bind__line_outside_window(line, since or None, until or None):
        return (_perf_at_token(line),)
    try:
        r = json.loads(line)
    except Exception:
        return None
    at = r.get("at")
    if realm and not row_matches_realm(r, realm):
        return (at,)
    at_value = at or 0
    if since and at_value < since:
        return (at,)
    if until and at_value > until:
        return (at,)
    return (at, r.get("model") or "unknown", row_realm(r),
            r.get("account") or "(unattributed)", row_outcome(r),
            r.get("elapsed_ms"), r.get("ttft_ms"), r.get("gen_ms"),
            r.get("tokens_per_sec"), r.get("cache_hit_pct"))

def _perf_drop_oldest(state):
    """滑出环里最旧的一行（含它对聚合的贡献）。"""
    old = state["ring"].popleft()
    if old is not None and old[0] is not None:
        state["n_at"] -= 1
    _perf_apply(state, old, -1, True)

def _perf_push(state, line):
    """把一行并进环：先腾位置，再折行、并入。

    腾位置放在折行之前——旧实现的窗口预过滤开关是"当前样本里已经有行的 at
    非空"，滑出样本的行不再算数。若先折行再淘汰，新行就可能被预过滤掉一行
    "在旧样本里不算、在新样本里却是第一行"的数据，sample_from 会跟着变。
    """
    sample = state["sample"]
    if sample <= 0:
        return
    ring = state["ring"]
    while len(ring) >= sample:
        _perf_drop_oldest(state)
    entry = _perf_line_entry(state, line)
    if entry is not None and entry[0] is not None:
        state["n_at"] += 1
    _perf_apply(state, entry, 1, False)
    ring.append(entry)

def _perf_pop_last(state):
    """摘掉环尾的条目（上一轮的半行，重折前先撤掉它的贡献）。"""
    ring = state["ring"]
    if not ring:
        return
    old = ring.pop()
    if old is not None and old[0] is not None:
        state["n_at"] -= 1
    _perf_apply(state, old, -1, False)

def _perf_fold(state):
    """把日志 offset 之后的新行并进状态；尾部半行作为样本的最后一行并进去。

    字节纪律与 _count_usage_scan 一致：整行推进、半行不推进 offset（内容随时
    可能被写完整，下次从同一位置按完整内容重折）。但半行在**样本**里算一行
    ——_tail_lines 就是这么数的（它把末尾没有换行的残余当一行）——所以它进环，
    只是每次重折前先摘掉上一轮那一份。

    返回"样本变没变"：没变时渲染可以整段跳过（0 新字节的 TTL 重算就是这条路）。
    """
    ring = state["ring"]
    if state["pending"]:
        _perf_pop_last(state)
        state["pending"] = False
    offset = state["offset"]
    pending_raw = None
    try:
        with _open(_usage_log_path(), "rb") as fh:
            fh.seek(offset)
            while True:
                raw = fh.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    pending_raw = raw
                    break
                line = raw.decode("utf-8", "replace").strip()
                if line:
                    _perf_push(state, line)
                offset += len(raw)
    except FileNotFoundError:
        pass
    except OSError as exc:
        _log("perf incremental read failed: %s" % exc)
    changed = offset != state["offset"] or pending_raw != state["pending_raw"]
    state["offset"] = offset
    state["pending_raw"] = pending_raw
    if pending_raw is not None and pending_raw.strip() and state["sample"] > 0:
        line = pending_raw.decode("utf-8", "replace").strip()
        if line:
            _perf_push(state, line)
            state["pending"] = True
    return changed

def _perf_payload(state):
    """把环形样本的聚合渲染成载荷（键序与字段与旧实现逐字一致）。

    输出里三层桶的顺序 = 各桶在样本里**第一次出现**的顺序（整段重扫时天然
    如此）。增量维护这个顺序要在每次淘汰时重排，比这里一趟扫描还贵；所以
    渲染时扫一遍环把顺序还原出来——只读环、不解析，而且桶都见齐就停。
    """
    agg = state["agg"]
    order = {}          # model -> realm -> account（插入序 = 第一次出现序）
    sample_from = None
    want = len(agg["m"])
    for realms in agg["mr"].values():
        want += len(realms)
    for realms in agg["ma"].values():
        for accts in realms.values():
            want += len(accts)
    seen = 0
    for entry in state["ring"]:
        if entry is None:
            continue
        if sample_from is None and entry[0] is not None:
            sample_from = entry[0]
        if len(entry) < _PERF_REC_LEN:
            continue
        realms = order.get(entry[1])
        if realms is None:
            realms = order[entry[1]] = {}
            seen += 1
        accts = realms.get(entry[2])
        if accts is None:
            accts = realms[entry[2]] = {}
            seen += 1
        if entry[3] not in accts:
            accts[entry[3]] = None
            seen += 1
        if seen >= want:
            break
    by_model = {}
    by_model_realm = {}
    by_model_acct = {}
    for mid, realms in order.items():
        mb = agg["m"][mid]
        by_model[mid] = {
            "requests": mb["total"],
            "errors": mb["err"],
            "client_aborted": mb["aborted"],
            "success_rate_pct": round(mb["ok"] * 100.0 / (mb["ok"] + mb["err"]), 1)
                                 if (mb["ok"] + mb["err"]) else None,
            "ttft_ms": _perf_block(mb["ttfts"]),
            "generation_ms": _perf_block(mb["gens"]),
            "wall_ms": _perf_block(mb["walls"]),
            "tokens_per_sec": _perf_block(mb["tok_rates"]),
            "cache_hit_pct": _perf_block(mb["hits"]),
        }
        realm_out = {}
        acct_out = {}
        for realm, accts in realms.items():
            rb = agg["mr"][mid][realm]
            realm_out[realm] = {
                "requests": rb["total"],
                "errors": rb["err"],
                "client_aborted": rb["aborted"],
                "success_rate_pct": round(rb["ok"] * 100.0 / (rb["ok"] + rb["err"]), 1)
                                     if (rb["ok"] + rb["err"]) else None,
                "ttft_ms": _perf_block(rb["ttfts"]),
                "generation_ms": _perf_block(rb["gens"]),
                "wall_ms": _perf_block(rb["walls"]),
                "tokens_per_sec": _perf_block(rb["tok_rates"]),
                "cache_hit_pct": _perf_block(rb["hits"]),
            }
            accts_out = {}
            for acct in accts:
                ab = agg["ma"][mid][realm][acct]
                accts_out[acct] = {
                    "requests": ab["total"],
                    "errors": ab["err"],
                    "client_aborted": ab["aborted"],
                    "success_rate_pct": round(ab["ok"] * 100.0 / (ab["ok"] + ab["err"]), 1)
                                         if (ab["ok"] + ab["err"]) else None,
                    "ttft_ms": _perf_block(ab["ttfts"]),
                    "generation_ms": _perf_block(ab["gens"]),
                    "wall_ms": _perf_block(ab["walls"]),
                    "tokens_per_sec": _perf_block(ab["tok_rates"]),
                    "cache_hit_pct": _perf_block(ab["hits"]),
                }
            acct_out[realm] = accts_out
        by_model_realm[mid] = realm_out
        by_model_acct[mid] = acct_out
    return {
        "sampled": agg["total"],
        # Where the sampled slice starts and whether it was cut short, so a
        # week/month view can admit that its latency columns do not reach back
        # to the window's own start.
        "sample_from": sample_from,
        "sample_capped": len(state["ring"]) >= state["sample"],
        "success": agg["ok"],
        "errors": agg["err"],
        "client_aborted": agg["aborted"],
        # Success rate is measured against requests the gateway actually
        # finished; client cancellations are reported separately rather than
        # being counted as failures.
        "success_rate_pct": round(agg["ok"] * 100.0 / (agg["ok"] + agg["err"]), 1)
                             if (agg["ok"] + agg["err"]) else None,
        "ttft_ms": _perf_block(agg["ttfts"]),
        "generation_ms": _perf_block(agg["gens"]),
        "wall_ms": _perf_block(agg["walls"]),
        "tokens_per_sec": _perf_block(agg["tok_rates"]),
        "cache_hit_pct": _perf_block(agg["hits"]),
        "by_model": by_model,
        "by_model_realm": by_model_realm,
        "by_model_acct": by_model_acct,
    }

def _log_complete_frontier(path=None):
    """最后一个换行之后的字节偏移：整行折叠从这里开始。

    日志的尾巴可能是写了一半的一行（没有换行符），它算样本的一行但不算已折
    的字节——offset 停在这里，等它写完整再从同一位置重折。向前找换行只在
    冷路径（或位置校验作废）上做，通常第一次读就命中。
    """
    path = path or _usage_log_path()
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0
    chunk = 256 * 1024
    pos = size
    try:
        with _open(path, "rb") as fh:
            while pos > 0:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                idx = fh.read(step).rfind(b"\n")
                if idx >= 0:
                    return pos + idx + 1
    except OSError:
        return 0
    return 0

def _perf_rebuild(key, sample, realm, since, until):
    """冷启动 / 位置校验不过：从日志尾部的 sample 行重建环形状态。"""
    state = {"sample": sample, "realm": realm, "since": since, "until": until,
             "key": None, "offset": 0, "tail": b"", "ring": deque(),
             "n_at": 0, "pending": False, "pending_raw": None,
             "agg": _perf_new_agg(), "at": 0.0,
             "dirty": True, "payload": None}
    raw_lines = _tail_lines(_usage_log_path(), sample)
    frontier = _log_complete_frontier()
    try:
        size = os.path.getsize(_usage_log_path())
    except OSError:
        size = 0
    pending_raw = None
    if size > frontier:
        try:
            with _open(_usage_log_path(), "rb") as fh:
                fh.seek(frontier)
                pending_raw = fh.read()
        except OSError:
            pending_raw = None
    # 尾部半行由 _tail_lines 算进样本的最后一行（末尾残余非空白时），这里把它
    # 从"完整行"里摘出来单独折——下面 offset 停在它前面，重折路径与它一致。
    if raw_lines and pending_raw is not None and raw_lines[-1] == pending_raw:
        raw_lines = raw_lines[:-1]
    for raw in raw_lines:
        line = raw.decode("utf-8", "replace").strip()
        if line:
            _perf_push(state, line)
    state["offset"] = frontier
    if pending_raw is not None and pending_raw.strip() and sample > 0:
        line = pending_raw.decode("utf-8", "replace").strip()
        if line:
            _perf_push(state, line)
            state["pending"] = True
    state["key"] = _usage_log_key()
    state["tail"] = _log_tail_signature(frontier)
    state["at"] = time.time()
    _perf_state[key] = state
    return state

def _perf_trim_states():
    """状态数超上限时按最近使用淘汰（载荷缓存另有 TTL，不受影响）。"""
    while len(_perf_state) > _PERF_STATE_MAX:
        oldest = min(_perf_state, key=lambda k: _perf_state[k]["at"])
        del _perf_state[oldest]

def _perf_stats_incremental(key, sample, realm, since, until):
    """perf_stats 的增量重建：输出与 _perf_stats_uncached 逐字节一致。

    必须在 _perf_lock 里调用（perf_stats 就是这么调的，与"重建在锁里做"的
    旧意图一致）：状态与载荷缓存由同一把锁保护。
    """
    try:
        state = _perf_state.get(key)
        log_key = _usage_log_key()
        if state is None or not _log_resume_ok(state, log_key):
            # 没有状态，或日志被截断/换掉/同尺寸重写（P:2525-2540 那套位置
            # 校验）：从尾部样本重建。
            state = _perf_rebuild(key, sample, realm, since, until)
        else:
            if _perf_fold(state):
                state["dirty"] = True
            state["key"] = _usage_log_key()
            state["tail"] = _log_tail_signature(state["offset"])
        if state["dirty"] or state["payload"] is None:
            # 样本没变就不重渲染：0 新字节的 TTL 重算到此为止（几十微秒），
            # 不再对每个桶重排序求分位。
            state["payload"] = _perf_payload(state)
            state["dirty"] = False
        payload = state["payload"]
        state["at"] = time.time()
        _perf_trim_states()
        return payload
    except Exception as exc:
        # 任何意外都退回旧的整段重建：状态作废（不留半折的账），这一次仍然
        # 给出正确载荷；旧实现遇到同样的输入会抛一样的异常，这里不会更差。
        _perf_state.pop(key, None)
        _log("perf incremental failed, falling back to full scan: %s" % exc)
        return _perf_stats_uncached(sample, realm, since=since, until=until)

_snap_cache = {}

_snap_lock = threading.Lock()

_STATS_TTL = ca_env.number("WB_STATS_TTL", 15.0, minimum=0.0, zero_ok=True)

def _scan_daily_usage(offset, state):
    """Fold rows at/after today's local midnight into `state`.

    Returns (state, new_offset). A line without its trailing newline is left
    for the next scan: rows are appended whole, so a partial tail only means
    this read raced the writer.
    """
    midnight = _local_midnight()
    with _open(_usage_log_path(), encoding="utf-8") as fh:
        fh.seek(offset)
        while True:
            pos = fh.tell()
            line = fh.readline()
            if not line:
                break
            if not line.endswith("\n"):
                return state, pos
            offset = fh.tell()
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            if (row.get("at") or 0) < midnight:
                continue
            # Same rule as the analytics scan: a client cancellation is not a
            # consumed request, and its token counts are incomplete.
            if row_outcome(row) == "client_aborted":
                continue
            uid = row.get("account")
            if not uid:
                continue
            tokens = row.get("total_tokens") or 0
            state["tokens"][uid] = state["tokens"].get(uid, 0) + tokens
            credit = row.get("credit") or 0
            if credit:
                state["credits"][uid] = state["credits"].get(uid, 0.0) + credit
            mid = row.get("model")
            if mid:
                per = state["models"].setdefault(uid, {})
                per[mid] = per.get(mid, 0) + tokens
    return state, offset

LIMIT_WINDOW_SECONDS = 24 * 3600

LIMIT_EVENTS_FILE = os.path.join(_usage_dir(), "limit-events.jsonl")

_ESTIMATE_SCHEMA = 1

_ESTIMATE_WEIGHTS = (6, 3, 1)

_ESTIMATE_KEEP_DAYS = len(_ESTIMATE_WEIGHTS)

_ESTIMATE_SEGMENT_DAYS = 2

_REMAINING_KEEP_SECONDS = 26 * 3600

_REMAINING_MAX_EVENTS = 1000

_remaining_state = {
    "events": [],          # 事件列表，src 标来源（file / log）
    "keys": set(),         # (账号, 模型, 重置时刻) 去重
    "usage": {},           # (uid, model) -> _pair_buffer() 的 {at,cum,head,base}
    "log": {"offset": 0, "key": None, "tail": b""},      # usage.jsonl 的续读位
    "file": {"offset": 0, "key": None, "tail": b""},     # limit-events.jsonl 的
    # 内存字段（不进 checkpoint，schema 不动）：事件表当前覆盖到哪个本地日，
    # 跨天归档的触发依据。重启后为空 -> 第一次构建按「刚过去的那天」试归档
    # 一次（幂等；数据不在就跳过），再置为今天。
    "day": "",
}

_remaining_state_lock = threading.Lock()

_remaining_cache = {"at": 0.0, "built_at": 0.0, "data": None}

_remaining_cache_lock = threading.Lock()

_estimate_daily_cache = {"entry": ((None, None, None), {})}

_estimate_daily_lock = threading.Lock()

def _pair_buffer(state, key):
    """The (at, cum) buffers of one (account, model), created on demand.

    Two parallel lists instead of a deque of (at, tokens) tuples: window sums
    then cost two bisections plus one subtraction over `cum`, and appends stay
    O(1). Only the timestamps and the running sum are kept - a row's token
    count is never read again once it is folded into `cum`, so a third list
    would be pure memory. stdlib only, and `bisect` is a builtin module on
    every CPython (unlike `array`, a shared extension on Linux), so this stays
    import-safe however the gateway is packaged.
    `head` is the first live index, `base` the token sum of everything trimmed
    away so far - `cum` keeps counting from the very first row ever buffered,
    so a range whose left edge falls on the first live entry has to subtract
    `base` instead of a predecessor.
    """
    buf = state["usage"].get(key)
    if buf is None:
        buf = state["usage"][key] = {"at": [], "cum": [], "head": 0, "base": 0}
    return buf

def _pair_append(buf, at, tokens):
    """Append one (at, tokens) sample, keeping the buffer sorted by `at`.

    The rows arrive in log order, but `at` is the request *completion* clock:
    two request threads finishing milliseconds apart can append out of order
    (the real log has a pair 4.96ms apart; the router's own checkpoint one
    0.47ms). `_range_sum` bisects these lists, so a single inversion would
    make the window sums skip or double-count whole stretches - the sorted
    insert (O(n) memmove on a pair that holds tens to hundreds of samples)
    is what keeps the bisection premise true. The common in-order append
    stays O(1) exactly as before.
    """
    # coerce: a log row is free text, and these buffers only ever hold numbers
    tokens = int(tokens)
    at = float(at)
    ats = buf["at"]
    if not ats or at >= ats[-1]:
        ats.append(at)
        buf["cum"].append((buf["cum"][-1] if buf["cum"] else 0) + tokens)
        return
    cum = buf["cum"]
    head = buf["head"]
    index = bisect.bisect_right(ats, at)
    if index < head:
        # The sample belongs before the dead prefix: compact it away first
        # (same absolute-base rule as _pair_trim), because the freshly folded
        # row is live by definition and must not land behind `head`.
        buf["base"] = cum[head - 1]
        del ats[:head]
        del cum[:head]
        buf["head"] = 0
        index = bisect.bisect_right(ats, at)
    ats.insert(index, at)
    # cum holds absolute prefix sums; every entry after the insert point
    # moves up by this sample's tokens.
    cum.insert(index, (cum[index - 1] if index else buf["base"]) + tokens)
    for i in range(index + 1, len(cum)):
        cum[i] += tokens

def _pair_repair(buf):
    """Canonicalize a (possibly out-of-order) pair buffer; False = unrepairable.

    A checkpoint written before this fix carries the buffers in log order,
    where `at` can regress by milliseconds (the router's own 674KB file does
    exactly that and was rejected whole). The loading side no longer demands
    an ordered list: this function stable-sorts the live region by `at` and
    rebuilds cum/head/base, so every (at, amount) pairing survives and each
    window sum equals the value recomputed on the sorted sequence. The dead
    prefix is physically dropped here (base keeps the absolute rule of
    _pair_trim's compaction), which leaves the state with exactly the live
    entries a cold fold would have. A negative amount (cum going backwards)
    is corrupt data: False makes the caller reject the entry and fall back
    to the cold fold.
    """
    at = buf["at"]
    cum = buf["cum"]
    head = buf["head"]
    if len(at) != len(cum) or not 0 <= head <= len(at):
        return False
    if head >= len(at):
        return False
    origin = cum[head - 1] if head else buf["base"]
    pairs = []
    prev = origin
    for i in range(head, len(cum)):
        amount = cum[i] - prev
        if amount < 0:
            return False
        pairs.append((at[i], amount))
        prev = cum[i]
    pairs.sort(key=lambda item: item[0])
    rebuilt_at = []
    rebuilt_cum = []
    total = origin
    for value, amount in pairs:
        rebuilt_at.append(value)
        total += amount
        rebuilt_cum.append(total)
    buf["at"] = rebuilt_at
    buf["cum"] = rebuilt_cum
    buf["head"] = 0
    buf["base"] = origin
    return True

def _pair_trim(buf, cutoff):
    """Drop entries older than `cutoff` (batched: the lists are compacted only
    when the dead prefix is big enough to pay for the memmove)."""
    at = buf["at"]
    while buf["head"] < len(at) and at[buf["head"]] < cutoff:
        buf["head"] += 1
    if buf["head"] > 512 and buf["head"] * 2 > len(at):
        # base 是「被裁掉前缀的累计和」的**绝对值**，不是增量：cum 从最早的一行
        # 累计、切片不重置，所以 cum[head-1] 已经把之前裁掉的都算进去了。写成
        # += 会让第二次压缩起把前缀重复计入，之后任何左端落在保留区之前的
        # 区间求和都会变成负数（真机上「上段」显示过 -1293.5M）。
        buf["base"] = buf["cum"][buf["head"] - 1]
        del at[:buf["head"]]
        del buf["cum"][:buf["head"]]
        buf["head"] = 0

def _range_sum(buf, lo, hi):
    """Tokens of one (account, model) with lo <= at <= hi. O(log n)."""
    if buf is None or buf["head"] >= len(buf["at"]):
        return 0
    at = buf["at"]
    j = bisect.bisect_left(at, lo, buf["head"])
    k = bisect.bisect_right(at, hi, buf["head"])
    if k <= j:
        return 0
    # cum 自最早的缓冲行累计；左端落到第一个存活条目时（j 在列表头），
    # 前面的累计值已被裁掉，只能拿 base 补回那段前缀。
    low = buf["cum"][j - 1] if j > 0 else buf["base"]
    return buf["cum"][k - 1] - low

def _range_sum_open(buf, lo, hi):
    """Tokens of one (account, model) with lo <= at < hi. O(log n).

    与 _range_sum 只差右端：日界用左闭右开（恰好落在午夜那一刻的行属于后一
    天），归档的当天用量与分段都按这个口径算，pre + post 的不变式在整秒边界
    上也不会多算一行。
    """
    if buf is None or buf["head"] >= len(buf["at"]):
        return 0
    at = buf["at"]
    j = bisect.bisect_left(at, lo, buf["head"])
    k = bisect.bisect_left(at, hi, buf["head"])
    if k <= j:
        return 0
    low = buf["cum"][j - 1] if j > 0 else buf["base"]
    return buf["cum"][k - 1] - low

def _merge_event(state, event, source):
    """Add one cap event, deduplicated by (account, model, reset).

    The first source to record a given cap wins: the request path's event is
    written the moment the 429 is handled, the log-derived one only appears
    when a scan reaches that row.
    """
    uid = str(event.get("account") or "")
    model = str(event.get("model") or "")
    try:
        reset = float(event.get("reset") or 0)
    except (TypeError, ValueError):
        return
    if not uid or not model or reset <= 0:
        return
    key = (uid, model, reset)
    if key in state["keys"]:
        return
    state["keys"].add(key)
    state["events"].append({
        "at": float(event.get("at") or 0), "reset": reset, "account": uid,
        "model": model, "realm": str(event.get("realm") or ""),
        "sample": int(event.get("sample") or 0), "src": source,
    })
    if len(state["events"]) > _REMAINING_MAX_EVENTS:
        # 从头部丢弃时同步清去重键：丢掉的键将来重新出现（重放日志）会再被
        # 收进来，不会因为键还留着而被静默跳过。
        dropped = state["events"][: len(state["events"]) - _REMAINING_MAX_EVENTS]
        del state["events"][: len(dropped)]
        for old in dropped:
            state["keys"].discard((old["account"], old["model"], old["reset"]))

def _drop_events(state, source):
    """Forget the events one source contributed (its file was rewritten)."""
    kept = [event for event in state["events"] if event["src"] != source]
    for event in state["events"]:
        if event["src"] == source:
            state["keys"].discard((event["account"], event["model"], event["reset"]))
    state["events"] = kept

def _window_sample(usage, uid, model, reset_at, at, start=None):
    """Usage of (uid, model) inside the window ending at `reset_at`.

    `start` 覆盖默认的窗口起点（重置时刻 − 24h）：链式撞线（上一个重置时刻
    落在 24h 之内）时窗口从上一个重置时刻起算，旧窗口的用量不进这个样本。
    """
    lo = reset_at - LIMIT_WINDOW_SECONDS if start is None else start
    return _range_sum(usage.get((uid, model)), lo, at)

def _cap_anchor(entries, at, reset):
    """把一个撞线锚点（撞线时刻 at + 恢复时刻 reset）并进 entries。

    entries 以 reset 为键去重：同一个重置时刻从事件日志与凭证档各来一份时
    只算一个锚点；at 取两者中较晚的（这个窗口最后被观测到还在消耗的时刻，
    截断点宁晚勿早——截早了会漏掉真实计过量的行）。
    """
    try:
        at = float(at or 0)
        reset = float(reset or 0)
    except (TypeError, ValueError):
        return
    if reset <= 0:
        return
    old = entries.get(reset)
    if old is None or at > old["at"]:
        entries[reset] = {"at": at, "reset": reset}

def _cap_anchors(events, uid, model):
    """(账号, 模型) 的锚点表，来自事件日志里该组合的全部事件。"""
    entries = {}
    for event in events:
        if event["account"] == uid and event["model"] == model:
            _cap_anchor(entries, event["at"], event["reset"])
    return entries

def _cap_window_start(entries, reset):
    """窗口起点：链上上一个重置时刻（落在 24h 内时），否则重置时刻 − 24h。

    上游的窗口锚定比「固定 24h 链」复杂（实测同组合的重置时刻有 48h+ 的空
    档），所以只用上游给的重置时刻这一个事实：上一个重置时刻落在 24h 窗口
    之内时它就是本窗口的起点（链式撞线，旧窗口的用量不得计进新窗口）；之
    外时窗口不超过 24h，起点取重置时刻 − 24h。
    """
    prev = 0.0
    for other in entries:
        if other < reset and other > prev:
            prev = other
    return max(prev, reset - LIMIT_WINDOW_SECONDS)

def _fold_remaining(row, state):
    """Fold one usage.jsonl row into the remaining-usage state.

    The row order is the log's append order, so the trim below can use each
    row's own `at` as "now": rows only ever get newer, and a row older than
    the retention window can never be needed again.
    """
    uid = row.get("account")
    model = row.get("model")
    if not uid or not model:
        return
    at = row.get("at") or 0
    if not at:
        return
    key = (uid, model)
    if row.get("status") == 429:
        reset = parse_rate_limit_reset(str(row.get("message") or ""))
        if reset is None:
            return
        # 样本按段截断：链式撞线时从上一个重置时刻起算（旧窗口的用量不进
        # 新窗口的样本），没撞过线时就是默认的重置时刻 − 24h。
        anchors = _cap_anchors(state["events"], uid, model)
        _merge_event(state, {
            "at": at, "reset": reset, "account": uid, "model": model,
            # 归一：历史行里写着已删区域的（intl）要和账号侧的 cn 对齐，否则
            # 预算按 (intl, model) 建、按 (cn, model) 查，永远查不到。
            "realm": normalize_realm(row.get("realm") or ""),
            "sample": _window_sample(state["usage"], uid, model, reset, at,
                                     _cap_window_start(anchors, reset)),
        }, "log")
        return
    if row.get("error") or row.get("usage_missing"):
        return
    if row_outcome(row) == "client_aborted":
        return
    buf = _pair_buffer(state, key)
    _pair_append(buf, at, row.get("total_tokens") or 0)
    _pair_trim(buf, at - _REMAINING_KEEP_SECONDS)

def _remaining_refresh(state):
    """Fold both files' new rows into `state`; caller holds the state lock.

    Same pass rules as the other folds: an unreadable or rewritten file resets
    the contributions it fed instead of publishing a half-folded one. The
    usage log is folded first so the event journal's samples (computed against
    it at cap time) and the log-derived events describe the same buffers.

    A brand-new process asks the checkpoint first: the cold scan is the only
    cost here that grows with the log (a few MB a day), so restarting should
    not pay it again. Missing or stale -> fold from zero, as before.
    """
    if state["log"].get("key") is None:
        _usage_cache_adopt_remaining(state, _usage_log_key())
    for source, path in (("log", _usage_log_path()), ("file", LIMIT_EVENTS_FILE)):
        slot = state[source]
        log_key = _usage_log_key(path)
        if not _log_resume_ok(slot, log_key, path):
            # 文件被换掉/截短：这个来源的贡献全部作废，从零重折。
            state[source] = {"offset": 0, "key": log_key, "tail": b""}
            if source == "log":
                state["usage"].clear()
            _drop_events(state, source)
        fold = (lambda row: _fold_remaining(row, state)) if source == "log" \
            else (lambda row: _merge_event(state, row, "file"))
        offset, error = _scan_usage_from(state[source]["offset"], fold, path=path)
        if error is None:
            state[source]["offset"] = offset
            state[source]["tail"] = _log_tail_signature(offset, path)
        else:
            _log("remaining usage fold failed (%s): %s" % (source, error))
            state[source] = {"offset": 0, "key": log_key, "tail": b""}
            if source == "log":
                state["usage"].clear()
            _drop_events(state, source)

def _budget_means(per_account):
    """{账号: [样本]} -> {avg, min, max, n}：先按账号平均、再跨账号平均。

    一个账号反复撞线只算一个样本（它自己样本的均值），所以跨账号平均称的是
    账号而不是事件；min/max/n 都是账号均值的极值与个数（沿用既有口径）。
    """
    means = [int(round(sum(v) / float(len(v)))) for v in per_account.values()]
    return {"avg": int(round(sum(means) / float(len(means)))),
            "min": min(means), "max": max(means), "n": len(means)}

def _estimate_budget_entry_ok(entry):
    """归档文件里一天的口径：{avg,min,max,n} 都是数字且 n > 0 才算数。

    文件在数据目录里、可能被手改或半写坏：任何一项不合形状就跳过这一天，
    估算退化成「那天没样本」，绝不因此让载荷构建报错。
    """
    if not isinstance(entry, dict):
        return False
    if not _usage_cache_int(entry.get("n")) or entry["n"] <= 0:
        return False
    return all(_usage_cache_number(entry.get(field))
               for field in ("avg", "min", "max"))

def _estimate_day_keys(now):
    """估算窗口的日键，就近在前：[今天, 昨天, 前天]。"""
    return [_local_day_key(_local_midnight(now, days_back=back))
            for back in range(_ESTIMATE_KEEP_DAYS)]

def _estimate_daily_stamp():
    """estimate-daily.json 的 (路径, mtime_ns, size)；文件不在时后两项为 None。

    路径也在戳里：--usage-dir 换目录后，不会被旧目录的戳骗过去（两个目录里
    恰好有 mtime/大小相同的文件几乎不可能，但也没必要赌）。
    """
    try:
        st = os.stat(_estimate_daily_file())
        return (_estimate_daily_file(), st.st_mtime_ns, st.st_size)
    except OSError:
        return (_estimate_daily_file(), None, None)

def _estimate_daily_read():
    """estimate-daily.json 的 days 表；坏文件/读不到按空表处理。

    按戳记忆解析结果：写盘路径主动刷新缓存，外部改动（手改、另一个进程）靠
    stat 变化发现。这是估算的加速件，任何一步不成立都只是回到「没有归档」
    （今天现算、更早的天跳过），绝不能因此报错。
    """
    stamp = _estimate_daily_stamp()
    cached_stamp, cached_days = _estimate_daily_cache["entry"]
    if cached_stamp == stamp:
        return cached_days
    days = {}
    if stamp[1] is not None:
        try:
            with _open(_estimate_daily_file(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError, UnicodeDecodeError):
            data = None
        if isinstance(data, dict) and data.get("schema") == _ESTIMATE_SCHEMA \
                and isinstance(data.get("days"), dict):
            days = {day: record for day, record in data["days"].items()
                    if _usage_cache_day_key_ok(day) and isinstance(record, dict)}
    _estimate_daily_cache["entry"] = (stamp, days)
    return days

def _estimate_daily_write(days):
    """原子写 estimate-daily.json（同目录 .tmp + os.replace，同 checkpoint）。"""
    os.makedirs(_usage_dir(), exist_ok=True)
    tmp = _estimate_daily_file() + ".tmp"
    text = json.dumps({"schema": _ESTIMATE_SCHEMA, "days": days},
                      ensure_ascii=False, separators=(",", ":"))
    try:
        with _open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, _estimate_daily_file())
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _estimate_daily_view(daily, archived):
    """文件表 + 本次归档的内存视图：该天已在文件里就用文件里的（幂等口径）。

    本次构建的估算直接读这份视图，跨天那一轮的载荷不用等下一轮才看到昨天；
    已被持久化下来的那天不会被这次重算的值盖掉（「调昨天的数据不重新计算」）。
    """
    if not archived:
        return daily
    view = dict(daily)
    for day, record in archived.items():
        view.setdefault(day, record)
    return view

def _estimate_daily_sync(archived, now):
    """把归档记录合并进文件、按保留策略裁剪；内容不变就不写盘。

    幂等：该天已在文件里就不覆盖（重启/重复构建不会写第二遍、也不会用重算的
    值盖掉持久化下来的值）。保留：只留估算窗口内的最近 3 天，更早的天整条
    删掉；分段只留最近 2 天（用户要求「仅保留到第二天」，多留一天防跨天
    边界），更早的天删掉 segments 字段、预算保留到 3 天。

    写盘在状态锁外做（与 checkpoint 同款理由：写盘在状态锁里会构成锁序环），
    用写锁串行、原子替换；失败只记日志——这是估算的加速件，不影响请求。
    """
    with _estimate_daily_lock:
        days = dict(_estimate_daily_read())
        changed = False
        for day, record in (archived or {}).items():
            if day not in days:
                days[day] = record
                changed = True
        keep = _estimate_day_keys(now)
        segment_days = set(keep[:_ESTIMATE_SEGMENT_DAYS])
        pruned = {}
        for day, record in days.items():
            if day not in keep:
                changed = True
                continue
            if day not in segment_days and record.get("segments"):
                record = dict(record)
                record.pop("segments", None)
                changed = True
            pruned[day] = record
        if changed:
            try:
                _estimate_daily_write(pruned)
            except Exception as exc:
                _log("estimate daily write failed: %s" % exc)
        # 缓存换成刚算好的表（含本次归档与裁剪）：写失败也不重试——这份表就是
        # 「本进程认为文件里有什么」，与 checkpoint 的「记尝试不记成功」同款。
        _estimate_daily_cache["entry"] = (_estimate_daily_stamp(), pruned)

def _remaining_archive_due(state, now, realm_of):
    """跨天（或重启后第一次构建）时归档刚过去的那天。

    调用方持有状态锁（归档要读事件表与用量缓冲）。返回 {日键: 记录}，没跨天
    或没有可归档的数据返回 None。state["day"] 是内存字段、不进 checkpoint：
    重启后为空，第一次构建按「刚过去的那天」试一次——幂等，数据不在就跳过，
    再置为今天（无论归档成没成）。
    """
    today = _local_day_key(now)
    stale = state.get("day") or ""
    if stale == today:
        return None
    state["day"] = today
    if not stale or stale >= today:
        # 重启后为空（或时钟回拨、stale 落在未来）：按「刚过去的那天」= 昨天。
        stale = _local_day_key(_local_midnight(now, days_back=1))
    if stale == today:
        return None
    record = _remaining_archive_day(state, stale, realm_of)
    return {stale: record} if record else None

def _remaining_archive_day(state, day, realm_of):
    """一天的量归档：当天样本的预算口径 + 每个组合的截断前后分段。

    budgets：撞线时刻 event["at"] 落在那天的样本，先按账号平均、再跨账号
    平均（沿用查询侧口径）。segments：那天每个 (uid, model) 的 pre/post。
    两样都空（数据不在缓冲里 / 当天没有样本）返回 None——调用方跳过不写。
    """
    start = _day_key_start(day)
    end = start + 86400
    events = [event for event in state["events"]
              if _local_day_key(event["at"]) == day]
    samples = {}
    for event in events:
        if event["sample"] <= 0:
            continue
        realm = event["realm"] or realm_of.get(event["account"], "")
        samples.setdefault((realm, event["model"]), {}) \
               .setdefault(event["account"], []).append(event["sample"])
    budgets = {"%s\x1f%s" % key: _budget_means(per_account)
               for key, per_account in samples.items()}
    segments = _remaining_archive_segments(state, events, start, end)
    if not budgets and not segments:
        return None
    return {"budgets": budgets, "segments": segments}

def _remaining_archive_segments(state, events, start, end):
    """那天每个 (uid, model) 的截断前 / 截断后用量。

    post = 恢复时刻落在当天的窗口在当天内的用量之和（从恢复时刻到「下一个
    撞线时刻或当天结束」）；pre = 当天该组合总用量 − post（不变式：pre + post
    == 当天该组合的用量，用缓冲的区间求和算）。两个都是 0 的组合不写。
    """
    caps = {}
    for event in events:
        caps.setdefault((event["account"], event["model"]), []).append(
            (event["at"], event["reset"]))
    segments = {}
    for (uid, model), buf in state["usage"].items():
        total = _range_sum_open(buf, start, end)
        pair_caps = caps.get((uid, model)) or ()
        post = 0
        for _at, reset in pair_caps:
            if not start <= reset < end:
                continue
            nxt = end
            for other_at, _other_reset in pair_caps:
                if reset < other_at < nxt:
                    nxt = other_at
            post += _range_sum_open(buf, reset, min(nxt, end))
        if total <= 0 and post <= 0:
            continue
        segments["%s\x1f%s" % (uid, model)] = {"pre": total - post, "post": post}
    return segments



def _remaining_activity_floor(now):
    """「昨日 00:00」：本地时区里 now 所在日的前一天零点。

    参与剩余用量计算的判定下界（昨天或今天有消耗才算在用）。取整天边界而
    不是 now − 24h，因为需求写的是「昨日或当日」；同一天里这个下界不变，
    面板因此不会在轮询之间来回抖动。
    """
    lt = time.localtime(now)
    midnight = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
    return midnight - LIMIT_WINDOW_SECONDS


def _remaining_budgets(events, realm_of, now, daily):
    """(realm, model) -> 近 3 天加权的窗口预算估计。

    样本按撞线当天的本地日期分桶，取最近 3 天（今天/昨天/前天）：今天用内存
    里的事件现算，更早的天直接读 estimate-daily.json 里归档好的当天口径（不
    再重算——这就是持久化的意义）。权重就近高（今天 6 / 昨天 3 / 前天 1，见
    _ESTIMATE_WEIGHTS），只在有样本的天之间归一，某天没样本就跳过。只有撞过
    6004 的窗口才有样本（天然成立），某组合 3 天内没有样本就没有预算。

    载荷里保留 avg/min/max/n（min/max 取各天账号均值的极值，n 为各天账号数
    之和），并新增 days 列出各天构成（{day, w, avg, n}）供面板/排查用。
    """
    keys = _estimate_day_keys(now)
    per_day = {}
    samples = {}
    for event in events:
        if event["sample"] <= 0 or _local_day_key(event["at"]) != keys[0]:
            continue
        realm = event["realm"] or realm_of.get(event["account"], "")
        samples.setdefault((realm, event["model"]), {}) \
               .setdefault(event["account"], []).append(event["sample"])
    for key, per_account in samples.items():
        per_day.setdefault(key, {})[keys[0]] = _budget_means(per_account)
    # 昨天/前天：直接读归档文件里当天的口径（avg/min/max/n 都是现成的）。
    for day in keys[1:]:
        record = (daily or {}).get(day) or {}
        for pair_key, entry in (record.get("budgets") or {}).items():
            if not _estimate_budget_entry_ok(entry):
                continue
            realm, _, model = pair_key.partition("\x1f")
            if not model:
                continue
            per_day.setdefault((realm, model), {})[day] = entry
    budgets = {}
    for key, days in per_day.items():
        rows = []
        for index, day in enumerate(keys):
            entry = days.get(day)
            if not entry or entry.get("n", 0) <= 0:
                continue
            rows.append({"day": day, "w": _ESTIMATE_WEIGHTS[index],
                         "avg": int(round(entry["avg"])), "n": int(entry["n"])})
        if not rows:
            continue
        weight = sum(row["w"] for row in rows)
        budgets[key] = {
            "avg": int(round(sum(row["w"] * row["avg"] for row in rows)
                             / float(weight))),
            "min": min(int(round(days[row["day"]]["min"])) for row in rows),
            "max": max(int(round(days[row["day"]]["max"])) for row in rows),
            "n": sum(row["n"] for row in rows),
            "days": rows,
        }
    return budgets

def _remaining_payload(now=None, accounts=None):
    """Per-account remaining usage against the estimated per-model budget.

    Refreshes the fold and builds the payload in one pass under the state
    lock: nothing is copied out (the buffers stay put and are read through
    their cumulative sums), so a rebuild costs what the new rows cost plus
    O(pairs * log n), not a re-sum of every buffered row.

    Every enabled account is reported for every model that has a budget in its
    realm, plus every model it actually used inside the retention window - an
    account at 0 usage is the honest "full budget" answer, not noise. A pair
    still cooling on a spent window reports remaining 0 and the reset clock
    that hands the quota back.

    Models nobody burned since yesterday 00:00 do not take part at all
    (activity is judged per realm + model, see _remaining_activity_floor);
    their budget samples stay in the payload marked inactive so the panel can
    say "not counted" instead of dropping a budget it would take another cap
    to relearn.

    跨天归档：本地日期与 state["day"] 不同（或重启后为空）时，在状态锁内把
    刚过去的那天算成 {预算, 分段}，本次构建的估算立刻把它并进视图；文件写盘
    在锁外（见 _estimate_daily_sync）。
    """
    now = time.time() if now is None else now
    if accounts is None:
        accounts = []
    accounts = [a for a in accounts
                if getattr(a, "enabled", True) and getattr(a, "uid", "")]
    with _remaining_state_lock:
        state = _remaining_state
        _remaining_refresh(state)
        realm_of = {a.uid: (getattr(a, "realm", "") or "") for a in accounts}
        archived = _remaining_archive_due(state, now, realm_of)
        daily = _estimate_daily_view(_estimate_daily_read(), archived)
        payload = _remaining_payload_locked(state, now, accounts, realm_of, daily)
        offset = state["log"].get("offset") or 0
    # 归档与 checkpoint 的写盘都在锁外做（见 checkpoint 一节）：写盘要逐把读
    # 各份状态，在状态锁里再取别的状态锁会构成锁序环。折叠失败的那次 offset
    # 已归零，落盘函数会跳过。
    _estimate_daily_sync(archived, now)
    _usage_cache_maybe_save("remaining", offset)
    return payload

def _remaining_payload_locked(state, now, accounts, realm_of, daily):
    """The payload itself; caller holds the state lock and has refreshed."""
    budgets = _remaining_budgets(state["events"], realm_of, now, daily)
    # strftime/localtime is one of the few per-row costs left (30 rows ≈ 0.12ms,
    # 74% of the build) and rows overwhelmingly share their window start / reset
    # clock - so format each distinct second once per payload.
    iso_cache = {}

    def iso_at(ts):
        key = int(ts)
        out = iso_cache.get(key)
        if out is None:
            out = iso_cache[key] = time.strftime("%Y-%m-%d %H:%M:%S",
                                                 time.localtime(ts))
        return out

    # 撞线锚点：事件日志 + 凭证档里的 model_caps，按 (账号, 模型, 重置时刻)
    # 去重——重启后日志可能丢失/被裁，凭证档里持久化的记录是那时唯一的依据；
    # 反之凭证档写失败时日志还在。锚点决定冷却、窗口起点与截断点。
    anchors = {}
    for event in state["events"]:
        _cap_anchor(anchors.setdefault((event["account"], event["model"]), {}),
                    event["at"], event["reset"])
    for acct in accounts:
        caps = getattr(acct, "model_caps", None)
        if not isinstance(caps, dict):
            continue
        try:
            items = list(caps.items())
        except RuntimeError:
            # 恰好并发在记新撞线（note_model_cap 在另一把锁下改这张表）：
            # 这轮少一个锚点，下一轮重建就补上，不值得为它拿别人的锁。
            continue
        for model, entry in items:
            if isinstance(entry, dict):
                _cap_anchor(anchors.setdefault((acct.uid, str(model)), {}),
                            entry.get("at"), entry.get("reset"))

    # 按需过滤：昨天或今天没消耗过的模型不参与（判定见 _remaining_activity_floor）。
    # 消耗 = 缓冲里有行（最后一行的时间戳就是该组合最后一次用量），或撞线锚点
    # 落在下界之后——撞线是「把窗口用满」的证据，冷却中的组合不能因为旧行被裁
    # 掉就从面板上消失。
    floor = _remaining_activity_floor(now)
    active = set()
    for (uid, model), buf in state["usage"].items():
        realm = realm_of.get(uid)
        if realm is None or not buf["at"]:
            continue
        if buf["at"][-1] >= floor:
            active.add((realm, model))
    for (uid, model), entries in anchors.items():
        realm = realm_of.get(uid)
        if realm is None:
            continue
        if any(max(entry["at"], entry["reset"]) >= floor
               for entry in entries.values()):
            active.add((realm, model))

    rows = []
    totals = {}
    for acct in accounts:
        uid = acct.uid
        realm = realm_of.get(uid, "")
        models = set(model for (r, model) in budgets
                     if r == realm and (r, model) in active)
        models.update(model for (u, model) in state["usage"]
                      if u == uid and (realm, model) in active)
        for model in sorted(models):
            entries = anchors.get((uid, model)) or {}
            buf = state["usage"].get((uid, model))
            past = [e for e in entries.values() if e["reset"] <= now]
            future = [e for e in entries.values() if e["reset"] > now]
            last = max(past, key=lambda e: e["reset"]) if past else None
            upcoming = min(future, key=lambda e: e["reset"]) if future else None
            segments = []
            if upcoming is not None:
                # 窗口已用满：正在冷却，额度到恢复时刻才回来。这个窗口的记账
                # 在撞线处截断——已用到撞线时刻为止（上游已经拒收，撞线之后
                # 残留的行不算这个窗口的消耗），所以已用量≈预算，与剩余 0 对
                # 得上。窗口起点是链上上一个重置时刻（链式撞线时），否则重
                # 置时刻 − 24h。
                reset_at = upcoming["reset"]
                window_start = _cap_window_start(entries, reset_at)
                end = min(now, upcoming["at"] or reset_at)
                used = _range_sum(buf, window_start, end)
                segments.append({"start": window_start, "end": end, "used": used,
                                 "capped": True, "current": True,
                                 "start_iso": iso_at(window_start),
                                 "end_iso": iso_at(end)})
                cooling = True
                estimated = False
            elif last is not None:
                reset_at = last["reset"]
                window_start = max(reset_at, now - LIMIT_WINDOW_SECONDS)
                used = _range_sum(buf, window_start, now)
                cooling = False
                # 重置时刻超过 24h 的组合锚不住当前窗口：它那个窗口早已到期，
                # 现在这个窗口的起点未知，落在最近 24h 内的用量只是下界，与
                # 从没撞过线的组合同样标 estimated。
                estimated = reset_at < now - LIMIT_WINDOW_SECONDS
                if not estimated:
                    # 分段相加：上一段（上一个窗口，在它的撞线处截断）+ 本段
                    # （自恢复时刻起重新记账，旧窗口的用量不计进本段的已用）。
                    if last["at"] > 0:
                        prev_end = min(last["at"], reset_at)
                        prev_start = _cap_window_start(entries, reset_at)
                        segments.append({
                            "start": prev_start, "end": prev_end,
                            "used": _range_sum(buf, prev_start, prev_end),
                            "capped": True, "current": False,
                            "start_iso": iso_at(prev_start),
                            "end_iso": iso_at(prev_end)})
                    segments.append({"start": reset_at, "end": now, "used": used,
                                     "capped": False, "current": True,
                                     "start_iso": iso_at(reset_at),
                                     "end_iso": iso_at(now)})
            else:
                window_start = now - LIMIT_WINDOW_SECONDS
                used = _range_sum(buf, window_start, now)
                reset_at = None
                cooling = False
                estimated = True
            budget = budgets.get((realm, model))
            remaining = None
            pct = None
            if cooling:
                # 冷却中的组剩余记 0（没有预算也照记）：额度到恢复时刻才回来。
                remaining = 0
                pct = round(used * 100.0 / budget["avg"], 1) \
                    if budget and budget["avg"] else None
            elif budget:
                remaining = max(0, budget["avg"] - used)
                pct = round(used * 100.0 / budget["avg"], 1) if budget["avg"] else None
            rows.append({
                "uid": uid,
                "nickname": getattr(acct, "nickname", "") or "",
                "realm": realm,
                "model": model,
                "used": used,
                "budget": budget["avg"] if budget else None,
                "budget_min": budget["min"] if budget else None,
                "budget_max": budget["max"] if budget else None,
                "samples": budget["n"] if budget else 0,
                "remaining": remaining,
                "used_pct": pct,
                "window_start": window_start,
                "window_iso": iso_at(window_start),
                "reset_at": reset_at,
                "reset_iso": iso_at(reset_at) if reset_at else None,
                "cooling": cooling,
                "estimated": estimated,
                "segments": segments,
            })
            # 按模型总剩余 = 可用组的剩余之和：冷却/已满的组 remaining 本身就是
            # 0（只加不减，绝不把别的组拉低），没有预算的组计入 unknown 不计数。
            total = totals.get((realm, model))
            if total is None:
                total = totals[(realm, model)] = {
                    "realm": realm, "model": model, "total_remaining": None,
                    "budget": budget["avg"] if budget else None,
                    "pairs": 0, "available": 0, "cooling": 0,
                    "unknown": 0, "estimated": 0,
                }
            total["pairs"] += 1
            if cooling:
                total["cooling"] += 1
            if estimated:
                total["estimated"] += 1
            if remaining is None:
                total["unknown"] += 1
            else:
                total["total_remaining"] = (total["total_remaining"] or 0) + remaining
                if not cooling:
                    total["available"] += 1
    rows.sort(key=lambda r: (r["remaining"] is None,
                             r["remaining"] if r["remaining"] is not None else 0,
                             r["realm"], r["nickname"], r["model"]))
    return {
        "window_seconds": LIMIT_WINDOW_SECONDS,
        "generated_at": now,
        "generated_iso": iso_at(now),
        "activity_floor": floor,
        "activity_floor_iso": iso_at(floor),
        "budgets": [dict(budget, realm=realm, model=model,
                         active=(realm, model) in active)
                    for (realm, model), budget in sorted(budgets.items())],
        "models": sorted(totals.values(),
                         key=lambda m: (m["total_remaining"] is None,
                                        -(m["total_remaining"] or 0),
                                        m["realm"], m["model"])),
        "rows": rows,
    }

def _usage_snapshot_scope(realm, range, since, until):
    """(过滤用的 realm, since, until, 缓存键) —— usage_snapshot() 与它的 ETag 共用。

    同 _perf_stats_scope()：键只允许有一个来源，否则 ETag 可能指向另一条缓存。
    """
    r = realm_scope(realm, _current_realm())
    lo, hi = range_window(range, since, until)
    # Bounds, not a today/all flag: this week and this month overlap, so a
    # flag would let one window serve the other's totals from the cache.
    key = "%s|%s|%s" % (r or "all",
                        lo if lo is not None else "", hi if hi is not None else "")
    return r, lo, hi, key

def usage_snapshot(realm=None, ttl=None, range=None, since=None, until=None):
    """Cached wrapper: the dashboard polls this every few seconds.

    The rebuild happens while holding the lock on purpose. Releasing it first
    let every concurrent caller run its own full scan of the JSONL when the
    entry expired, so a single dashboard refresh could trigger several scans
    of the same file.
    """
    ttl = _bind__STATS_TTL() if ttl is None else ttl
    r, lo, hi, key = _usage_snapshot_scope(realm, range, since, until)
    now = time.time()
    with _snap_lock:
        hit = _snap_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
        data = _usage_snapshot_uncached(r, since=lo, until=hi)
        _snap_cache[key] = (time.time(), data)
    return data

def usage_snapshot_etag(realm=None, range=None, since=None, until=None):
    """usage_snapshot() 当前缓存条目的 ETag；条目不存在时返回 None。

    配对调用（取数前后各一次、一致才发）由 _json_cached() 负责，理由见那里。
    """
    _r, _lo, _hi, key = _usage_snapshot_scope(realm, range, since, until)
    with _snap_lock:
        hit = _snap_cache.get(key)
    if hit is None:
        return None
    return _cache_etag("usage", key, hit[0])

def _usage_log_key(path=None):
    """(size, device, inode) of the usage log, or a zero key when it is gone.

    One stat answers both questions an incremental fold has to ask. The size
    says whether the bytes the cached offset counted are still there: a
    shorter file was truncated, or replaced by a shorter one. The device and
    inode say whether it is still the same file at all - a log copied over in
    place keeps its inode and is caught by the size test, while one moved into
    position is a different file and a stale offset would point into the
    middle of unrelated rows.

    `path` defaults to the usage log; the remaining-usage fold keys its own
    event journal with the same rule.
    """
    try:
        info = os.stat(path or _usage_log_path())
        return (info.st_size, info.st_dev, info.st_ino)
    except OSError:
        return (0, 0, 0)

def _log_offset_holds(previous, current, offset):
    """True when `offset` still sits inside the file `previous` described.

    False means the cached fold counted bytes that are gone or belong to a
    different file now, so it has to start over.
    """
    return (previous is not None
            and previous[1] == current[1] and previous[2] == current[2]
            and current[0] >= offset)

_TAIL_SIGNATURE = 64

def _log_tail_signature(offset, path=None):
    """The last bytes before `offset`, or None when they cannot be read.

    An incremental fold assumes the bytes it has already counted are still
    there. Size and inode catch a log that was replaced or cut short, but
    not one that was emptied in place and has since grown past the old
    offset: same file, only longer, which is what truncating the log - or
    a log rotation with copytruncate - leaves behind. Reading the seam back
    is what tells those apart, because an append leaves it alone and a
    rewrite does not.
    """
    if offset <= 0:
        return b""
    try:
        with _open(path or _usage_log_path(), "rb") as fh:
            start = max(0, offset - _TAIL_SIGNATURE)
            fh.seek(start)
            return fh.read(offset - start)
    except OSError:
        return None

def _log_resume_ok(state, log_key, path=None):
    """True when the cached offset still sits on the log's current prefix.

    False means the fold cannot be carried over: the file shrank, it is a
    different file, or the bytes it counted were rewritten under it.
    """
    if not _log_offset_holds(state["key"], log_key, state["offset"]):
        return False
    return _log_tail_signature(state["offset"], path) == state["tail"]

def _pricing_inputs(pricing_on=None):
    """Everything cost_for_row() reads besides the row itself.

    Identity, not equality: ca_pricing caches each of these behind its own
    file key, so an edited file hands back a different object, and comparing
    identities keeps the check off the refresh path - walking the whole price
    table to notice a change would cost more than the change does. Holding the
    objects here is also what makes the test sound: a live object cannot have
    its id handed to a replacement.

    With the master switch off cost_for_row() never opens a table at all, so
    the flag is the whole input. It is read through the same no-argument
    call cost_for_row() makes - passing a directory here would answer from
    a different settings file whenever the two disagree, and the fingerprint
    would then watch an input the fold never read.
    """
    # 价格估算体系已下线（2026-10-22）：不再读价表，「关闭」是唯一状态。
    # 保留函数签名是因为快照 / 指纹 / 缓存三条链路都靠它开短路。
    return (False, None, None, None)

def _pricing_unchanged(previous, current):
    """True when two _pricing_inputs() tuples describe the same prices.

    只留给行级结果记忆（_row_cost_remember）：那里按「价表代次」整表判定，
    保守但正确。状态指纹走 _pricing_used_unchanged()（T15 的收窄判定）。
    """
    if previous is None or current is None:
        return False
    return (previous[0] == current[0] and previous[1] is current[1]
            and previous[2] is current[2] and previous[3] is current[3])

_PRICED_FIELDS = ("refs", "timeline", "timeline_at", "timeline_models",
                  "unresolved", "backfilled", "builtin")

def _pricing_record_new():
    """一份空的状态指纹记录（见上面一节；字段固定、可 JSON 往返）。"""
    return {"refs": {}, "timeline": None, "timeline_at": None,
            "timeline_models": [], "unresolved": [], "backfilled": False,
            "builtin": None}

def _pricing_record_ok(record):
    """状态指纹记录的形状；不合格的记录按「价表变了」处理（判废重折）。"""
    if not isinstance(record, dict):
        return False
    for field in _PRICED_FIELDS:
        if field not in record:
            return False
    refs = record["refs"]
    if not isinstance(refs, dict):
        return False
    for pid, digest in refs.items():
        if not isinstance(pid, str) or not (digest is None
                                            or isinstance(digest, str)):
            return False
    for field in ("timeline", "builtin"):
        value = record[field]
        if not (value is None or isinstance(value, str)):
            return False
    at = record["timeline_at"]
    if not (at is None or _usage_cache_number(at)):
        return False
    for field in ("timeline_models", "unresolved"):
        value = record[field]
        if not isinstance(value, list) or not all(isinstance(v, str)
                                                  for v in value):
            return False
    return isinstance(record["backfilled"], bool)

def _copy_pricing_record(record):
    """记录的深拷贝：落盘在状态锁外序列化，记录必须和活状态脱钩。"""
    if record is None:
        return None
    copy = dict(record)
    copy["refs"] = dict(record.get("refs") or {})
    copy["timeline_models"] = list(record.get("timeline_models") or ())
    copy["unresolved"] = list(record.get("unresolved") or ())
    return copy

def _timeline_at_value(value):
    """一个 at 值按数字比（坏值按 0，与折叠里的 `at or 0` 同口径）。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

def _timeline_row_at(row):
    """时间线一行的 at。"""
    return _timeline_at_value(row.get("at"))

_pricing_timeline_memo = {}

def _pricing_timeline_digest(timeline, record):
    """记录里时间线依赖的投影摘要（折叠侧收尾与判定侧共用一份定义）。

    投影 = [[行 at, 该行里 timeline_models 的 {model: pid} 子字典], ...]，
    摘要 = 排序 JSON + sha1：

      * backfilled 为真（有行靠回填解析）：整条时间线——那批行的解析扫过全部
        行，任何追加都可能改变结果（保守）；
      * 否则：at <= timeline_at 的行，外加最早那一行（二分夹逼 index=0 时会读
        它）；每行只取 timeline_models 里的子字典，无关模型的价变动不进依赖
        ——这正是 T15 要收掉的重折。行本身（连 at）都要进投影：at 的增减会
        挪动二分的结果；
      * unresolved（整条时间线都没提到过的模型）：整条时间线里「提到它的行」
        ——那批行的解析扫过全部行，之后任何时刻补一行都会改变结果。

    timeline_models 为空（没有无引用非零成本的行）时没有依赖，返回 None。
    按（时间线对象, 记录参数）记忆：一次刷新里 5 条状态共用同一份时间线，
    记录没变时只算一次。
    """
    models = record.get("timeline_models") or ()
    if not models:
        return None
    key = (record.get("timeline_at"), tuple(models),
           tuple(record.get("unresolved") or ()),
           bool(record.get("backfilled")))
    hit = _pricing_timeline_memo.get(id(timeline))
    if hit is not None and hit[0] is timeline and hit[1] == key:
        return hit[2]
    wanted = set(models)
    rows = list(timeline or ())
    parts = []
    if key[3]:
        scope = rows
    else:
        bound = _timeline_at_value(record.get("timeline_at"))
        scope = [row for row in rows if _timeline_row_at(row) <= bound]
        if rows and not scope:
            scope = rows[:1]
    parts.append([[_timeline_row_at(row),
                   {m: pid for m, pid in (row.get("policies") or {}).items()
                    if m in wanted}]
                  for row in scope])
    for model in sorted(record.get("unresolved") or ()):
        parts.append([[_timeline_row_at(row), (row.get("policies") or {})[model]]
                      for row in rows
                      if model in (row.get("policies") or {})])
    try:
        payload = json.dumps(parts, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
    except Exception:
        return None
    digest = hashlib.sha1(payload).hexdigest()
    if len(_pricing_timeline_memo) > 8:
        # 正常进程里时间线只在价格变化时换代；这里只是给长期运行兜底
        # （与 _object_digest 的记忆同一条规则）。
        _pricing_timeline_memo.clear()
    _pricing_timeline_memo[id(timeline)] = (timeline, key, digest)
    return digest

def _priced_note(priced, row, cost, pricing):
    """把一行「用到的价」记进状态指纹记录（折叠侧；见上面一节）。

    refs 收下解析出来的 pid 的内容摘要（显式引用 + 时间线解析）；无显式引用
    且成本非零的行另记时间线依赖。总开关关掉（cost 带 disabled）或价表读不
    出来（pricing 为 None）时不记——前者折叠没读任何价、后者记不完整，两种
    都由判定侧按「记录对不上」兜底作废。

    热路径开销：每行几次 dict 查找 + 按对象身份记忆的摘要（第一次之后 O(1)），
    只有无引用非零成本的行（旧前缀，一次性折过）才会碰列表；那批行里落到
    内置快照的（模型从未进过时间线）再问一次 policy_ref_at 把依赖记准。
    """
    if priced is None or pricing is None or not cost:
        return
    if cost.get("disabled"):
        return
    source = cost.get("source")
    if source and source != "builtin":
        if source not in priced["refs"]:
            # 一次扫描里价表不变，同一个 pid 的摘要只算一次：命中记忆之后
            # 这一步就只剩一次成员检查（真机 4.7 万行里只有几个不同 pid）。
            policy = (pricing[1] or {}).get(source)
            priced["refs"][source] = (_object_digest(policy)
                                      if policy is not None else None)
    else:
        # 内置快照：文档摘要一变，这些行的价就变（同一份文档只算一次摘要）。
        doc = pricing[3]
        if doc is not None and priced["builtin"] is None:
            priced["builtin"] = _object_digest(doc)
    pid = row.get("cost_policy")
    if pid:
        # 显式引用：价由 refs 看住，与时间线无关；引用的策略当前查不到时
        # 按「不存在」记，它一旦出现（内容当然也就变了）必须作废重折。
        if pid not in priced["refs"]:
            priced["refs"][pid] = None
        return
    if not cost.get("known") or not cost.get("cny"):
        return                       # 零成本：数值上不依赖价表（refs 已记）
    at = row.get("at") or 0
    bound = priced["timeline_at"]
    if bound is None or at > bound:
        priced["timeline_at"] = at
    model = row.get("model")
    if model is not None and model not in priced["timeline_models"]:
        priced["timeline_models"].append(model)
        priced["timeline_models"].sort()
    backfilled = bool(cost.get("backfilled"))
    if source == "builtin":
        # 解析结果没进 cost（pid 为空、或它的策略查不到，两条都落到内置快照）：
        # 再问一次时间线，把「解析出没出 pid / 是不是回填」记准。
        resolved, scan_backfilled = None, False
        if resolved is None:
            # 整条时间线都没提到这个模型：解析扫过全部行，之后任何时刻补一
            # 行都会改变结果，所以它按「整条时间线里提到它的行」记账。
            if model is not None and model not in priced["unresolved"]:
                priced["unresolved"].append(model)
                priced["unresolved"].sort()
        else:
            backfilled = backfilled or bool(scan_backfilled)
            if resolved not in priced["refs"]:
                priced["refs"][resolved] = None
    if backfilled:
        priced["backfilled"] = True

def _pricing_record_close(priced, pricing):
    """一次成功的折叠收尾：把时间线投影摘要刷成当前参数下的值。

    记录在折叠过程中增量更新（新行进来只加不改），摘要必须跟着参数走——
    下一次判定拿它跟「当前时间线按同一组参数算出来的投影」比。按时间线对象
    与参数记忆，参数没动时这里只是一次查表。
    """
    if priced is None or pricing is None:
        return
    priced["timeline"] = _pricing_timeline_digest(pricing[2], priced)

def _pricing_used_unchanged(record, pricing):
    """折叠行真正用到的价，与当前价表一致？（T15 的状态判废判定）

    只读记录与当前价表、不碰日志：refs 逐个 pid 比对内容摘要（查不到 = 变化；
    折叠时查不到的 pid 出现也是变化），时间线依赖重算同一份投影摘要，builtin
    比对文档摘要。任何一项对不上就返回 False（状态作废、重折）。

    pricing 为 None（价表读不出来）时不能确认，一律 False；总开关关着时折叠
    没读任何价，只有「折叠时也没用价」（record 为 None）才算一致。
    """
    if pricing is None:
        return False
    if not pricing[0]:
        return record is None
    if not _pricing_record_ok(record):
        return False
    policies = pricing[1]
    for pid, digest in record["refs"].items():
        policy = policies.get(pid) if policies else None
        current = _object_digest(policy) if policy is not None else None
        if current != digest:
            return False
    if record["timeline"] != _pricing_timeline_digest(pricing[2], record):
        return False
    if record["builtin"] is not None:
        if _object_digest(pricing[3]) != record["builtin"]:
            return False
    return True

def _realm_inputs():
    """What row_realm() consults for a row that carries no realm field.

    Rows written before the field existed - an error row with no account - are
    attributed to the account that served them, or to the model's home realm.
    Importing or dropping an account can therefore move such a row from one
    exit to the other, and a cached aggregate must not outlive that.

    这两样（当前出口 + uid→realm 归属）从**磁盘**同步读，而不是从活账号池的
    内存映射读。池是启动时从同一份磁盘加载的快照，但「它什么时候加载完」会让
    同一个进程在不同时刻算出不同的指纹：重启后第一刻的进程算出的是启动期那
    一份，于是刚写下的 checkpoint 反而被判无效——而那正是它存在的意义（重启
    后免冷扫）。从磁盘读，任何时刻、任何进程算出来都一样。

    池仍然要查，但只作为「这次折叠能不能被冷进程复现」的判据（见
    _realm_fold_reproducible），不再进指纹的值。
    """
    disk = _account_realm_map()
    if disk is None:
        return None
    return (_current_realm(), disk)

def _account_realm_map(directory=None):
    """uid→realm 映射。数据源（WorkBuddy 账号文件）已随池移除，恒为空。

    空元组是这条链路本来就支持的「一个账号都没有」状态（全新安装就是这样）：
    折叠退化成按日志行里写的 realm 归属，不会把任何一行算丢；指纹也稳定，
    checkpoint 照常可写。
    """
    return ()

def _realm_fold_reproducible(disk):
    """这次折叠用的归属，冷启动的进程能不能按同一份磁盘原样复现。

    账号池移除后折叠不再查账号映射（`_account_realm_map` 恒为空），所以只要
    磁盘侧也读不到账号，两边就一致；没有池可以「还没重载」了。
    """
    return not disk

def _scan_usage_from(offset, fold, stop_at=None, skip=None, skip_raw=None, path=None):
    """Fold every row past `offset` into `fold(row)`; returns (offset, error).

    The offset handed back is the end of the last row the pass got through.
    Rows are appended whole, so a line without its trailing newline is left
    for the next pass rather than half-parsed - the rule _scan_daily_usage()
    follows.

    `skip(line)` drops a line before the parse; the windowed readers pass
    _bind__line_outside_window() here, so a line the range excludes costs a substring
    search instead of a json.loads. `skip_raw(raw)` is the same test on the
    undecoded line, run before the decode: the windowed readers pass
    _bind__line_outside_window_bytes(), which only answers True for a line the text
    check above would drop as well, so a line it drops skips the decode too
    and no other line reads differently. Both are optional and either may be
    given alone.

    `stop_at` caps the read at the offset an all-time fold has already covered,
    so a windowed payload built on top of that fold describes exactly the same
    bytes as its all-time half.

    `path` defaults to the usage log; the remaining-usage fold folds its own
    event journal through the same pass rules.

    The log is read in binary and the offset advances by the length of each
    line: a tell() per line costs more than the parse it would be tracking,
    and an offset only has to be a byte count. Every line that reaches the
    text checks is decoded to text before it is looked at, which is the order
    the text-mode readers read in and the one the text-mode pre-filter
    expects; a line `skip_raw` drops never gets that far.

    `error` is the exception that stopped the read, or None. A row the fold
    cannot swallow ends the pass exactly where it used to - the readers have
    always kept what they had folded so far - and the caller reports it with
    its own label. The offset handed back with an error is the end of that
    row: the fold may have half applied it before it raised, so the caller
    starts its own fold over instead of resuming after it, while a windowed
    pass built on the state still sees the row - and stops there - so the
    two halves keep describing the same bytes.
    """
    if stop_at is not None and offset >= stop_at:
        return offset, None
    try:
        with _open(path or _usage_log_path(), "rb") as fh:
            fh.seek(offset)
            while True:
                if stop_at is not None and offset >= stop_at:
                    break
                raw = fh.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    break
                end = offset + len(raw)
                if stop_at is not None and end > stop_at:
                    # The line straddles the covered bytes, so the all-time
                    # fold never saw it either: leave it out of this pass too.
                    break
                # The bytes-level pre-filter runs first: a line it can read
                # exactly and place outside the window never becomes text at
                # all. It only answers for lines the text filter below would
                # drop too (see _bind__line_outside_window_bytes), so the rows this
                # pass folds are exactly the rows it folded before.
                if skip_raw is not None and skip_raw(raw):
                    offset = end
                    continue
                try:
                    # Decoded before anything else, exactly as the text-mode
                    # readers do: a line no reader can decode stops them where
                    # it stands, so it stops this pass too rather than letting
                    # it count rows the full scan never reached. Stripping the
                    # text (not the bytes) keeps the two agreeing on what
                    # counts as an empty line.
                    line = raw.decode("utf-8").strip()
                except UnicodeDecodeError as exc:
                    return end, exc
                if not line:
                    offset = end
                    continue
                if skip is not None and skip(line):
                    offset = end
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    offset = end
                    continue
                try:
                    fold(row)
                except Exception as exc:
                    return end, exc
                offset = end
    except FileNotFoundError:
        pass
    except Exception as exc:
        return offset, exc
    return offset, None

def _copy_usage_bucket(bucket):
    """Copy one by_model* bucket, its accounts dict included."""
    out = dict(bucket)
    out["accounts"] = dict(bucket["accounts"])
    return out

def _copy_usage_snapshot(snap):
    """A snapshot copy the caller may decorate and hand out.

    The fold is cached and shared, so what leaves this module is a copy - the
    same reason _daily_state_copy() exists for the daily counters. Only the
    three per-model views nest; every other value is a scalar.
    """
    out = dict(snap)
    out["by_model"] = {m: _copy_usage_bucket(b) for m, b in snap["by_model"].items()}
    out["by_model_realm"] = {m: {rr: _copy_usage_bucket(b) for rr, b in realms.items()}
                             for m, realms in snap["by_model_realm"].items()}
    out["by_model_acct"] = {
        m: {rr: {acct: _copy_usage_bucket(b) for acct, b in accts.items()}
            for rr, accts in realms.items()}
        for m, realms in snap["by_model_acct"].items()}
    return out

_ROW_MEMO_MAX = 65536

def _row_memo_env_cap(name, default):
    """导入时读一次上限；读不到或解析不出来就按默认。"""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return default

_ROW_MEMO_MAX = _row_memo_env_cap("WB_ROW_MEMO_MAX", _ROW_MEMO_MAX)

_row_day_memo = {}          # at -> "YYYY-MM-DD"

_row_memo_tz = time.tzname  # 日键表绑在哪个时区上（见 _row_memo_tz_changed）

def _row_memo_at(value):
    """记忆表的「新旧」比较键：只有数字能比大小，别的（None / 坏行）一律按 0。

    比大小只决定「这条记不记」，不决定结果——比不动就不比，照记。
    """
    return value if isinstance(value, (int, float)) else 0

def _row_memo_tz_changed():
    """进程时区被 tzset() 换过 → 日键表整体作废（定价表不受影响）。

    日键是本地时区的函数，跨时区复用旧值会算错天。CPython 的 time.tzset()
    每次都会重建 time.tzname 这个元组对象，所以「对象换了」就是「时区换过」；
    没换时这里只是一次身份比较。生产里进程时区不会变，这一句就是白送的。
    """
    global _row_memo_tz
    now = time.tzname
    if _row_memo_tz is now:
        return False
    _row_memo_tz = now
    _row_day_memo.clear()
    return True

#: 价格估算体系已下线（2026-10-22）：这个网关只按码道积分记账，不再折算
#: OpenRouter / 美元等价花费。所有成本出口统一返回这一份零值。只剩
#: _priced_note() 还在读它（disabled / source / known / cny / backfilled），
#: 形状就收敛到这五个键。
_ZERO_COST = {
    "cny": 0.0,
    "known": False,
    "disabled": True,
    "source": "",
    "backfilled": False,
}

def _row_cost(row, pricing, pricing_on):
    """一行的估算成本。

    价格体系已移除，恒返回零值 —— 保留函数与签名是因为聚合、增量快照、
    analytics 三处都从这里取价，改签名会波及二十多个核心函数。
    """
    return dict(_ZERO_COST)

def _fold_usage_snapshot(row, snap, r, since, until, pricing_on=None, also=None,
                         pricing=None, priced=None):
    """Fold one parsed row into a usage snapshot.

    One definition for both callers: the all-time fold (fed only the rows past
    its offset) and the windowed one (fed the whole file, out-of-window lines
    dropped before the parse). The realm and window tests come first, so every
    total below - requests, tokens, per-model and per-account breakdowns -
    describes the same slice of the log.

    pricing_on 是本次扫描开头问过一次的总开关：聚合不再读任何价（价格估算
    体系已下线），开关只进 _priced_note 的指纹链路，整扫不逐行重问。代价是
    设置改动从下一次扫描起生效。

    `also` 是同一行还要折进的其余同形状快照（按日/按小时分桶的窗口半），
    一个元组，空/None 表示没有。过滤、取行级记忆与字段提取只做一次，几份
    各自累加：折叠本来就要求每份各记一笔，而行级记忆与 realm 判定是每行
    最贵的那部分，只该付一次。

    `pricing` 是本次扫描开头取到的 _pricing_inputs() 元组（调用方从同一个
    值里取指纹，两处看到的是同一份价表）；传给 _bind__row_cost 当记忆的代次，
    None 表示价表读不出来、不进表。

    `priced` 是本次扫描要填的「用到的价」记录（见「用到的价」状态指纹一节），
    只有推进状态的那条折叠传它；窗口半/冷扫描传 None，一行都不记。
    """
    if r and not row_matches_realm(row, r):
        return
    at = row.get("at") or 0
    if since and at < since:
        return
    if until and at > until:
        return
    outcome = row_outcome(row)
    # Each row is priced against the version that was in force when it
    # happened, so a later price change cannot rewrite yesterday's totals.
    # _bind__row_cost 按行记忆（见「行级结果记忆」）：同一个视图里这一行只算一次，
    # 第二个视图直接取上次的结果；pricing 是本次扫描的价表代次。
    cost = _bind__row_cost(row, pricing, pricing_on)
    if outcome != "client_aborted":
        # 折进去的每一行都把「用到的价」记进状态指纹（中止行只记 errors，
        # 不碰价，所以不记）。记的是这次折叠真正读到的价，价表无关的变动
        # 因此不再判废这条状态（见「用到的价」状态指纹一节）。
        _priced_note(priced, row, cost, pricing)
    model = row.get("model")
    targets = (snap,) if not also else (snap,) + tuple(also)
    if outcome != "completed":
        for tgt in targets:
            tgt["errors"] += 1
            # Credit is money already spent: a request that failed after the
            # upstream had billed for it still consumed credit, so it is summed
            # here exactly like the analytics page sums it. Token totals keep
            # the completed-only rule this page has always used, and a client
            # abort is skipped because its usage block is incomplete.
            if outcome != "client_aborted":
                tgt["credit"] += (row.get("credit") or 0)
        return
    # Read each tracked field once: the row lands in four buckets below and
    # every one of them walks the same fields.
    present = [(k, row[k] or 0) for k in USAGE_FIELDS if k in row]
    m = model or "unknown"
    rr = row_realm(row)
    acct_id = row.get("account")
    acct_key = acct_id or "(unattributed)"
    for tgt in targets:
        tgt["requests"] += 1
        for k, value in present:
            tgt[k] += value
        per = tgt["by_model"].setdefault(m, {"requests": 0, "accounts": {}, **{k: 0 for k in USAGE_FIELDS}})
        per_realm = tgt["by_model_realm"].setdefault(m, {}).setdefault(
            rr, {"requests": 0, "accounts": {}, **{k: 0 for k in USAGE_FIELDS}})
        per_acct = (tgt["by_model_acct"].setdefault(m, {})
                    .setdefault(rr, {})
                    .setdefault(acct_key, {"requests": 0, "accounts": {},
                                           **{k: 0 for k in USAGE_FIELDS}}))
        for bucket in (per, per_realm, per_acct):
            bucket["requests"] += 1
            for k, value in present:
                bucket[k] += value
            if acct_id:
                accounts = bucket["accounts"]
                accounts[acct_id] = accounts.get(acct_id, 0) + 1

_usage_snap_state = {}

_usage_snap_state_lock = threading.Lock()

def _usage_snap_state_advance(r, pricing_on):
    """（不折叠）取/建状态、采纳 checkpoint、判废归零、记身份指纹。

    调用方必须已持有 _usage_snap_state_lock。返回本次扫描取到的价表代次
    （_pricing_inputs 的元组）：调用方把它传给折叠当行级记忆的代次，与记进
    状态指纹的是同一份，两处不会看到两份价表。

    状态指纹是「折叠行真正用到的价」记录（T15，见「用到的价」状态指纹一节）：
    折叠时逐行更新（state["pricing"]），扫描成功后把时间线投影摘要刷成当前
    参数下的值（_pricing_record_close）——下一次判废拿它跟「当前价表按同一组
    参数算出来的投影」比（_pricing_used_unchanged）。

    状态是否「冷」（这次要付一次全量重折）看折过的位置：state["offset"] > 0
    表示有可续折的数据；0 表示折叠要从文件头开始——状态刚建、刚被价表 /
    realm / 日志判废、或 checkpoint 采纳失败。判定只看已折位置与三份指纹，
    一行都不折，所以窗口路径拿它分流是纯加速：重折之后两边给出的字节完全
    一致（见 _usage_snap_state_cold）。

    采纳/判废只有这一段定义：_usage_snap_state_ready（all-time 折叠）与
    窗口路径的冷热判定共用它，两边的规则因此不会漂移。
    """
    state = _usage_snap_state.get(r)
    if state is None:
        state = _usage_snap_state[r] = {"snap": None, "offset": 0, "key": None,
                                        "pricing": None, "realm": None,
                                        "tail": b"", "days": {}, "days_floor": None,
                                        "hours_floor_at": None,
                                        "hits": [], "hits_overflow": False}
    pricing = _pricing_inputs(pricing_on)
    realm = _realm_inputs()
    log_key = _usage_log_key()
    # 重折时状态指纹从这份空记录重新长起；总开关关着 / 价表读不出来时
    # 记 None（折叠没读任何价，判定侧只认「记录也是 None」这一种一致）。
    fresh = _pricing_record_new() if (pricing is not None
                                      and pricing[0]) else None
    if state["snap"] is None:
        # 全新状态（进程刚起来）：先问 checkpoint，问不到才从零折起。
        if not _usage_cache_adopt_snapshot(r, state, log_key, pricing, realm):
            state.update({"snap": _empty_stats(), "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "hours_floor_at": None,
                          "hits": [], "hits_overflow": False, "pricing": fresh})
    elif (not _pricing_used_unchanged(state["pricing"], pricing)
            or state["realm"] != realm
            or not _log_resume_ok(state, log_key)):
        state.update({"snap": _empty_stats(), "offset": 0, "tail": b"",
                      "days": {}, "days_floor": None, "hours_floor_at": None,
                      "hits": [], "hits_overflow": False, "pricing": fresh})
    state.update({"realm": realm, "key": log_key})
    return pricing

def _usage_snap_state_cold(r, pricing_on):
    """窗口请求现在会不会付一次全量重折？True = 会（窗口改走冷扫描）。

    调用方必须已持有 _usage_snap_state_lock。判定就是 all-time 折叠的前半段
    （_usage_snap_state_advance），不折任何行；为真时窗口半改走按日/按小时
    分组的冷扫描（_scan_usage_snapshot_window_days / _hours，~1s 量级），
    重折留给 all-time 视图（_usage_alltime_snapshot）与预热器。

    这条路不写折叠结果，也不改「重折该不该发生」：状态里 offset 仍是 0，
    下一个 all-time 请求照样从文件头折到文件尾——窗口请求不会把状态冻在
    冷态。重折发生之后，走不走这条路给出的字节完全相同（冷扫描与日桶/小时
    桶之和本就是同一批行、同一个求和口径，见两个冷路径函数的 docstring）。
    """
    _usage_snap_state_advance(r, pricing_on)
    return _usage_snap_state[r]["offset"] <= 0

def _usage_snap_state_ready(r, pricing_on):
    """把 `r` 的 all-time 折叠推进到文件尾；返回 (state, offset, error)。

    调用方必须已持有 _usage_snap_state_lock。日桶与 all-time 折叠共用这一次
    扫描（见 _fold_usage_snapshot 的 also），所以窗口半与 all-time 半描述的
    永远是同一段字节——这正是旧实现用 stop_at 想保证的事。

    采纳 checkpoint 与判废归零在 _usage_snap_state_advance 里（窗口路径的
    冷热判定也用那一段，见 _usage_snap_state_cold），这里只管折到文件尾。
    """
    pricing = _usage_snap_state_advance(r, pricing_on)
    state = _usage_snap_state[r]
    priced = state["pricing"]

    def fold(row):
        # 一行折三处：all-time 半 + 它所属那天的窗口半 + 那个小时的小时桶。
        # 过滤与算价在 _fold_usage_snapshot 里只做一次。
        day = _usage_day_bucket(state, row, r, _day_snapshot_bucket)
        hour = None if day is None else _usage_hour_bucket(state, row, day)
        extras = () if day is None else ((day,) if hour is None else (day, hour))
        _bind__fold_usage_snapshot(row, state["snap"], r, None, None, pricing_on,
                             also=extras, pricing=pricing, priced=priced)

    offset, error = _scan_usage_from(state["offset"], fold)
    if error is None:
        state["offset"] = offset
        state["tail"] = _log_tail_signature(offset)
        _pricing_record_close(priced, pricing)
    return state, offset, error

def _usage_alltime_snapshot(r, pricing_on=None):
    """A private copy of the cached all-time fold for realm filter `r`
    (None = every realm).

    One state per realm: the filter decides which rows the fold ever sees, so
    two realms would be two folds and neither may inherit the other's rows.
    The state holds the raw fold only - `started`, `since`, `accounts_map` and
    the rest are re-derived on every call, exactly as the full scan re-derived
    them.
    """
    with _usage_snap_state_lock:
        state, offset, error = _usage_snap_state_ready(r, pricing_on)
        if error is None:
            # Copied while the lock is held: the caller decorates what it
            # gets, and a concurrent refresh must never be seen half-applied.
            snap = _copy_usage_snapshot(state["snap"])
        else:
            # A row the fold could not swallow may have half applied itself,
            # so the carried-over totals cannot be resumed from there: this
            # call answers what was folded - the full scan reports the same
            # partial totals - and the next refresh starts over, which is
            # what the full scan does on every call.
            _log(f"usage snapshot read failed: {error}")
            snap = state["snap"]
            state.update({"snap": None, "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "hours_floor_at": None,
                          "hits": [], "hits_overflow": False})
    # 落盘决定在锁外做（见 checkpoint 一节）：写盘要逐把读三份状态，在状态
    # 锁里再取别的状态锁会构成锁序环。折叠失败的那次不写——它的 offset 已经
    # 归零，落盘函数也会跳过。
    if error is None:
        _usage_cache_maybe_save("snapshot", offset)
    return snap

def _scan_usage_snapshot_window(r, since, until, pricing_on=None):
    """One pass over the log, keeping only the rows inside the window.

    Nothing is carried over here - a window moves with the clock - but the
    pre-filter drops the parse for every line it can prove is outside it, and
    its bytes-level half drops the decode of those lines as well, which is
    what keeps a cold day or week view cheap on a multi-day log.

    The bounds reach the pre-filter through `or None` because that is the
    test the fold itself applies (`if since and at < since`): a bound of 0
    is a bound the fold ignores, and the pre-filter must not read it as
    "keep nothing after the epoch" and drop rows the fold would have
    counted.

    价表在这里取一次（与 all-time 折叠同一条口径：一次扫描一份价表快照），
    传给折叠当行级记忆的代次；这次扫描里的行因此可以和别的视图共享定价结果。
    """
    pricing = _pricing_inputs(pricing_on)
    snap = _empty_stats()
    _, error = _scan_usage_from(
        0,
        lambda row: _bind__fold_usage_snapshot(row, snap, r, since, until, pricing_on,
                                         pricing=pricing),
        skip=lambda line: _bind__line_outside_window(line, since or None,
                                                 until or None),
        skip_raw=lambda raw: _bind__line_outside_window_bytes(raw, since or None,
                                                        until or None))
    if error is not None:
        _log(f"usage snapshot read failed: {error}")
    return snap

def _usage_snapshot_window_from_days(r, since, until, pricing_on):
    """窗口半快照 = 窗口内的日桶之和；日桶不可用时返回 None。

    先把 all-time 折叠推进到文件尾：日桶与它同一次扫描推进，窗口半与
    all-time 半因此描述同一段字节。

    until 开放（None）时窗口从起点一路到文件尾；until 给出时它必须是本地
    午夜（调用方已按格点判过，这里再校验一次），窗口就是「起点那天起、
    until 那天之前」的日桶之和。桶按 at 严格切分（恰好落在 until 上的行归
    until 那天那一桶，见 _usage_hour_bucket），桶切不出那一刻的行，所以
    那一刻有整秒行时整条路退回 None（见 _closed_window_edge_ok），调用方
    接着整段扫描，结果不变。

    状态冷（从没折过/刚被价表、realm、日志判废/采纳失败）时直接返回 None：
    那条路要先付一次全量重折，窗口请求不背它——调用方退回按日分组的冷扫描
    （同一批行、同一个求和口径，逐字节相同），重折留给 all-time 视图与
    预热器（见 _usage_snap_state_cold）。
    """
    with _usage_snap_state_lock:
        if _usage_snap_state_cold(r, pricing_on):
            return None
        state, offset, error = _usage_snap_state_ready(r, pricing_on)
        if error is not None:
            # 折叠失败时状态已经归零，日桶跟着清空：这一次退回整段扫描，
            # 与「没有缓存」时的行为一致。
            _log(f"usage snapshot read failed: {error}")
            state.update({"snap": None, "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "hours_floor_at": None,
                          "hits": [], "hits_overflow": False})
            return None
        day_key = _window_day_key_safe(since)
        if day_key is None or not _days_cover(state, day_key):
            return None
        until_key = None
        if until is not None:
            until_key = _window_day_key_safe(until)
            if until_key is None or not _closed_window_edge_ok(state, until):
                return None
        snap = _empty_stats()
        days = state["days"]
        for key in sorted(days):
            if key < day_key:
                continue
            if until_key is not None and key >= until_key:
                break
            _add_usage_snapshot(snap, days[key])
    _usage_cache_maybe_save("snapshot", offset)
    return snap

def _usage_snapshot_window_from_hours(r, since, until, pricing_on):
    """窗口半快照 = 整点窗口内的小时桶之和；小时层不可用时返回 None。

    与日桶版同一条规矩：先把 all-time 折叠推进到文件尾（小时桶与它同一次
    扫描推进），再从存量桶求和。成立条件缺一不可，任何一条不成立就返回
    None（调用方退回按小时分组的冷路径）：

      * 窗口起点是本地整点（见 _hour_window_key）；
      * days_floor 覆盖窗口起点——小时桶挂在日桶上，剪枝跟着日桶走；
      * 被选中的每个日桶都带小时表。某天的小时格点不成立时整张表被摘掉
        （见 _usage_hour_bucket），这时整个窗口退回扫描，不能只跳过那一天；
      * 每个小时桶的 at 落在「窗口起点 + k*3600」的格点上，且与所属日桶
        对得上（日桶 at + 序号*3600）。这一条挡住夏令时把日边界挪动的
        情形——与 _series_slice 的格点校验同源；
      * until 给出时（闭窗口）它也必须落在同一套小时格点上，且直到那一刻
        没有整秒行（见 _closed_window_edge_ok）：桶按 at 严格切分，窗口
        只取 at < until 的那批桶，恰好落在 until 上的行由边沿账挡回整段
        扫描。

        情形——与 _series_slice 的格点校验同源。

    状态冷（从没折过/刚被价表、realm、日志判废/采纳失败）时直接返回 None：
    那条路要先付一次全量重折，窗口请求不背它——调用方退回按小时分组的冷
    扫描（同一批行、同一个求和口径，逐字节相同），重折留给 all-time 视图
    与预热器（见 _usage_snap_state_cold）。
    """
    key = _hour_window_key(since)
    if key is None:
        return None
    day_key, k0 = key
    until_key = None
    if until is not None:
        until_key = _hour_window_key(until)
        if until_key is None:
            return None
    with _usage_snap_state_lock:
        if _usage_snap_state_cold(r, pricing_on):
            return None
        state, offset, error = _usage_snap_state_ready(r, pricing_on)
        if error is not None:
            _log(f"usage snapshot read failed: {error}")
            state.update({"snap": None, "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "hours_floor_at": None,
                          "hits": [], "hits_overflow": False})
            return None
        if not _days_cover(state, day_key):
            return None
        if not _hours_cover(state, since):
            return None
        if until_key is not None and not _closed_window_edge_ok(state, until):
            return None
        lo = int(since)
        snap = _empty_stats()
        days = state["days"]
        for key in sorted(days):
            if key < day_key:
                continue
            if until_key is not None and key > until_key[0]:
                break
            bucket = days[key]
            hours = bucket.get("hours")
            if hours is None:
                return None
            day_at = int(bucket["at"])
            for hour in sorted(hours, key=int):
                if key == day_key and int(hour) < k0:
                    # 起点那天只看起点之后的整点：更早的桶属于窗口外，跳过
                    # 它们不影响正确性（桶按 at 严格切分，见 _usage_hour_bucket）。
                    continue
                sub = hours[hour]
                at = int(sub["at"])
                if at != day_at + int(hour) * 3600:
                    return None
                if (at - lo) % 3600:
                    return None
                if until_key is not None and (key, int(hour)) >= until_key:
                    # 闭窗口：until 那一刻归后一桶（桶按 at 严格切分），
                    # 只取 at < until 的桶；那一刻有整秒行时上面已经退回。
                    break
                _add_usage_snapshot(snap, sub)
    _usage_cache_maybe_save("snapshot", offset)
    return snap

def _usage_snapshot_window(r, since, until, pricing_on=None):
    """窗口半快照：对齐窗口由日桶/小时桶相加，其余保持整段扫描。

    只有「两端都落在同一套格点上」的窗口拆得成存量桶的并集：起点是本地
    午夜、终点（开放或闭）也是本地午夜时用日桶（today / week / month 与
    「到某天零点」都是），两端落在本地整点上时用小时桶（自定义区间的常见
    形态，见 _hour_window_key）。闭窗口的右边界按「at < until 的桶」切
    （见 _closed_window_edge_ok）：那一刻有整秒行时退回整段扫描，结果与
    改动前逐字节一致——闭窗口本来走的就是这条兜底。起点不落在格点上、
    或 until 不落格点的窗口同样保持整段扫描。
    """
    if until is None:
        day_key = _window_day_key_safe(since)
        if day_key is not None and _usage_day_buckets_enabled():
            snap = _usage_snapshot_window_from_days(r, since, None, pricing_on)
            if snap is not None:
                return snap
            # 日桶没盖住窗口起点（还没折过/被剪枝/折叠出错）：冷路径现折一份
            # 按日分组的窗口半，口径与日桶状态一致，两条路径的字节因此相同。
            return _bind__scan_usage_snapshot_window_days(r, since, None, pricing_on)
        if _usage_day_buckets_enabled() and _window_hour_key_safe(since) is not None:
            snap = _usage_snapshot_window_from_hours(r, since, None, pricing_on)
            if snap is not None:
                return snap
            # 小时层没盖住窗口起点（还没折过/被剪枝/那天的小时格点不成立）：
            # 冷路径现折一份按小时分组的窗口半，口径与小时桶状态一致。
            return _bind__scan_usage_snapshot_window_hours(r, since, None, pricing_on)
        return _bind__scan_usage_snapshot_window(r, since, until, pricing_on)
    # 闭窗口：两端都落在格点上才有桶可借（与上面同一套格点校验）。
    if _usage_day_buckets_enabled():
        if (_window_day_key_safe(since) is not None
                and _window_day_key_safe(until) is not None):
            snap = _usage_snapshot_window_from_days(r, since, until, pricing_on)
            if snap is not None:
                return snap
            return _bind__scan_usage_snapshot_window_days(r, since, until, pricing_on)
        if (_window_hour_key_safe(since) is not None
                and _window_hour_key_safe(until) is not None):
            snap = _usage_snapshot_window_from_hours(r, since, until, pricing_on)
            if snap is not None:
                return snap
            return _bind__scan_usage_snapshot_window_hours(r, since, until, pricing_on)
    return _bind__scan_usage_snapshot_window(r, since, until, pricing_on)

def _usage_snapshot_uncached(realm=None, since=None, until=None):
    # None means every realm; usage_snapshot() has already mapped "all"
    # onto it, so the filter below is simply skipped.
    r = realm
    # WorkBuddy 池已移除：这里不再有「代表账号」。字段保留（面板按它们渲染），
    # 值恒为空 —— 删字段会让前端读到 undefined。
    rep = None
    # 总开关整扫只问一次，值一路传进折叠与价格指纹：每行重问一次就是每行一次
    # os.stat，2.7 万行上很可观（见 tests/_test_usage_aggregate_fold.py）。
    # 价格估算体系已下线：折叠永远在「不计价」档跑。
    pricing_on = False
    if since is None and until is None:
        # An open window covers every row, and the rows only ever arrive at
        # the end of the log, so the all-time totals are carried over from the
        # last fold and only the rows appended since then are read.
        snap = _usage_alltime_snapshot(r, pricing_on)
    else:
        snap = _usage_snapshot_window(r, since, until, pricing_on)
    snap["started"] = _usage.get("started", time.time())
    snap["since"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snap.get("started", time.time())))
    snap["log_file"] = _usage_log_path()
    snap["realm"] = r or "all"
    snap["accounts_map"] = {}
    snap["account"] = {
        "uid": "", "domain": "", "issuer": "", "credential_file": "",
        "expires_at": 0, "accounts": 0, "accounts_ready": 0,
    }
    return snap

def _tail_lines(path, max_lines, chunk=256 * 1024):
    """Return up to the last `max_lines` non-empty lines, oldest first.

    The usage log passes 20MB within a day. Scanning it end to end on every
    dashboard poll was the dominant cost behind slow /usage/* responses, so
    the reader walks the file backwards in `chunk`-sized blocks and splits
    each block exactly once: `buf` carries only the fragment that straddles
    the boundary into the next (older) block, never the blocks already read.

    Lines that hold nothing but whitespace are not rows and do not count
    towards max_lines; a trailing chunk with no newline still counts as a
    line when it holds anything else (record_usage always writes the
    newline, so that case is a write caught mid-flight).

    逐行的活只剩"这一行要不要"：整块的非空行在 C 层用列表推导滤出来、一次
    extend 收进 lines（上限再截断），比逐行 strip()+append 少一层 Python
    循环。字节口径与逐行写法逐字相同（套件里留了参考实现对拍）。
    """
    lines = []
    try:
        with _open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and len(lines) < max_lines:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                buf = parts[0]
                got = [raw for raw in parts[1:] if raw and not raw.isspace()]
                if got:
                    lines.extend(reversed(got))
                    if len(lines) > max_lines:
                        # 与逐行写法一样：收满 max_lines 就停，剩下的（更老的）
                        # 行属于更早的块，本来也不会被收进来。
                        del lines[max_lines:]
                        break
            if len(lines) < max_lines and buf.strip():
                lines.append(buf)
    except FileNotFoundError:
        return []
    except Exception as exc:
        _log("tail read failed: %s" % exc)
        return []
    lines.reverse()
    return lines

_series_cache = {}

_series_lock = threading.Lock()

def _usage_timeseries_scope(realm, range, since, until, bucket_seconds):
    """(realm, lo, hi, step, 缓存键) —— usage_timeseries() 与它的 ETag 共用。

    lo/hi 是这次真正要扫的窗口（未钉住的边界在这里补成"现在/往前 24 小时"），
    键只收**钉住的**边界，理由见下面 wrapper 里的注释。
    """
    r = realm_scope(realm, _current_realm())
    lo, hi = range_window(range, since, until)
    # Which bounds the caller pinned, captured before the fallbacks below fill
    # the rest in. Only a pinned bound may enter the cache key as a value:
    # "now" (and the 24h-before-now default lo) is recomputed on every call,
    # so a key holding it could never be reused while the panel polls the same
    # chart, and the cache would buy nothing. The "auto" sentinel keeps the two
    # kinds of bound apart, so a rolling window is never served a pinned
    # window's series.
    pinned_lo, pinned_hi = lo, hi
    if hi is None:
        hi = time.time()
    if lo is None:
        lo = hi - 86400
    span = max(1.0, hi - lo)
    if bucket_seconds:
        step = max(60, int(bucket_seconds))
    elif span <= 6 * 3600:
        step = 60
    elif span <= 14 * 86400:
        step = 3600
    else:
        step = 86400
    # Bounds, not a range flag: this week and this month overlap, so a flag
    # would let one window serve the other's series from the cache. The
    # bucket step joins the key for the same reason: an explicit bucket
    # changes every bucket's width, and the auto-scaled one flips with the
    # span, so two different steps are two different payloads.
    key = (r or "all",
           pinned_lo if pinned_lo is not None else "auto",
           pinned_hi if pinned_hi is not None else "auto",
           step)
    return r, lo, hi, step, key

def usage_timeseries(realm=None, range=None, since=None, until=None,
                     bucket_seconds=None, ttl=None):
    """Bucketed token/credit series for the analytics chart.

    Bucket size auto-scales with the window: minute (<=6h), hour (<=14d),
    day otherwise; an explicit bucket_seconds overrides it. Completed
    requests contribute tokens; every non-client-aborted row contributes
    credit (money already spent). The most recent credited requests ride
    along so the panel can show a credit history without another endpoint.

    Cached wrapper: the Token chart polls this endpoint whenever the metrics
    tab is open, and one uncached call re-reads and re-parses the whole log.
    Same shared TTL as its siblings, and the rebuild runs under the lock so a
    burst of pollers cannot each start their own scan.
    """
    ttl = _bind__STATS_TTL() if ttl is None else ttl
    r, lo, hi, step, key = _usage_timeseries_scope(realm, range, since, until,
                                                   bucket_seconds)
    now = time.time()
    with _series_lock:
        hit = _series_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
        data = _usage_timeseries_uncached(r, lo, hi, step)
        _series_cache[key] = (time.time(), data)
    return data

def usage_timeseries_etag(realm=None, range=None, since=None, until=None,
                          bucket_seconds=None):
    """usage_timeseries() 当前缓存条目的 ETag；没有条目时返回 None。

    配对调用由 _json_cached() 负责。注意键里只有钉住的边界，所以"滚动窗口"这一类
    请求始终落在同一条目上：条目没重建，响应体（含它自己的 until / 桶边界）就逐
    字节不变，这正是可以放心回 304 的原因。
    """
    _r, _lo, _hi, _step, key = _usage_timeseries_scope(realm, range, since, until,
                                                       bucket_seconds)
    with _series_lock:
        hit = _series_cache.get(key)
    if hit is None:
        return None
    return _cache_etag("series", repr(key), hit[0])

_AT_PREFIX = '{"at": '

_AT_PREFIX_B = _AT_PREFIX.encode("ascii")

def _line_outside_window(line, lo, hi):
    """True when this log line's `at` is provably outside [lo, hi].

    Either bound may be None, which means "unbounded on that side": the
    ranges the dashboard asks for ("today", "this week") only pin a start,
    and an open side must never drop a row.

    The scan uses it to drop out-of-window lines without paying for
    json.loads, which is what made a cold pass over the log expensive. False
    means "parse it as before" - both for lines that match the shape and fall
    inside the window, and for anything the check cannot read exactly:

    * another key order or a hand-edited line: no leading `{"at": `, or no
      comma to end the value;
    * an integer token: json.loads would hand back an int, and int/float
      comparison stays exact where float(token) rounds once the value passes
      2**53 (a float token round-trips through float() exactly, which is why
      those are the only ones accepted);
    * a later `"at"` key: json.loads keeps the last duplicate, so the first
      value read here would be the wrong one. Escaped quotes inside string
      values (\\") cannot produce a false `"at"`, so this check only ever
      costs a parse - and it runs only for lines that would be skipped, so a
      line the scan is going to parse anyway never pays for it.
    """
    if not line.startswith(_AT_PREFIX):
        return False
    end = line.find(",", len(_AT_PREFIX))
    if end < 0:
        return False
    token = line[len(_AT_PREFIX):end]
    if "." not in token and "e" not in token and "E" not in token:
        return False
    try:
        at = float(token)
    except ValueError:
        return False
    if not ((lo is not None and at < lo) or (hi is not None and at > hi)):
        return False
    return line.find('"at"', end) < 0

def _line_outside_window_bytes(raw, lo, hi):
    """_bind__line_outside_window() on the undecoded line: True only when the text
    check would answer True too.

    The scan reads bytes and only then decodes, so the same test can run
    before the decode and a line it drops never becomes text at all - which
    is the whole point, since a narrow window leaves most of a multi-day log
    outside it. The rules are the text version's, read off the bytes: same
    prefix, same first comma, same float-token requirement, same window
    comparison, same "no later `"at"` key" test (see that docstring for what
    each one is protecting).

    One extra condition: the line has to be ASCII from end to end. Two things
    ride on it. It makes the byte read exact - every character the text check
    would see is the byte the check saw - and it is what keeps a line no
    reader can decode out of the skip path. On the text path that line stops
    the pass with UnicodeDecodeError before any filter runs (see
    _scan_usage_from), so skipping it here would fold in rows the old pass
    never reached. ASCII is a subset of UTF-8, so an all-ASCII line always
    decodes, and a line with anything else in it returns False and is decoded
    and filtered exactly as before.

    False therefore means "decode it and check as before", never "this line
    is inside the window". Bounds must be the ones handed to
    _bind__line_outside_window(): this check is only allowed to drop lines that one
    drops.
    """
    if not raw.startswith(_AT_PREFIX_B):
        return False
    end = raw.find(b",", len(_AT_PREFIX_B))
    if end < 0:
        return False
    token = raw[len(_AT_PREFIX_B):end]
    # 46/101/69 are `.`/`e`/`E` as byte values. The test is spelled with int
    # needles because on bytes an int needle is a plain single-byte scan
    # (memchr), where `b"." in token` runs the general substring search - about
    # four times the cost on a token this short, paid once per skipped line.
    # The answer is the text version's either way.
    if 46 not in token and 101 not in token and 69 not in token:
        return False
    try:
        at = float(token)
    except ValueError:
        return False
    if not ((lo is not None and at < lo) or (hi is not None and at > hi)):
        return False
    if raw.find(b'"at"', end) >= 0:
        return False
    return raw.isascii()

def _usage_timeseries_scan(realm, lo, hi, step):
    """One uncached pass over the log, folding rows into fixed-width buckets.

    这是窗口序列的兜底路径：日/小时桶切片不成立（见 _series_slice）时用它，
    口径一字未改。
    """
    buckets = {}
    # 窗口内 credit 前 50 条：大小 50 的最小堆，堆顶是当前的第 50 名。旧实现
    # 把整窗的计费行全 append 进列表、扫完再 sort 整份切前 50——排序的是上万
    # 条，留下的只有 50 条。堆把每行压到一次「比不比堆顶大」的比较，进不了
    # 前 50 的行连载荷字典都不建。
    # 堆元素是 (at, -序号, 载荷)：序号取负，让相同 at 时日志靠前的行更大，与
    # 稳定排序（at 倒序、同 at 保持日志顺序）以及 _series_credit_push 的缓冲
    # 逐条一致（键唯一，堆的替换规则与稳定排序的取舍等价）。
    credits = []
    credit_seq = 0
    try:
        with _open(_usage_log_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                # Cheap window test first: a day or week window covers a small
                # slice of a multi-day log, and the json.loads this skips is
                # what made a cold scan expensive. A line the check cannot read
                # exactly falls through to the full parse and the full test
                # below, so a skipped row is always one the parse would have
                # skipped as well - same output, fewer parses.
                if _bind__line_outside_window(line, lo, hi):
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if realm and not row_matches_realm(row, realm):
                    continue
                at = row.get("at") or 0
                if at < lo or at > hi:
                    continue
                key = int((at - lo) // step)
                bucket = buckets.setdefault(key, {
                    "at": lo + key * step, "requests": 0, "errors": 0,
                    "prompt_tokens": 0, "completion_tokens": 0,
                    "reasoning_tokens": 0, "cached_tokens": 0,
                    "total_tokens": 0, "credit": 0.0,
                })
                outcome = row_outcome(row)
                if outcome == "completed":
                    bucket["requests"] += 1
                    for field in ("prompt_tokens", "completion_tokens",
                                  "reasoning_tokens", "cached_tokens",
                                  "total_tokens"):
                        bucket[field] += (row.get(field) or 0)
                else:
                    bucket["errors"] += 1
                credit = row.get("credit") or 0
                if outcome != "client_aborted":
                    bucket["credit"] += credit
                if credit > 0:
                    seq = -credit_seq
                    credit_seq += 1
                    if len(credits) < _SERIES_CREDITS_KEEP:
                        heapq.heappush(credits,
                                       (at, seq, _bind__series_credit_entry(at, row)))
                    elif (at, seq) > (credits[0][0], credits[0][1]):
                        heapq.heapreplace(credits,
                                          (at, seq, _bind__series_credit_entry(at, row)))
    except FileNotFoundError:
        pass
    except Exception as exc:
        _log("usage timeseries read failed: %s" % exc)
    # 堆里就是窗口内的前 50 条；按同一把键排出（键唯一，等于旧实现的稳定
    # 排序结果：at 倒序、同 at 保持日志顺序）。
    credits.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return {
        "ok": True, "realm": realm or "all", "bucket_seconds": step,
        "since": lo, "until": hi,
        "series": [buckets[key] for key in sorted(buckets)],
        "credits": [item[2] for item in credits],
    }

def _usage_timeseries_uncached(realm, lo, hi, step):
    """窗口序列：优先由日/小时桶/分钟环切片，不成立时整段扫描。

    切片只在「桶宽与窗口对齐」时才是同一件事，所以先按桶宽判断要不要惊动
    状态：日/小时桶要求窗口起点是本地午夜，分钟环要求起点落在分钟格点上
    （lo 是 60 的整数倍）。两条都不成立的自定义区间根本不折状态，也就不会
    为它们白扫一遍。
    """
    if step in (3600, 86400):
        day_key = _window_day_key(lo)
    elif step == 60:
        # 分钟窗口：起点落在格点上才可能与存量分钟桶一一对应（见
        # _series_slice_minutes）；不在格点上的窗口连状态都不惊动。
        day_key = _series_window_day_key(lo)
        if day_key is not None and not _series_minute_grid_ok(lo):
            day_key = None
    else:
        day_key = None
    if day_key is not None and _usage_day_buckets_enabled():
        with _series_state_lock:
            state, offset, error = _usage_series_state_ready(realm)
            out = None
            if error is not None:
                # 折叠失败：状态归零（下一次从零折起），这次退回整段扫描。
                _log("usage timeseries fold failed: %s" % error)
                state.update({"days": {}, "days_floor": None, "max_at": 0,
                              "credits": [], "minutes": {}, "minutes_from": None,
                              "hits": [], "hits_overflow": False,
                              "offset": 0, "tail": b""})
            else:
                out = _series_slice(state, realm, lo, hi, step, day_key)
        if error is None:
            _usage_cache_maybe_save("series", offset)
        if out is not None:
            return out
    return _bind__usage_timeseries_scan(realm, lo, hi, step)

_REALM_KEY = '"realm"'

_REALM_KEY_LEN = len(_REALM_KEY)

def _count_usage_line(state, line):
    """折一行：总数 + 这一行所属的 realm 桶。

    总数数的是**所有非空行**（包括解析不了的行），与旧实现一致。带 realm
    字段的行按字段值归桶（只认旧 needle 覆盖的两种间距 `"realm": "x"` 与
    `"realm":"x"`，值读到下一个引号为止——字符串里的转义引号拼不出
    `"realm"` 这个键文本，所以不会误判）。

    桶键一律过 normalize_realm，与 row_realm 同口径：历史行里写着已删区域的
    （intl）并进现存出口的桶。不归一的话，「按 realm 过滤」数出来的会比总数
    少一大截，而按行解析的其它路径给出的是总数，两边永远对不上。

    一行只归一个桶（第一处能读出来的声明）：一行就是一次请求，它只可能属于
    一个出口。字段存在但读不出值（`"realm": null`、间距花哨、被手改坏）的
    行，以及完全没有该字段的老错误行，都解析 JSON 走 row_realm() 的
    账号/模型回退——只在折叠时付一次，不像旧实现每次查询都付。
    """
    state["n"] += 1
    counts = state["n_realm"]
    pos = line.find(_REALM_KEY)
    while pos >= 0:
        end = pos + _REALM_KEY_LEN
        if line.startswith(': "', end):
            start = end + 3
        elif line.startswith(':"', end):
            start = end + 2
        else:
            start = -1
        if start >= 0:
            quote = line.find('"', start)
            if quote >= 0:
                value = normalize_realm(line[start:quote])
                counts[value] = counts.get(value, 0) + 1
                return
        pos = line.find(_REALM_KEY, end)
    # 读不出声明：解析回退。解析不了就只算进总数。
    try:
        realm = row_realm(json.loads(line))
    except Exception:
        return
    counts[realm] = counts.get(realm, 0) + 1

_RECENT_INDEX_SCHEMA = 1

_RECENT_INDEX_SEGMENT = 65536

_RECENT_INDEX_REALM_CAP = 6

_RECENT_INDEX_REALM_MAX = 128

def _recent_index_enabled():
    """索引总开关，默认开；WB_RECENT_INDEX=0 关（现场应急 / 测试切换）。

    与 WB_USAGE_CACHE 同款：每次调用读环境变量，不在导入时定死。
    """
    return os.environ.get("WB_RECENT_INDEX", "0").strip().lower() in (
        "1", "true", "yes", "on")

def _recent_index_min_bytes():
    """写盘节流：推进不足这么多字节就不写。默认 256KB。

    这个阈值就是「重启后最多回放多少」：索引加载回来后要把没索引的尾部重新
    折一遍（每行一次 json.loads），真机 1MB ≈ 0.14s、256KB ≈ 35ms。索引本身
    只有几 KB，写盘很便宜（日志每天涨 6MB 上下 → 一天几十次写、几百 KB），
    所以阈值取得比 checkpoint 的 1MB 小一档，把重启后的第一页压在几十毫秒。
    """
    return ca_env.number("WB_RECENT_INDEX_MIN_BYTES", 256 * 1024,
                         minimum=0, integer=True, zero_ok=True)

def _recent_index_min_seconds():
    """写盘节流：距上次尝试不足这么多秒就不写。默认 900s。"""
    return ca_env.number("WB_RECENT_INDEX_MIN_SECONDS", 900.0,
                         minimum=0.0, zero_ok=True)

def _recent_index_stamp():
    """索引文件的 (路径, mtime_ns, size)；文件不在时后两项为 None。

    路径也在戳里（同 estimate-daily）：换目录后不会被旧目录的戳骗过去。
    """
    try:
        st = os.stat(_recent_index_file())
        return (_recent_index_file(), st.st_mtime_ns, st.st_size)
    except OSError:
        return (_recent_index_file(), None, None)

def _recent_index_realm_map_json(disk):
    """磁盘那份 uid→realm 的 JSON 形态（与索引文件里的比）。"""
    if disk is None:
        return None
    return [[uid, realm] for uid, realm in disk]

def _recent_index_realm_name(value):
    """realm 表里的键：只收能出现在查询里的短字符串，其余让索引作废。

    row_realm 对带字段的行原样返回字段值，手改过的行可以带出数字或超长的
    值：它们既进不了 JSON 键、也不会等于任何字符串查询，但会把表撑大，索性
    让整份索引不可用（老路照常给出正确结果）。
    """
    if isinstance(value, str) and len(value) <= _RECENT_INDEX_REALM_MAX:
        return value
    return None

def _recent_index_realm_ok(state):
    """realm 相关的数字能不能信这份索引。

    只有「没带 realm 字段、带 account 的行」会查到活池（row_realm），别的行
    归属只由行内字段决定，任何进程、任何时刻算出来都一样。有这类行时要求：
    折进来时的 uid→realm（磁盘那份）与现在一致，且活池与磁盘一致
    （_realm_fold_reproducible）——两者合起来把归属钉死，索引算出的每个
    realm 计数与现在这台机器上会算出来的那份逐字相同。
    """
    if not state["legacy"]:
        return True
    realm_map = state["realm_map"]
    if realm_map is None:
        return False
    disk = _account_realm_map()
    if _recent_index_realm_map_json(disk) != realm_map:
        return False
    return _realm_fold_reproducible(disk)

def _recent_index_blank():
    """一份空索引的核心字段（写盘形态与内存形态共用）。"""
    return {"key": None, "size": 0, "tail": b"", "realm_map": None,
            "legacy": False, "realms": [], "counts": {}, "row_counts": {},
            "lines": 0, "rows": 0, "segs": []}

_recent_index_lock = threading.Lock()

_recent_index_state = {
    "stamp": None, "usable": False, "giveup": False, "giveup_key": None,
    "key": None, "size": 0, "tail": b"", "realm_map": None, "legacy": False,
    "realms": [], "counts": {}, "row_counts": {}, "lines": 0, "rows": 0,
    "segs": [], "wrote_size": 0, "wrote_at": 0.0,
}

def _recent_index_restart(state, realm_map):
    """清回零重新折（保留文件戳与写盘节流）：位置或归属口径变了才走这里。"""
    state.update(_recent_index_blank())
    state.update({"usable": False, "giveup": False, "giveup_key": None,
                  "realm_map": realm_map})

def _recent_index_add_realm(state, name):
    """把一个新 realm 值加进表，段数组同步补一列零。

    表就是段数组的列序：某一段里没出现过的值，计数本来就是 0，补零不改变
    任何累计值。
    """
    if name in state["realms"]:
        return True
    if len(state["realms"]) >= _RECENT_INDEX_REALM_CAP:
        return False
    state["realms"].append(name)
    for seg in state["segs"]:
        seg.append(0)
    state["counts"].setdefault(name, 0)
    state["row_counts"].setdefault(name, 0)
    return True

def _recent_index_dirty(state):
    """扫描撞上索引处理不了的行：这份状态不能用了，本进程不再重试。

    与「干净停下」的区别：_count_usage_line 可能已经把半个计数写进状态，
    续读会得到错的累计值，所以整份丢掉、记住日志位置——日志被换掉（key 变）
    才再试一次，否则每次调用都重扫一遍比老路还贵。
    """
    state.update(_recent_index_blank())
    state.update({"usable": False, "giveup": True,
                  "giveup_key": _usage_log_key()})
    return False

def _recent_index_fold_line(state, line):
    """一行折进两个口径；返回 False 表示这行让索引不能用了（见上）。"""
    counts = state["counts"]
    before = len(counts)
    shim = {"n": state["lines"], "n_realm": counts}
    try:
        _count_usage_line(shim, line)
    except Exception:
        return _recent_index_dirty(state)
    state["lines"] = shim["n"]
    if len(counts) != before:
        for name in list(counts):
            if name in state["realms"]:
                continue
            good = _recent_index_realm_name(name)
            if good is None or not _recent_index_add_realm(state, good):
                return _recent_index_dirty(state)
    try:
        row = json.loads(line)
    except Exception:
        return True                     # 坏 JSON：算行数、不算记录（D5 同款）
    if not isinstance(row, dict):
        # 老实现会把 null / 数组这类行原样放进 matching（随后计价时炸掉）：
        # 这种日志不用索引，让老路照旧处理。
        return _recent_index_dirty(state)
    if not row.get("realm") and row.get("account"):
        state["legacy"] = True          # 这一行的归属要查活池
    try:
        name = row_realm(row)
    except Exception:
        return _recent_index_dirty(state)
    name = _recent_index_realm_name(name)
    if name is None or not _recent_index_add_realm(state, name):
        return _recent_index_dirty(state)
    state["rows"] += 1
    state["row_counts"][name] = state["row_counts"].get(name, 0) + 1
    return True

def _recent_index_extend(state):
    """把索引推进到日志尾部；返回是否可用。

    与 _count_usage_scan 同一套字节纪律：整行推进、半行留给下一趟、解码失败
    即停。停下的位置就是 size（最后一条完整行的末尾），下一趟从那里接着读，
    所以半行与坏字节只让索引暂时不可用，不会让每次调用都重扫整份日志。
    """
    if state["giveup"]:
        return False
    offset = state["size"]
    try:
        with _open(_usage_log_path(), "rb") as fh:
            fh.seek(offset)
            while True:
                raw = fh.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    state["size"] = offset      # 半行（写入中/掉电碎片）
                    return False
                end = offset + len(raw)
                try:
                    line = raw.decode("utf-8").strip()
                except UnicodeDecodeError:
                    state["size"] = offset      # 解码失败：索引停在这行之前
                    return False
                if line and not _recent_index_fold_line(state, line):
                    if not state["giveup"]:
                        state["size"] = offset
                    return False
                offset = end
                last = state["segs"][-1][0] if state["segs"] else 0
                if offset - last >= _RECENT_INDEX_SEGMENT:
                    state["segs"].append(
                        [offset, state["rows"]]
                        + [state["row_counts"].get(r, 0)
                           for r in state["realms"]])
    except OSError:
        state["size"] = offset
        return False
    except Exception:
        state["size"] = offset
        return False
    state["size"] = offset
    state["key"] = _usage_log_key()
    state["tail"] = _log_tail_signature(offset)
    if state["tail"] is None:
        return False                        # 签名读不回来：位置校验立不住
    state["usable"] = True
    return True

def _recent_index_payload(state):
    """索引的 JSON 形态：段用增量写（offset 差 + 各列计数差）。

    增量写出来的数字都小（offset 差就是段宽，计数差是段内的记录数），4 万行
    的日志整份不到 10KB；累计值在加载时一次加回去。不排序键：段数组是位置
    敏感的，形状固定，无需靠键序表达什么。
    """
    segs = []
    prev_off = 0
    prev = [0] * (2 + len(state["realms"]))
    for seg in state["segs"]:
        row = [seg[0] - prev_off]
        for i in range(1, len(seg)):
            row.append(seg[i] - prev[i])
        segs.append(row)
        prev_off = seg[0]
        prev = seg
    return {
        "schema": _RECENT_INDEX_SCHEMA,
        "seg": _RECENT_INDEX_SEGMENT,
        "key": list(state["key"] or (0, 0, 0)),
        "tail": state["tail"].hex(),
        "realm_map": state["realm_map"],
        "legacy": bool(state["legacy"]),
        "realms": list(state["realms"]),
        "totals": {"lines": state["lines"], "rows": state["rows"],
                   "counts": dict(state["counts"]),
                   "row_counts": dict(state["row_counts"])},
        "segs": segs,
    }

def _recent_index_write(state):
    """原子写索引（同目录 .tmp + os.replace，同 checkpoint / estimate-daily）。"""
    os.makedirs(_usage_dir(), exist_ok=True)
    tmp = _recent_index_file() + ".tmp"
    text = json.dumps(_recent_index_payload(state), ensure_ascii=False,
                      separators=(",", ":"))
    try:
        with _open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, _recent_index_file())
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _recent_index_parse(data):
    """磁盘上的索引 → 内存状态；任何一处不合形状都返回 None（当作没有索引）。"""
    if not isinstance(data, dict) or data.get("schema") != _RECENT_INDEX_SCHEMA:
        return None
    if data.get("seg") != _RECENT_INDEX_SEGMENT:
        return None
    realms = data.get("realms")
    if not isinstance(realms, list) or len(realms) > _RECENT_INDEX_REALM_CAP:
        return None
    for name in realms:
        if _recent_index_realm_name(name) is None:
            return None
    if len(set(realms)) != len(realms):
        return None
    totals = data.get("totals")
    if not isinstance(totals, dict):
        return None
    lines = totals.get("lines")
    rows = totals.get("rows")
    counts = totals.get("counts")
    row_counts = totals.get("row_counts")
    if (not _usage_cache_int(lines) or lines < 0
            or not _usage_cache_int(rows) or rows < 0):
        return None
    if not _usage_cache_counts_ok(counts) or not _usage_cache_counts_ok(row_counts):
        return None
    key = data.get("key")
    if (not isinstance(key, list) or len(key) != 3
            or not all(_usage_cache_int(v) and v >= 0 for v in key)):
        return None
    tail = data.get("tail")
    if not isinstance(tail, str):
        return None
    try:
        tail_bytes = bytes.fromhex(tail)
    except ValueError:
        return None
    realm_map = data.get("realm_map")
    if realm_map is not None:
        if not isinstance(realm_map, list):
            return None
        for item in realm_map:
            if (not isinstance(item, list) or len(item) != 2
                    or not isinstance(item[0], str)
                    or not isinstance(item[1], str)):
                return None
    if not isinstance(data.get("legacy"), bool):
        # 老行归属要不要查池：这个标记决定 realm 数字信不信这份索引，写成
        # 别的一律当坏文件（宁可重扫）。
        return None
    segs_raw = data.get("segs")
    if not isinstance(segs_raw, list):
        return None
    width = 2 + len(realms)
    segs = []
    off = 0
    prev = [0] * width
    for raw in segs_raw:
        if (not isinstance(raw, list) or len(raw) != width
                or not all(_usage_cache_int(v) and v >= 0 for v in raw)):
            return None
        off += raw[0]
        cur = [off]
        for i in range(1, width):
            cur.append(prev[i] + raw[i])
        segs.append(cur)
        prev = cur
    state = _recent_index_blank()
    state.update({
        "key": tuple(key), "size": key[0], "tail": tail_bytes,
        "realm_map": realm_map, "legacy": data.get("legacy") is True,
        "realms": list(realms), "counts": dict(counts),
        "row_counts": dict(row_counts), "lines": lines, "rows": rows,
        "segs": segs,
    })
    return state

def _recent_index_adopt(state, stamp):
    """文件戳变了：把磁盘那份读进来。

    只接受「比内存这份更新」（同一份日志上更长的索引，或内存这份已经不成立）
    的文件——内存里那份是同一份日志的续读，回退到更短的磁盘版本等于白扫。
    读不出来或校验不过就当没有索引：下一趟从零重建（坏文件不报错）。
    """
    data = None
    if stamp[1] is not None:
        try:
            with _open(_recent_index_file(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError, UnicodeDecodeError):
            data = None
    loaded = _recent_index_parse(data) if data is not None else None
    if loaded is not None:
        log_key = _usage_log_key()
        if (_log_offset_holds(loaded["key"], log_key, loaded["size"])
                and _log_tail_signature(loaded["size"]) == loaded["tail"]):
            if not state["usable"] or loaded["size"] > state["size"]:
                state.update(loaded)
                state.update({"usable": True, "giveup": False,
                              "giveup_key": None, "stamp": stamp,
                              "wrote_size": loaded["size"],
                              "wrote_at": time.time()})
                return
    state["stamp"] = stamp
    if not state["usable"]:
        _recent_index_restart(
            state, _recent_index_realm_map_json(_account_realm_map()))

def _recent_index_maybe_write(state):
    """按节流阈值把索引落盘（默认 256KB / 900s）。

    第一次建起来立即写——那正是「重启后免重扫」的那一份；之后只在推进满
    256KB 或距上次尝试满 900s 时写（空闲不重写）。记「尝试」而非成功：只读
    文件系统上失败会一直成立，不退避的话每次刷新都去试写一遍。归属复现不了
    的索引不写：写下去别的进程也不敢用。
    """
    now = time.time()
    size = state["size"]
    if size <= state["wrote_size"]:
        return
    if (size - state["wrote_size"] < _recent_index_min_bytes()
            and (now - state["wrote_at"]) < _recent_index_min_seconds()):
        return
    if not _recent_index_realm_ok(state):
        return
    state["wrote_at"] = now
    state["wrote_size"] = size
    try:
        _recent_index_write(state)
    except Exception as exc:
        _log("recent index write failed: %s" % exc)
        return
    state["stamp"] = _recent_index_stamp()

def _recent_index_snapshot(state):
    """给调用方的只读拷贝（锁外读页时状态可能被别的线程推进）。"""
    return {
        "size": state["size"],
        "realms": list(state["realms"]),
        "counts": dict(state["counts"]),
        "row_counts": dict(state["row_counts"]),
        "lines": state["lines"],
        "rows": state["rows"],
        "segs": [list(seg) for seg in state["segs"]],
    }

def _recent_index_resume_ok(state, log_key):
    """位置校验：索引覆盖的字节还是这份日志的前缀。

    与聚合折叠同款判据（_log_offset_holds + _log_tail_signature）：size/inode
    挡住截断与换文件，size 前的 64B 签名挡住同尺寸重写。
    """
    return (_log_offset_holds(state["key"], log_key, state["size"])
            and _log_tail_signature(state["size"]) == state["tail"])

def _recent_index_ready(realm_filtered=False):
    """扩到文件尾的索引快照；None 表示这次查询走老路（count + 反向读）。

    顺序固定：先看文件戳（外部改动）→ 位置校验（截断/替换/同尺寸重写）→
    归属口径（realm_map 变了整份重折）→ 续读到尾 → realm 查询再验一次归属。
    """
    if not _recent_index_enabled():
        return None
    with _recent_index_lock:
        state = _recent_index_state
        stamp = _recent_index_stamp()
        if state["stamp"] != stamp:
            _recent_index_adopt(state, stamp)
        log_key = _usage_log_key()
        if state["giveup"]:
            if state["giveup_key"] == log_key:
                return None
            state["giveup"] = False             # 日志被换掉了：再给一次机会
        if state["size"] > 0:
            if not _recent_index_resume_ok(state, log_key):
                # 位置对不上（截断/换文件/同尺寸重写）：整份重折
                _recent_index_restart(
                    state, _recent_index_realm_map_json(_account_realm_map()))
            elif state["legacy"]:
                realm_map = _recent_index_realm_map_json(_account_realm_map())
                if state["realm_map"] != realm_map:
                    # 归属口径变了（uid→realm 改过）：整份重折
                    # ——与聚合折叠同款政策。
                    _recent_index_restart(state, realm_map)
        if not state["usable"] and not state["segs"] and not state["lines"]:
            # 从零开始：把这次的归属口径记下来（后面续读都按它校验）
            state["realm_map"] = _recent_index_realm_map_json(
                _account_realm_map())
        # 每次都续读到文件尾：日志只会追加，续读的代价就是新字节（没有新
        # 字节时只是一次 seek 到底的空读）。
        if not _recent_index_extend(state):
            return None
        if realm_filtered and not _recent_index_realm_ok(state):
            return None
        _recent_index_maybe_write(state)
        return _recent_index_snapshot(state)

def _recent_index_total(snap, realm):
    """页数标签：口径与 count_usage_rows 完全一致（总数含坏 JSON 的非空行）。"""
    if not realm:
        return snap["lines"]
    return snap["counts"].get(realm, 0)

def _recent_index_page(snap, realm, page, limit):
    """第 page 页的记录（新的在前）；None 表示索引答不了，调用方走老路。

    老实现的页 = 从尾部往回数第 (page-1)*limit+1 .. page*limit 条记录，切片
    两端都夹在「真的存在这么多条」上（页数标签含坏行、记录数不含，最后几页
    因此可能短、甚至为空）。这里把同一件事换算成从头数的序号：第 k 条匹配
    记录在两套里是同一行，于是页的字节区间就是 [第 K_lo 条起点, 第 K_hi 条
    终点]，从 K_lo 所在段的起点顺序读过去即可。
    """
    if realm:
        if realm not in snap["realms"]:
            return []                        # 一条也不匹配：老路也是空页
        col = 2 + snap["realms"].index(realm)
        total_rows = snap["row_counts"].get(realm, 0)
    else:
        col = 1
        total_rows = snap["rows"]
    target = page * limit
    k_hi = total_rows - (page - 1) * limit
    if k_hi < 1:
        return []                            # 页落在记录总数之外：老路是空切片
    k_lo = max(1, total_rows - target + 1)
    segs = snap["segs"]
    # 二分：第一个「到该段起点为止的记录数 >= K_lo」的段；它前一段就是起点
    lo, hi = 0, len(segs)
    while lo < hi:
        mid = (lo + hi) // 2
        if segs[mid][col] < k_lo:
            lo = mid + 1
        else:
            hi = mid
    start = segs[lo - 1][0] if lo > 0 else 0
    have = segs[lo - 1][col] if lo > 0 else 0
    # 段起点之前的记录数是 have，段里第一条就是第 have+1 条：跳过
    # k_lo-have-1 条，下一条正好是第 k_lo 条（K_lo > have 由二分保证）。
    rows = _recent_index_read(start, realm, k_lo - have - 1, k_hi - k_lo + 1)
    if rows is None:
        return None
    rows.reverse()
    return rows

def _recent_index_read(start, realm, skip, take):
    """从 start 顺序读到第 take 条匹配记录；对不上就返回 None（走老路）。

    读取量 = 一段（64KB）+ 页本身的字节，与页深无关——这正是老实现最贵的
    地方（第 1 页也要读满一个 256KB 块，realm 过滤的页要读回整个文件）。
    读到的行与老实现逐字一致：同一套 strip/解码（"replace"）与 json.loads，
    realm 过滤走同一个 row_matches_realm。
    """
    rows = []
    seen = 0
    try:
        with _open(_usage_log_path(), "rb") as fh:
            fh.seek(start)
            buf = b""
            while len(rows) < take:
                # 64KB 一读：正好一段的量级，页读完就停手（读取量 = 一段 +
                # 页本身的字节，与页深无关）。
                chunk = fh.read(64 * 1024)
                if not chunk:
                    break
                buf += chunk
                parts = buf.split(b"\n")
                buf = parts.pop()
                for raw in parts:
                    st = raw.strip()
                    if not st:
                        continue
                    try:
                        item = json.loads(st.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    if not isinstance(item, dict):
                        return None     # 索引覆盖的字节里不该有这种行
                    if realm and not row_matches_realm(item, realm):
                        continue
                    if seen < skip:
                        seen += 1
                        continue
                    rows.append(item)
                    if len(rows) >= take:
                        break
    except Exception as exc:
        _log("recent index read failed: %s" % exc)
        return None
    if len(rows) < take:
        return None
    return rows

def _recent_backward_page(realm, page, limit):
    """老路：从尾部按 256KB 块往回读，凑够 page*limit 条再切片。

    页深越大读得越多（realm 过滤命中率低时要读回整个文件），所以索引可用时
    不走这里；索引答不了（半行、坏字节、池没就绪……）时它是唯一的正确答案，
    逐字保留原实现的行为。
    """
    target_count = page * limit
    matching = []
    chunk = 256 * 1024
    try:
        with _open(_usage_log_path(), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0 and len(matching) < target_count:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                parts = buf.split(b"\n")
                buf = parts[0]
                for raw in reversed(parts[1:]):
                    st = raw.strip()
                    if not st:
                        continue
                    try:
                        item = json.loads(st.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    if realm and not row_matches_realm(item, realm):
                        continue
                    matching.append(item)
                    if len(matching) >= target_count:
                        break
            if len(matching) < target_count and buf.strip():
                try:
                    item = json.loads(buf.strip().decode("utf-8", "replace"))
                    if not realm or row_matches_realm(item, realm):
                        matching.append(item)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    except Exception as exc:
        _log("recent_usage read failed: %s" % exc)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    return matching[start_idx:end_idx]

_byacct_cache = {"at": 0.0, "data": None}

_byacct_lock = threading.Lock()

def usage_by_account(ttl=None):
    """Cached wrapper: full aggregation over the whole log is expensive.

    Rebuilds under the lock, same reasoning as usage_snapshot."""
    ttl = _bind__STATS_TTL() if ttl is None else ttl
    now = time.time()
    with _byacct_lock:
        if _byacct_cache["data"] is not None and (now - _byacct_cache["at"]) < ttl:
            return _byacct_cache["data"]
        data = _usage_by_account_uncached()
        _byacct_cache["at"] = time.time()
        _byacct_cache["data"] = data
    return data

def usage_by_account_etag():
    """usage_by_account() 当前缓存条目的 ETag；没有条目时返回 None。

    这个视图只有一条缓存（没有窗口/区域参数），所以键是常量。配对调用由
    _json_cached() 负责。
    """
    with _byacct_lock:
        if _byacct_cache["data"] is None:
            return None
        built_at = _byacct_cache["at"]
    return _cache_etag("by-account", "all", built_at)

_byacct_state = {"buckets": None, "offset": 0, "key": None, "tail": b""}

_byacct_state_lock = threading.Lock()

def _fold_usage_by_account(row, buckets):
    """Fold one row into the per-account buckets.

    No window and no realm filter here - this view has always described the
    whole log - so the fold only skips the rows the original skipped.
    """
    if row.get("error"):
        return
    key = row.get("account") or "(unattributed)"
    bucket = buckets.get(key)
    if bucket is None:
        bucket = buckets[key] = {
            "account": key, "requests": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "reasoning_tokens": 0,
            "cached_tokens": 0, "total_tokens": 0, "models": {},
        }
    bucket["requests"] += 1
    bucket["prompt_tokens"] += row.get("prompt_tokens") or 0
    bucket["completion_tokens"] += row.get("completion_tokens") or 0
    bucket["reasoning_tokens"] += row.get("reasoning_tokens") or 0
    bucket["cached_tokens"] += row.get("cached_tokens") or 0
    bucket["total_tokens"] += row.get("total_tokens") or 0
    model = row.get("model") or "?"
    models = bucket["models"]
    models[model] = models.get(model, 0) + 1

def _usage_by_account_buckets():
    """The cached per-account fold, refreshed and copied for the caller.

    The copy matters: _usage_by_account_uncached() replaces each bucket's
    `models` dict with a sorted list, and the next refresh must still find the
    counts dict where it left it.
    """
    with _byacct_state_lock:
        log_key = _usage_log_key()
        if _byacct_state["buckets"] is None:
            # 全新状态（进程刚起来）：先问 checkpoint，问不到才从零折起。
            if not _usage_cache_adopt_by_account(_byacct_state, log_key):
                _byacct_state.update({"buckets": {}, "offset": 0, "tail": b""})
        elif not _log_resume_ok(_byacct_state, log_key):
            _byacct_state.update({"buckets": {}, "offset": 0, "tail": b""})
        _byacct_state["key"] = log_key
        offset, error = _scan_usage_from(
            _byacct_state["offset"],
            lambda row: _fold_usage_by_account(row, _byacct_state["buckets"]))
        buckets = _byacct_state["buckets"]
        if error is None:
            _byacct_state["offset"] = offset
            _byacct_state["tail"] = _log_tail_signature(offset)
        else:
            # The row that stopped the fold may have half applied
            # itself, so this view starts over next call - the full
            # scan it replaces does the same on every call.
            _log("usage_by_account failed: %s" % error)
            _byacct_state.update({"buckets": {}, "offset": 0, "tail": b""})
        out = {k: dict(v) for k, v in buckets.items()}
    if error is None:
        _usage_cache_maybe_save("by_account", offset)
    return out

def _usage_by_account_uncached():
    """Aggregate the JSONL log per account id.

    Incremental: the fold is carried over and refreshed with the rows appended
    since the last call, so this costs what the new traffic costs instead of
    what the whole log costs.
    """
    buckets = _usage_by_account_buckets()
    out = sorted(buckets.values(), key=lambda b: -b["total_tokens"])
    for item in out:
        item["models"] = sorted(item["models"].items(), key=lambda kv: -kv[1])[:5]
    return out

_analytics_cache = {}

_analytics_lock = threading.Lock()

def _analytics_scope(realm, range, since, until):
    """(since, until, 缓存键) —— compute_usage_analytics() 与它的 ETag 共用。

    注意键里用的是**原始** realm（`realm or "all"`），与这个接口一直以来的键
    一致；折叠时用 realm_scope(realm) 另有其义。两者都不能顺手"统一"，否则就是
    换了一条缓存键。
    """
    lo, hi = range_window(range, since, until)
    cache_key = "%s|%s|%s" % (realm or "all",
                              lo if lo is not None else "", hi if hi is not None else "")
    return lo, hi, cache_key

def usage_analytics_etag(realm=None, range=None, since=None, until=None):
    """compute_usage_analytics() 当前缓存条目的 ETag；无条目返回 None。

    配对调用由 _json_cached() 负责，理由见那里。
    """
    _lo, _hi, cache_key = _analytics_scope(realm, range, since, until)
    with _analytics_lock:
        entry = _analytics_cache.get(cache_key)
    if entry is None:
        return None
    return _cache_etag("analytics", cache_key, entry["at"])

def _new_analytics_stat():
        return {
            "requests": 0, "errors": 0,
            "prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0,
            "cached_tokens": 0, "total_tokens": 0,
            "credit": 0.0,
            "ttft_sum": 0.0, "ttft_n": 0,
            "speed_sum": 0.0, "speed_n": 0,
            "elapsed_sum": 0.0, "elapsed_n": 0,
        }

KEY_BUCKET_BEFORE = "__before_keys__"

KEY_BUCKET_ANON = "__no_key__"

_ANALYTICS_ALL = ("all_time", "all_models")

_ANALYTICS_WINDOW = ("window", "window_models")

def _new_analytics_maps():
    """The four maps one half of the payload folds into."""
    return {"summary": _new_analytics_stat(), "accts": {}, "models": {}, "keys": {}}

def _analytics_row_values(row):
    """The per-row numbers the folds below need, read once per row.

    feed()/bump_models() used to call row.get() for each of them on every
    invocation - eight stat objects per row, all walking the same handful of
    fields - which was the single biggest cost of a cold analytics pass.
    """
    return (row.get("prompt_tokens") or 0,
            row.get("completion_tokens") or 0,
            row.get("reasoning_tokens") or 0,
            row.get("cached_tokens") or 0,
            row.get("total_tokens") or 0,
            row.get("credit") or 0,
            row.get("ttft_ms"),
            row.get("tokens_per_sec"),
            row.get("elapsed_ms"))

def _feed_analytics(stat_obj, vals, is_err):
    """Fold one row's numbers into one analytics stat object.

    Token totals follow actual consumption, so a request that failed after the
    upstream had already billed for tokens still shows them; only the
    request/error counters depend on the outcome.
    """
    if is_err:
        stat_obj["errors"] += 1
    else:
        stat_obj["requests"] += 1
    stat_obj["prompt_tokens"] += vals[0]
    stat_obj["completion_tokens"] += vals[1]
    stat_obj["reasoning_tokens"] += vals[2]
    stat_obj["cached_tokens"] += vals[3]
    stat_obj["total_tokens"] += vals[4]
    stat_obj["credit"] += vals[5]
    if vals[6]:
        stat_obj["ttft_sum"] += vals[6]
        stat_obj["ttft_n"] += 1
    if vals[7]:
        stat_obj["speed_sum"] += vals[7]
        stat_obj["speed_n"] += 1
    if vals[8]:
        stat_obj["elapsed_sum"] += vals[8]
        stat_obj["elapsed_n"] += 1

def _bump_analytics_models(tgt, m_id, vals, is_err):
    """Fold one row into one {model: {...}} bucket.

    Model distribution counts successful requests only: a failed call
    attributed to a model would show up as demand for it when the caller got
    nothing.
    """
    if is_err:
        return
    tm = tgt.get(m_id)
    if tm is None:
        tm = tgt[m_id] = {"requests": 0, "tokens": 0, "reasoning": 0}
    tm["requests"] += 1
    tm["tokens"] += vals[4]
    tm["reasoning"] += vals[2]

def _fold_usage_analytics(row, realm, maps, half, pricing_on=None, also=None,
                          pricing=None, priced=None):
    """Fold one parsed row into one half of the analytics payload.

    `maps` holds the four maps that half folds into and `half` names the stat
    each entry of that half owns, so the incremental all-time fold (every
    entry's all_time stat) and the windowed pass (the same entries' window
    stat) share one definition of what a row contributes.

    The key axis is separate from the account axis on purpose: one key can be
    served by many upstream accounts, and one account can serve many keys, so
    the two tables are views of the same spend, not a decomposition of it.

    `also` 是同一行还要折进的那几份 (maps, half) 的序列（按日分桶与按小时
    分桶的窗口半）。过滤、算价与字段提取只做一次，各份各自累加：折叠本来
    就要求每侧各记一笔，而 cost_for_row 与 realm 判定是每行最贵的那部分，
    只该付一次。

    `pricing` 是本次扫描开头取到的 _pricing_inputs() 元组（见
    _fold_usage_snapshot 的同名参数）。

    `priced` 是本次扫描要填的「用到的价」记录（见「用到的价」状态指纹一节），
    只有推进状态的那条折叠传它；窗口半/冷扫描传 None。
    """
    if realm and not row_matches_realm(row, realm):
        return
    # Only a genuine gateway/upstream failure is an error. A client
    # cancellation is not: its token counts are incomplete, and folding them
    # into the ratios this page reports would understate cache hit and speed.
    # It is counted in perf_stats instead.
    outcome = row_outcome(row)
    if outcome == "client_aborted":
        return
    is_err = outcome != "completed"
    cost = _bind__row_cost(row, pricing, pricing_on)
    # 折进去的每一行都把「用到的价」记进状态指纹（中止行在上面整行跳过）。
    _priced_note(priced, row, cost, pricing)
    vals = _analytics_row_values(row)
    acct_uid = row.get("account") or "(unattributed)"
    m_id = row.get("model") or "(unknown)"
    # A row written before this feature existed has no `key` field at all; a
    # row from a deployment that never configured a key has one, and it is
    # empty.
    if "key" in row:
        k_id = row.get("key") or KEY_BUCKET_ANON
    else:
        k_id = KEY_BUCKET_BEFORE
    k_realm = row_realm(row) or ""
    at = row.get("at") or 0
    targets = [(maps, half)]
    if also is not None:
        targets.extend(also)
    for tgt, (stat_key, models_key) in targets:
        _feed_analytics(tgt["summary"], vals, is_err)

        entry = tgt["accts"].get(acct_uid)
        if entry is None:
            entry = tgt["accts"][acct_uid] = {
                "uid": acct_uid,
                "nickname": acct_uid,
                "realm": row.get("realm", ""),
                "domain": "",
                stat_key: _new_analytics_stat(),
                models_key: {},
            }
        _feed_analytics(entry[stat_key], vals, is_err)
        _bump_analytics_models(entry[models_key], m_id, vals, is_err)

        model = tgt["models"].get(m_id)
        if model is None:
            model = tgt["models"][m_id] = {"model": m_id,
                                           stat_key: _new_analytics_stat()}
        _feed_analytics(model[stat_key], vals, is_err)

        km = tgt["keys"].get(k_id)
        if km is None:
            km = tgt["keys"][k_id] = {
                "key": k_id,
                stat_key: _new_analytics_stat(),
                models_key: {},
                # realm -> row count. A key bound to one exit only ever sees
                # that exit; a key with no binding follows the model, and its
                # credit column then adds up two different products. Kept as a
                # dict because this ends up in JSON.
                "realms": {},
                "last_at": 0,
            }
        km["realms"][k_realm] = km["realms"].get(k_realm, 0) + 1
        if at and at > km["last_at"]:
            km["last_at"] = at
        _feed_analytics(km[stat_key], vals, is_err)
        _bump_analytics_models(km[models_key], m_id, vals, is_err)

_analytics_state = {}

_analytics_state_lock = threading.Lock()

def _analytics_all_time(realm, pricing_on=None):
    """The cached all-time fold for one realm filter; returns (maps, offset).

    One state per realm: the filter decides which rows the fold ever sees, so
    two realms are two folds and neither may inherit the other's rows. Only
    the all-time half is cached - the windowed half moves with the clock - and
    the offset comes back with it so a windowed pass can stop where the fold
    stopped.
    """
    with _analytics_state_lock:
        state, offset, error = _analytics_state_ready(realm, pricing_on)
        if error is None:
            # Copied under the lock, same rule as the snapshot state: what
            # the caller decorates must not be the live fold.
            maps = _copy_analytics_all_time(state["maps"])
        else:
            # Same rule as the snapshot state: the row that stopped the
            # fold may have half applied itself, so the state starts
            # over next call. The offset still goes back - it is the
            # end of that row - because the windowed half has to see
            # it, and stop there, to describe the same bytes the
            # all-time half already folded.
            _log("compute_usage_analytics failed: %s" % error)
            maps = state["maps"]
            state.update({"maps": _new_analytics_maps(), "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "max_at": 0})
    if error is None:
        _usage_cache_maybe_save("analytics", offset)
    return maps, offset

def _analytics_state_advance(realm, pricing_on=None):
    """（不折叠）取/建状态、采纳 checkpoint、判废归零、记指纹。

    调用方必须已持有 _analytics_state_lock。返回本次扫描取到的价表代次
    （与记进状态指纹的是同一份）。状态是否「冷」（这次要付一次全量重折）看
    state["offset"]：> 0 表示有可续折的数据，0 表示折叠要从文件头开始——
    状态刚建、刚被价表 / realm / 日志判废、或 checkpoint 采纳失败。与
    snapshot 侧同一套分工：采纳/判废只有这一段定义，_analytics_state_ready
    与窗口路径的冷热判定（_analytics_state_cold）共用它，两边不会漂移。
    """
    state = _analytics_state.get(realm)
    if state is None:
        state = _analytics_state[realm] = {"maps": _new_analytics_maps(),
                                           "offset": 0, "key": None,
                                           "pricing": None, "realm": None,
                                           "tail": b"", "days": {},
                                           "days_floor": None, "max_at": 0,
                                           "hours_keep": True,
                                           "hits": [], "hits_overflow": False}
    pricing = _pricing_inputs(pricing_on)
    realm_inputs = _realm_inputs()
    log_key = _usage_log_key()
    fresh = _pricing_record_new() if (pricing is not None
                                      and pricing[0]) else None
    if state["key"] is None:
        # 全新状态（进程刚起来）：先问 checkpoint，问不到才从零折起。
        if not _usage_cache_adopt_analytics(realm, state, log_key, pricing, realm_inputs):
            state.update({"maps": _new_analytics_maps(), "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "max_at": 0,
                          "hits": [], "hits_overflow": False, "pricing": fresh})
    elif (not _pricing_used_unchanged(state["pricing"], pricing)
            or state["realm"] != realm_inputs
            or not _log_resume_ok(state, log_key)):
        state.update({"maps": _new_analytics_maps(), "offset": 0, "tail": b"",
                      "days": {}, "days_floor": None, "max_at": 0,
                      "hits": [], "hits_overflow": False, "pricing": fresh})
    state.update({"realm": realm_inputs, "key": log_key})
    return pricing

def _analytics_state_cold(realm, pricing_on=None):
    """窗口请求现在会不会付一次全量重折？True = 会（窗口改走冷扫描）。

    调用方必须已持有 _analytics_state_lock。语义与 _usage_snap_state_cold
    逐条相同：判定不折叠、不写结果，窗口请求不会把状态冻在冷态（offset 仍是
    0，下一个 all-time 半的请求照样从零折到文件尾），重折之后两边字节一致。
    """
    _analytics_state_advance(realm, pricing_on)
    return _analytics_state[realm]["offset"] <= 0

def _analytics_state_ready(realm, pricing_on=None):
    """把 `realm` 的 all-time 折叠推进到文件尾；返回 (state, offset, error)。

    调用方必须已持有 _analytics_state_lock。日桶、小时子表与 all-time 折叠
    共用这一次扫描（见 _fold_usage_analytics 的 also），窗口半与 all-time 半
    因此描述同一段字节。

    `hours_keep` 标记这份状态要维护小时子表（剪枝线比日桶短，见
    _prune_day_buckets）；`max_at` 是折过的最大 at（含 realm 不匹配的行），
    小时窗口靠它判断窗口上界有没有切掉桶里的行。

    状态指纹是「折叠行真正用到的价」记录（T15，见「用到的价」状态指纹一节）：
    折叠时逐行更新（state["pricing"]），扫描成功后刷时间线投影摘要
    （_pricing_record_close），判废走 _pricing_used_unchanged。

    采纳 checkpoint 与判废归零在 _analytics_state_advance 里（窗口路径的
    冷热判定也用那一段），这里只管折到文件尾。
    """
    pricing = _analytics_state_advance(realm, pricing_on)
    state = _analytics_state[realm]
    priced = state["pricing"]

    def fold(row):
        # 一行折三处：all-time 半 + 它所属那天的窗口半 + 那天里它所属那小时
        # 的窗口半（过滤与算价只做一次）。
        at = row.get("at") or 0
        if at > state["max_at"]:
            state["max_at"] = at
        day = _usage_day_bucket(state, row, realm, _day_analytics_bucket)
        hour = _analytics_hour_bucket(day, at)
        if day is None:
            also = None
        elif hour is None:
            also = ((day, _ANALYTICS_WINDOW),)
        else:
            also = ((day, _ANALYTICS_WINDOW), (hour, _ANALYTICS_WINDOW))
        _bind__fold_usage_analytics(
            row, realm, state["maps"], _ANALYTICS_ALL, pricing_on, also=also,
            pricing=pricing, priced=priced)

    offset, error = _scan_usage_from(state["offset"], fold)
    if error is None:
        state["offset"] = offset
        state["tail"] = _log_tail_signature(offset)
        _pricing_record_close(priced, pricing)
    return state, offset, error

def _analytics_window_from_days(realm, day_key, until, pricing_on):
    """窗口半 maps = 窗口内的日桶之和；日桶不可用时返回 None。

    先确保 all-time 折叠推进到文件尾：日桶与它同一次扫描推进，窗口半与
    all-time 半因此描述同一段字节（旧实现用 stop_at 保证的同一件事）。

    until 给出时（闭窗口）它必须是本地午夜（调用方已按格点判过，这里再
    校验一次），窗口只取 at < until 的那批日桶：恰好落在 until 上的行归
    until 那天那一桶（桶按 at 严格切分，见 _usage_hour_bucket），桶切不出
    那一刻的行，所以那一刻有整秒行时整条路退回 None（见
    _closed_window_edge_ok），调用方接着整段扫描，结果不变。

    状态冷（从没折过/刚被价表、realm、日志判废/采纳失败）时直接返回 None：
    那条路要先付一次全量重折，窗口请求不背它——调用方退回按日分组的冷扫描
    （同一批行、同一个求和口径，逐字节相同），重折留给 all-time 半与预热器
    （见 _analytics_state_cold）。
    """
    with _analytics_state_lock:
        if _analytics_state_cold(realm, pricing_on):
            return None
        state, offset, error = _analytics_state_ready(realm, pricing_on)
        if error is not None:
            _log("compute_usage_analytics failed: %s" % error)
            state.update({"maps": _new_analytics_maps(), "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "max_at": 0,
                          "hits": [], "hits_overflow": False})
            return None
        if not _days_cover(state, day_key):
            return None
        until_key = None
        if until is not None:
            until_key = _window_day_key_safe(until)
            if until_key is None or not _closed_window_edge_ok(state, until):
                return None
        maps = _new_analytics_maps()
        days = state["days"]
        for key in sorted(days):
            if key < day_key:
                continue
            if until_key is not None and key >= until_key:
                break
            _add_analytics_window_maps(maps, days[key])
    _usage_cache_maybe_save("analytics", offset)
    return maps

def _analytics_window_from_hours(realm, since, until, pricing_on):
    """窗口半 maps = 窗口内的小时桶之和；小时层不可用时返回 None。

    成立条件（缺一不可，任何一条不成立就退回扫描——正确性优先）：
      * 窗口起点落在本地午夜起算的小时格点上（调用方已判过，这里再按桶校验）；
      * until 开放，或 until 不低于折过的最大 at（否则窗口上界会切掉桶里的行），
        或 until 落在同一套小时格点上且直到那一刻没有整秒行（见
        _closed_window_edge_ok）——这时窗口只取 at < until 的那批桶，恰好
        落在 until 上的行由边沿账挡回整段扫描；
      * days_floor 覆盖窗口起点所在的天（更早的天没有桶）；
      * 窗口起点所在的天及其后每一天都有 hours 子表（被剪枝线剪掉、或本地
        午夜落在不存在的小时里而摘掉的那天，都会让窗口整体退回扫描）。

    状态冷（从没折过/刚被价表、realm、日志判废/采纳失败）时直接返回 None：
    那条路要先付一次全量重折，窗口请求不背它——调用方退回按小时分组的冷
    扫描（同一批行、同一个求和口径，逐字节相同），重折留给 all-time 半与
    预热器（见 _analytics_state_cold）。
    """
    with _analytics_state_lock:
        if _analytics_state_cold(realm, pricing_on):
            return None
        state, offset, error = _analytics_state_ready(realm, pricing_on)
        if error is not None:
            _log("compute_usage_analytics failed: %s" % error)
            state.update({"maps": _new_analytics_maps(), "offset": 0, "tail": b"",
                          "days": {}, "days_floor": None, "max_at": 0,
                          "hits": [], "hits_overflow": False})
            return None
        cut_at = None
        if until is not None:
            if until < state["max_at"]:
                # 闭窗口切进桶里：until 必须落在同一套小时格点上、且直到
                # 那一刻没有整秒行，桶才切得出这个窗口。
                if (_window_hour_key_safe(until) is None
                        or not _closed_window_edge_ok(state, until)):
                    return None
                cut_at = int(until)
        day_key = _local_day_key(since)
        if not _days_cover(state, day_key):
            return None
        lo_i = int(since)
        maps = _new_analytics_maps()
        for key in sorted(state["days"]):
            if key < day_key:
                continue
            if cut_at is not None and _day_key_start(key) > cut_at:
                break
            bucket = state["days"][key]
            hours = bucket.get("hours")
            if hours is None:
                return None
            day_at = int(bucket["at"])
            for hour in sorted(hours, key=int):
                sub = hours[hour]
                if int(sub["at"]) != day_at + int(hour) * 3600:
                    return None
                # 格点校验对起点所在那天的每个桶都做（含 at < since 的桶）：
                # 时区偏移不是整小时的夏令时（极少数时区）会让格点整体错开
                # 半小时，错开的桶可能横跨起点、把 at >= since 的行关在里面
                # ——跳过它就会漏行，所以宁可整个窗口退回扫描。
                if (int(sub["at"]) - lo_i) % 3600:
                    return None
                if int(sub["at"]) < lo_i:
                    continue
                if cut_at is not None and int(sub["at"]) >= cut_at:
                    # 闭窗口：until 那一刻归后一桶（桶按 at 严格切分），
                    # 只取 at < until 的桶；那一刻有整秒行时上面已经退回。
                    break
                _add_analytics_window_maps(maps, sub)
    _usage_cache_maybe_save("analytics", offset)
    return maps

def _analytics_window(realm, since, until, stop_at, pricing_on):
    """窗口半 analytics：对齐窗口由日桶/小时桶相加，其余保持整段扫描。

    与 _usage_snapshot_window 同一条规矩，外加一层小时桶：起点是本地午夜、
    终点开放或也是本地午夜的窗口拆得成整天的并集；起点落在整小时的其它窗口
    （自定义区间）拆得成整小时的并集，由 analytics 自己的小时层回答（见
    「小时层」一节）；其余一律保持整段扫描。闭窗口的右边界按「at < until
    的桶」切，那一刻有整秒行时退回扫描（见 _closed_window_edge_ok）。
    """
    day_key = _window_day_key_safe(since)
    until_day = None if until is None else _window_day_key_safe(until)
    if (day_key is not None and _usage_day_buckets_enabled()
            and (until is None or until_day is not None)):
        maps = _analytics_window_from_days(realm, day_key, until, pricing_on)
        if maps is not None:
            return maps
        # 日桶没盖住窗口起点：冷路径现折一份按日分组的窗口半，口径一致。
        return _bind__scan_usage_analytics_window_days(realm, since, until, stop_at,
                                                 pricing_on)
    if _window_hour_aligned(since) and _usage_day_buckets_enabled():
        maps = _analytics_window_from_hours(realm, since, until, pricing_on)
        if maps is not None:
            return maps
        # 小时层没盖住：冷路径现折一份按小时分组的窗口半，口径与小时层一致。
        return _bind__scan_usage_analytics_window_hours(realm, since, until, stop_at,
                                                  pricing_on)
    return _bind__scan_usage_analytics_window(realm, since, until, stop_at=stop_at,
                                        pricing_on=pricing_on)

def _scan_usage_analytics_window(realm, since, until, stop_at=None, pricing_on=None):
    """One pass over the log, folding only the rows inside the window.

    The all-time half is not rebuilt here - it comes from the incremental fold
    - and the read stops where that fold stopped, so both halves of the
    payload describe the same bytes even when a row lands mid-rebuild.

    价表在这里取一次（与 all-time 折叠同一条口径），传给折叠当行级记忆的
    代次：这次窗口扫描里的行可以和 all-time 半共享定价结果。
    """
    pricing = _pricing_inputs(pricing_on)
    maps = _new_analytics_maps()

    def fold(row):
        # Same bounds as /usage and /usage/perf, so the three readers agree on
        # what the selected range contains.
        at = row.get("at", 0)
        if since is not None and at < since:
            return
        if until is not None and at > until:
            return
        _bind__fold_usage_analytics(row, realm, maps, _ANALYTICS_WINDOW, pricing_on,
                              pricing=pricing)

    _, error = _scan_usage_from(
        0, fold, stop_at=stop_at,
        skip=lambda line: _bind__line_outside_window(line, since, until),
        skip_raw=lambda raw: _bind__line_outside_window_bytes(raw, since, until))
    if error is not None:
        _log("compute_usage_analytics failed: %s" % error)
    return maps

def _copy_analytics_models(models):
    """Copy one {model: {...}} bucket; its inner dicts are only ever read."""
    return {mid: dict(entry) for mid, entry in models.items()}

def _copy_analytics_all_time(maps):
    """A private copy of the cached all-time maps.

    The payload build decorates what it is given (finalize writes the
    derived ratios into the stat dicts) and the cached fold keeps growing
    under a concurrent refresh, so the caller gets a copy taken while the
    state lock is held rather than a live view of it.
    """
    out = {"summary": dict(maps["summary"]), "accts": {}, "models": {}, "keys": {}}
    for uid, entry in maps["accts"].items():
        copy = dict(entry)
        copy["all_time"] = dict(entry["all_time"])
        copy["all_models"] = _copy_analytics_models(entry["all_models"])
        out["accts"][uid] = copy
    for m_id, entry in maps["models"].items():
        out["models"][m_id] = {"model": m_id, "all_time": dict(entry["all_time"])}
    for k_id, km in maps["keys"].items():
        copy = dict(km)
        copy["all_time"] = dict(km["all_time"])
        copy["all_models"] = _copy_analytics_models(km["all_models"])
        out["keys"][k_id] = copy
    return out

def _add_analytics_stat(dst, src):
    """Field-wise sum of two _new_analytics_stat() dicts, in place."""
    for field in _USAGE_CACHE_ANALYTICS_NUMBERS:
        dst[field] += src.get(field) or 0

_USAGE_DAY_KEEP_DAYS = 32

_USAGE_HOUR_KEEP_DAYS = 2

_USAGE_DAY_SNAPSHOT_FIELDS = tuple(
    k for k, v in _empty_stats().items()
    if isinstance(v, (int, float)) and not isinstance(v, bool) and k != "started")

def _usage_keep_setting(key):
    """面板设的聚合保留值（没设过 / 读不出来返回 None）。

    环境变量始终优先（现场调、测试里来回切），面板设置只在没有环境变量时
    生效——与 upstream_timeouts() 读 header_timeout_seconds 同一条路子。
    """
    try:
        cfg = ca_settings.usage_config(_accounts_dir())
    except Exception:
        return None
    value = cfg.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value

def _usage_day_keep_days():
    """日桶保留天数，默认 32；WB_USAGE_DAY_KEEP_DAYS 优先，其次面板设置。

    每次调用都读环境变量，理由与 WB_USAGE_CACHE 相同（现场调、测试里来回切）。
    """
    raw = os.environ.get("WB_USAGE_DAY_KEEP_DAYS")
    if raw is not None:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return _USAGE_DAY_KEEP_DAYS
    return _usage_keep_setting("day_keep_days") or _USAGE_DAY_KEEP_DAYS

def _usage_hour_keep_days():
    """小时桶保留天数，默认 2；WB_USAGE_HOUR_KEEP_DAYS 优先，其次由面板的
    「小时层保留」折算（向上取整到整天）。

    两个状态各有一条小时层保留线（snapshot 按天，analytics 按小时），面板只
    暴露一个「小时层保留（小时）」，所以这里跟着它走，免得调了一个另一个不动。
    取值再小也保留一天（max(1, ...)）：小时层至少要能服务「今天的整点窗口」，
    否则等于没建。
    """
    raw = os.environ.get("WB_USAGE_HOUR_KEEP_DAYS")
    if raw is not None:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return _USAGE_HOUR_KEEP_DAYS
    hours = _usage_keep_setting("hour_keep_hours")
    if hours:
        return max(1, (hours + 23) // 24)
    return _USAGE_HOUR_KEEP_DAYS

def _usage_day_buckets_enabled():
    """日桶总开关，默认开；WB_USAGE_DAY_BUCKETS=0 退回逐行扫描口径。

    与 WB_USAGE_CACHE 同样的用法：现场紧急关掉、测试在一个进程里来回切。
    关掉时既不折日桶也不用它们，窗口路径与改动前逐字节一致。小时层挂在
    日桶上（每个日桶里的 hours 子表），所以这个开关一并管住小时层：关掉
    时既不折小时桶，整点窗口也退回逐行口径。
    """
    return os.environ.get("WB_USAGE_DAY_BUCKETS", "1").strip().lower() not in (
        "0", "false", "no", "off")

_USAGE_HOUR_KEEP_HOURS = 48

def _usage_hour_keep_hours():
    """小时子表保留小时数，默认 48；WB_USAGE_HOUR_KEEP_HOURS 优先，其次面板设置。

    每次调用都读环境变量，理由与 WB_USAGE_DAY_KEEP_DAYS 相同（现场调、测试
    里来回切）。
    """
    raw = os.environ.get("WB_USAGE_HOUR_KEEP_HOURS")
    if raw is not None:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return _USAGE_HOUR_KEEP_HOURS
    return _usage_keep_setting("hour_keep_hours") or _USAGE_HOUR_KEEP_HOURS

def _local_day_key(ts):
    """ts 所属的本地日历日，"YYYY-MM-DD"。

    用字符串而不是午夜 epoch 当日桶的键：窗口与日桶的比较就是一次字符串
    比较（ISO 日期天然有序），查询不必再算一遍本地午夜，也不会被夏令时的
    日长变化影响——同一套本地日历日规则在折叠与查询两侧都成立。

    结果按 ts 记忆（见「行级结果记忆」）：一次冷启动里三个视图各扫一遍日志，
    每一行都要问一次日键，第二、第三遍直接取。时区被 tzset() 换过时表整体
    作废；不可哈希的 ts（坏行）不进表，照旧真算、照旧抛同样的异常。
    """
    memo = _row_day_memo
    if _row_memo_tz is not time.tzname:
        _row_memo_tz_changed()
    try:
        hit = memo.get(ts)
    except TypeError:
        return time.strftime("%Y-%m-%d", time.localtime(ts))
    if hit is not None:
        return hit
    key = time.strftime("%Y-%m-%d", time.localtime(ts))
    cap = _ROW_MEMO_MAX
    if cap > 0:
        if len(memo) >= cap:
            # 满了：只收「不比表里最旧那条更旧」的 ts。扫描从头往尾走，表里
            # 留住的因此总是最近的一批行，第二遍走到尾部照样命中。
            oldest = next(iter(memo))
            if _row_memo_at(ts) < _row_memo_at(oldest):
                return key
            memo.pop(oldest, None)
        memo[ts] = key
    return key

def _day_key_start(key):
    """日键 -> 该日的本地午夜 epoch。"""
    lt = time.strptime(key, "%Y-%m-%d")
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))

def _window_day_key(since):
    """窗口起点能由日桶推导时返回它的日键，否则 None。

    只有「起点正好是本地午夜」的窗口才拆得成整天的并集：at >= 本地午夜
    等价于「日键 >= 那天的键」。自定义区间的起点是任意时刻，拆不开——那条
    路径保持整段扫描（正确性优先）。
    """
    if since is None:
        return None
    if _local_midnight(since) != since:
        return None
    return _local_day_key(since)

def _hour_window_key(since):
    """窗口起点能由小时桶推导时返回 (日键, 小时序号)，否则 None。

    只有「起点正好是本地整点」的窗口才拆得成整小时桶的并集：小时桶按
    「离那天本地午夜多少个 3600 秒」切格点（见 _usage_hour_bucket），所以
    起点必须同时满足两条——本地墙上时间落在整点（_local_hour_start 能原样
    还原），并且离本地午夜的距离是 3600 的整数倍。夏令时把日边界挪动、
    或时区按半小时偏移的情形，只要 since 不落在格点上就返回 None（退回
    扫描，正确性优先）。

    整点起点也可能是本地午夜（两者同时成立）：调用方先问日桶，所以这条
    只在「不是午夜」时兜住自定义区间的整点窗口。
    """
    if since is None:
        return None
    if _local_hour_start(since) != since:
        return None
    day_key = _local_day_key(since)
    day_at = _day_key_start(day_key)
    k = int((since - day_at) // 3600)
    if day_at + k * 3600 != since:
        return None
    return day_key, k

def _window_hour_aligned(since):
    """窗口起点是否落在「本地午夜 + k*3600」的小时格点上。

    小时桶的格点是「离那天的本地午夜多少秒」（见 _analytics_hour_bucket），
    所以起点减它所属那天的本地午夜必须是 3600 的整数倍。自定义区间的起点是
    任意分钟时拆不开——那条路径保持整段扫描（正确性优先）；起点正好是本地
    午夜时恒成立（0 是 3600 的整数倍），与 _window_day_key 相容。
    """
    if since is None:
        return False
    return (_local_midnight(since) - since) % 3600 == 0

_CLOSED_WINDOW_HITS_MAX = 256

def _closed_window_hit_record(state, at):
    """行恰好落在整秒上时记一笔（闭窗口走桶求和的边沿账）。

    桶按 at 严格切分（见 _usage_hour_bucket）：闭窗口 [since, until] 与
    「at < until 的那批桶」只差「恰好落在 until 上的行」，所以直到那一刻
    没有整秒行时，桶的和就是窗口的全部（见 _closed_window_edge_ok）。这份
    账只收真正进了桶的那些行（realm/剪枝线与折叠同一套判定），记录点因此
    在 _usage_day_bucket 的过滤之后。

    at 不是有限数（手改日志的 Infinity/NaN）时整秒判定不成立就跳过——
    `at // 1` 对这些值不抛异常，不把一次折叠打断在这里。
    """
    if at != at // 1:
        return
    hits = state["hits"]
    if len(hits) >= _CLOSED_WINDOW_HITS_MAX:
        state["hits_overflow"] = True
        return
    hits.append(int(at))

def _closed_window_edge_ok(state, until):
    """闭窗口的右边界能否由存量桶回答：直到 until 为止没有行落在整秒上。

    直到那一刻没有整秒行时，「[since, until] 的行」与「at < until 的桶」是
    同一批（桶按 at 严格切分，恰好落在 until 上的行归后一桶）；真有一行
    恰好落在 until 上时桶切不出它，只能退回整段扫描。账记满（见
    _closed_window_hit_record）同样退回。
    """
    if state["hits_overflow"]:
        return False
    return until not in state["hits"]

def _window_day_key_safe(ts):
    """_window_day_key 的取值安全版：取值离谱时返回 None。

    手写的极大 since/until（例如 6e18）会让 _local_midnight 里的
    time.localtime 抛 OSError——那只是「这个窗口服务不了」的一种，按退回
    整段扫描处理，不该把端点打成 500（与 _series_window_day_key 同一个用意）。
    """
    try:
        return _window_day_key(ts)
    except (OSError, OverflowError, ValueError):
        return None

def _window_hour_key_safe(ts):
    """_hour_window_key 的取值安全版：取值离谱时返回 None（同上）。"""
    try:
        return _hour_window_key(ts)
    except (OSError, OverflowError, ValueError):
        return None

def _new_window_snapshot_bucket(at):
    """一份带格点 at 的窗口半快照桶（日桶与小时桶共用这个形状）。

    started 不参与求和（见 _add_usage_snapshot），形状保留只是让校验与
    all-time 半共用同一套 _usage_cache_snapshot_ok。at 是这个桶的本地格点
    （日的午夜 / 小时的整点）epoch：小时桶按它切 3600 的格点，求和侧按它
    做格点校验——与时间序列的桶同一套做法（_new_series_bucket）。
    """
    bucket = _empty_stats()
    bucket["at"] = at
    return bucket

def _day_snapshot_bucket(key, day_start):
    """一天一份的窗口半快照桶；形状与 _empty_stats() 一致。"""
    return _new_window_snapshot_bucket(day_start)

def _day_analytics_bucket(key, day_start):
    """一天一份的窗口形状 analytics maps（带 at 与小时子表，见「小时层」一节）。

    at 是那天的本地午夜：小时子表按「离本地午夜多少秒」切，行的归属因此
    不依赖折叠时刻（迟写/补写的行落回它时间戳所属的那天那小时）。
    """
    bucket = _new_analytics_maps()
    bucket["at"] = day_start
    bucket["hours"] = {}
    return bucket

def _new_analytics_hour_bucket(at):
    """一小时一份的窗口形状 analytics maps（带 at；见「小时层」一节）。"""
    bucket = _new_analytics_maps()
    bucket["at"] = at
    return bucket

def _analytics_hour_bucket(day, at):
    """这一行该折进的小时桶（day 桶的 hours 子表）；不该折时返回 None。

    小时键是「离那天的本地午夜多少秒」的整小时数（字符串，与 JSON 往返后的
    形状一致，同时间序列的小时子表）。本地午夜落在不存在的小时里（夏令时在
    午夜切换的极少数时区）时这一行放不进格点：把整天的 hours 摘掉，让覆盖
    这一天的小时窗口整体退回扫描（日桶本身照常，不受影响）。
    """
    if day is None:
        return None
    hours = day.get("hours")
    if hours is None:
        return None
    day_at = int(day["at"])
    if at < day_at:
        day.pop("hours", None)
        return None
    hour = str(int((at - day_at) // 3600))
    sub = hours.get(hour)
    if sub is None:
        sub = hours[hour] = _new_analytics_hour_bucket(day_at + int(hour) * 3600)
    return sub

def _day_series_bucket(key, day_start):
    """一天一份的时间序列桶（带小时子表，见 _fold_usage_series）。"""
    bucket = _new_series_bucket(day_start)
    bucket["hours"] = {}
    return bucket

def _usage_day_bucket(state, row, r, factory):
    """这一行该折进哪个日桶；必要时新建（顺带剪枝），不该折时返回 None。

    行的归属只看它自己的 at：补写/迟到的行必须落进它时间戳所属的那天。
    realm 不匹配的行折叠本来就会跳过，这里也不为它建桶；总开关关掉时连
    日桶都不折（窗口路径也不会用它们，见 _usage_day_buckets_enabled）。
    """
    if not _usage_day_buckets_enabled():
        return None
    if r and not row_matches_realm(row, r):
        return None
    at = row.get("at") or 0
    key = _local_day_key(at)
    floor = state.get("days_floor")
    if floor is not None and key < floor:
        # 剪枝线以下的天：那些桶已经被丢掉，而且任何可服务的窗口都从
        # days_floor 那天起，这一行不在其中——跳过不影响窗口。
        return None
    _closed_window_hit_record(state, at)
    days = state["days"]
    bucket = days.get(key)
    if bucket is None:
        bucket = days[key] = factory(key, _day_key_start(key))
        _prune_day_buckets(state, days, key)
    return bucket

def _prune_day_buckets(state, days, newest_key):
    """丢掉任何窗口都够不到的旧日桶，并把 days_floor 抬到剪枝线。

    days_floor 的语义是「这份状态从哪天起是完整的」：它就是剪枝线（最新那天
    往前 _usage_day_keep_days() 天），没剪过时第一次折到新的一天也会把它记
    下来——比这条线更早的窗口一律退回整段扫描（时钟大幅回拨、日志里有远古
    补写行这类情况），宁可多扫一次，不能少算一天。

    analytics 状态还挂着一条更短的小时子表保留线（state["hours_keep"]）：
    小时层只为近期的自定义窗口服务，只摘旧天的 "hours" 子表，日桶本身照常
    留满保留天数。被摘掉的天由查询侧按「这一天还有没有 hours」自己表达
    （见 _analytics_window_from_hours），所以这里不用另存一个 floor。
    """
    horizon = _local_day_key(_day_key_start(newest_key)
                             - _usage_day_keep_days() * 86400)
    for old in [k for k in days if k < horizon]:
        del days[old]
    floor = state.get("days_floor")
    if floor is None or floor < horizon:
        state["days_floor"] = horizon
    # 带小时层的状态（snapshot，见 _usage_hour_bucket）顺带剪小时表：小时层
    # 的保留期比日桶短，剪枝线要跟着一起抬。analytics / series 的状态没有
    # hours_floor_at 这个键，不会被这条带到。
    if "hours_floor_at" in state:
        _prune_hour_buckets(state, days, newest_key)
    # analytics 状态还挂着一条更短的小时子表保留线（state["hours_keep"]）：
    # 小时层只为近期的自定义窗口服务，只摘旧天的 "hours" 子表，日桶本身照常
    # 留满保留天数。
    if state.get("hours_keep"):
        hour_horizon = _local_day_key(_day_key_start(newest_key)
                                      - _usage_hour_keep_hours() * 3600)
        for key, bucket in days.items():
            if key < hour_horizon:
                bucket.pop("hours", None)

def _days_cover(state, day_key):
    """这份状态的日桶能否服务以 day_key 为起点的窗口。

    days_floor 是剪枝线：比它早的窗口可能少了被剪掉的天，只能退回扫描。
    它最早也要折到第一个新的一天才会记下（没折过就是 None，此时谁都不服务
    ——调用方总是先折到文件尾，所以实际不会遇到）。
    """
    floor = state.get("days_floor")
    return floor is not None and day_key >= floor

def _usage_hour_bucket(state, row, day):
    """这一行该折进哪个小时桶；不该折时返回 None。

    小时桶挂在日桶里（`hours` 子表），键是「离当天本地午夜的 3600 秒个数」
    的字符串——与时间序列的小时子桶同一套格点规则（见 _fold_usage_series）：
    桶的 at = 日桶 at + 序号*3600，所以每个桶恰好覆盖一个整点区间，跨桶
    求和不会重复也不会漏。

    at 早于日桶 at 的行（极少数时区在本地午夜切换夏令时，午夜那一刻不存在）
    放不进格点：整张小时表摘掉并留痕（`hours` 记为 None），求和侧看到没有表
    就退回按小时分组的冷路径（日桶本身照常，日窗口不受影响）。留痕是为了
    挡住「摘掉之后又来了这一天的行、把表重建出来」——重建的表缺了被摘掉的
    那批行，一旦被求和侧选中就是少算。

    hours_floor_at 是小时层的剪枝线：比它早的天不再折小时表。迟写/补写的
    行可能落回很久以前那天（日桶还留着），但那张表早被剪掉，重新建起来
    只会得到一张缺了其余小时的表——求和侧一旦用它就会少算，所以这里直接
    不折（求和侧另有 _hours_cover 兜底）。
    """
    floor = state.get("hours_floor_at")
    if floor is None or day["at"] < floor:
        return None
    at = row.get("at") or 0
    day_at = day["at"]
    hours = day.get("hours")
    if hours is None and "hours" in day:
        # 这天的小时表被摘过（午夜兜底）：不再重建，见 docstring。
        return None
    if at < day_at:
        day["hours"] = None
        return None
    if hours is None:
        hours = day["hours"] = {}
    hour = str(int((at - day_at) // 3600))
    sub = hours.get(hour)
    if sub is None:
        sub = hours[hour] = _new_window_snapshot_bucket(day_at + int(hour) * 3600)
    return sub

def _prune_hour_buckets(state, days, newest_key):
    """丢掉保留窗口之外的日桶里的小时表，并把 hours_floor_at 抬到剪枝线。

    小时层比日桶短命：它只服务最近几天的整点窗口（见 _USAGE_HOUR_KEEP_DAYS）。
    剪枝按天走（与 _prune_day_buckets 同一套算术），所以实际保留在
    keep_days 与 keep_days+1 天之间。hours_floor_at 的语义与 days_floor 相同
    ——「这份状态的小时层从哪个时刻起是完整的」——更早的整点窗口一律退回
    冷路径，宁可多扫一次，不能少算一个桶。
    """
    horizon_at = _day_key_start(newest_key) - _usage_hour_keep_days() * 86400
    horizon = _local_day_key(horizon_at)
    for key in list(days):
        if key < horizon and "hours" in days[key]:
            # 与午夜兜底同一个留痕：表置 None 而不是删键。剪枝线（下面那条）
            # 本来也挡着重建，但留痕让「这张表不可用」成为桶自己的事实，
            # 求和侧与折叠侧不必再依赖两条线的一致性。
            days[key]["hours"] = None
    floor = state.get("hours_floor_at")
    if floor is None or floor < horizon_at:
        state["hours_floor_at"] = horizon_at

def _hours_cover(state, since):
    """这份状态的小时层能否服务起点为 `since` 的窗口。

    hours_floor_at 是剪枝线（见 _prune_hour_buckets）：比它早的窗口可能少了
    被剪掉的小时表，只能退回扫描。它最早也要折到第一个新的一天才会记下
    （没折过就是 None，此时谁都不服务——调用方总是先折到文件尾）。
    """
    floor = state.get("hours_floor_at")
    return floor is not None and since >= floor

def _hours_floor_on_adopt(days, stored):
    """采用 checkpoint 时的小时层剪枝线：取「文件里的」与「按最新一天现算」
    的较晚者。

    较晚者一定安全：剪枝线只会往前抬，抬高了最多是少服务几天（那些窗口
    退回冷路径），永远不会服务一张被剪过的表。两条都挡住同一条路——拿
    不完整的表当完整（那是这个层唯一会算错数的方向）：文件里那条可能是
    别的保留天数下写的，现算这条跟着当前 WB_USAGE_HOUR_KEEP_DAYS 走。
    """
    recomputed = None
    if days:
        recomputed = _day_key_start(max(days)) - _usage_hour_keep_days() * 86400
    if stored is None:
        return recomputed
    if recomputed is None:
        return stored
    return max(stored, recomputed)

def _add_usage_bucket(dst_map, key, src):
    """把一个 by_model* 桶并入同键的桶（不存在就整只拷进来）。"""
    dst = dst_map.get(key)
    if dst is None:
        dst_map[key] = _copy_usage_bucket(src)
        return
    for field in _USAGE_CACHE_BUCKET_NUMBERS:
        dst[field] += src.get(field) or 0
    for acct, count in src["accounts"].items():
        dst["accounts"][acct] = dst["accounts"].get(acct, 0) + count

def _add_usage_snapshot(dst, src):
    """把一份窗口半快照按字段并入另一份（日桶求和用）。

    逐字段相加，不是重折：日桶是不可变的聚合，窗口只是它们的和。started
    是每份快照各自的创建时刻，不是累计量，跳过。
    """
    for field in _USAGE_DAY_SNAPSHOT_FIELDS:
        dst[field] += src.get(field) or 0
    for mid, bucket in src["by_model"].items():
        _add_usage_bucket(dst["by_model"], mid, bucket)
    for mid, realms in src["by_model_realm"].items():
        for rr, bucket in realms.items():
            _add_usage_bucket(dst["by_model_realm"].setdefault(mid, {}), rr, bucket)
    for mid, realms in src["by_model_acct"].items():
        for rr, accts in realms.items():
            tgt = dst["by_model_acct"].setdefault(mid, {}).setdefault(rr, {})
            for acct, bucket in accts.items():
                _add_usage_bucket(tgt, acct, bucket)

def _add_analytics_models(dst, src):
    """把一份 {model: {requests, tokens, reasoning}} 并入另一份。"""
    for mid, stat in src.items():
        tgt = dst.get(mid)
        if tgt is None:
            dst[mid] = dict(stat)
            continue
        for field in ("requests", "tokens", "reasoning"):
            tgt[field] += stat.get(field) or 0

def _add_analytics_window_maps(dst, src):
    """把一份窗口形状的 analytics maps 并入另一份（日桶求和用）。

    日桶本身就是 _ANALYTICS_WINDOW 那一半的形状（window / window_models），
    所以这里只动这两个键；realms / last_at 照并，虽然 _merge_analytics_halves
    最终取的是 all-time 侧的值。
    """
    _add_analytics_stat(dst["summary"], src["summary"])
    for uid, entry in src["accts"].items():
        tgt = dst["accts"].get(uid)
        if tgt is None:
            tgt = dst["accts"][uid] = {
                "uid": uid, "nickname": uid, "realm": entry["realm"],
                "domain": "", "window": _new_analytics_stat(),
                "window_models": {}}
        _add_analytics_stat(tgt["window"], entry["window"])
        _add_analytics_models(tgt["window_models"], entry["window_models"])
    for mid, entry in src["models"].items():
        tgt = dst["models"].get(mid)
        if tgt is None:
            tgt = dst["models"][mid] = {"model": mid,
                                        "window": _new_analytics_stat()}
        _add_analytics_stat(tgt["window"], entry["window"])
    for kid, entry in src["keys"].items():
        tgt = dst["keys"].get(kid)
        if tgt is None:
            tgt = dst["keys"][kid] = {
                "key": kid, "window": _new_analytics_stat(),
                "window_models": {}, "realms": {}, "last_at": 0}
        _add_analytics_stat(tgt["window"], entry["window"])
        _add_analytics_models(tgt["window_models"], entry["window_models"])
        for rr, count in entry["realms"].items():
            tgt["realms"][rr] = tgt["realms"].get(rr, 0) + count
        if entry["last_at"] > tgt["last_at"]:
            tgt["last_at"] = entry["last_at"]

def _copy_analytics_window_maps(maps):
    """一份窗口形状 maps 的深拷贝（落盘用，形状同 _new_analytics_maps()）。

    日桶/小时桶还会多带 at（两者都有）与 hours 子表（日桶）：照原样拷贝、
    键序保持折叠时的插入顺序——checkpoint 不排序，加载回来要与冷启动逐字节
    一致（见 _usage_cache_write）。
    """
    out = {"summary": dict(maps["summary"]), "accts": {}, "models": {}, "keys": {}}
    for uid, entry in maps["accts"].items():
        copy = dict(entry)
        copy["window"] = dict(entry["window"])
        copy["window_models"] = _copy_analytics_models(entry["window_models"])
        out["accts"][uid] = copy
    for mid, entry in maps["models"].items():
        out["models"][mid] = {"model": mid, "window": dict(entry["window"])}
    for kid, km in maps["keys"].items():
        copy = dict(km)
        copy["window"] = dict(km["window"])
        copy["window_models"] = _copy_analytics_models(km["window_models"])
        copy["realms"] = dict(km["realms"])
        out["keys"][kid] = copy
    if "at" in maps:
        out["at"] = maps["at"]
    hours = maps.get("hours")
    if hours is not None:
        out["hours"] = {h: _copy_analytics_window_maps(sub)
                        for h, sub in hours.items()}
    return out

def _scan_usage_snapshot_window_days(r, since, until, pricing_on=None):
    """窗口半的冷路径：整段扫一遍，先按日分桶再相加。

    日桶状态不可用（还没折过、被剪枝、折叠出错）时走这里。结果必须与日桶
    状态给出的窗口半逐字节一致：窗口起点是本地午夜（until 给出时终点也是
    本地午夜），两边装的是同一批行、同一个「按日分组」的求和口径，只是桶
    一个现折、一个存量。

    状态冷时它是窗口请求的直接答案（不折状态，重折留给 all-time 视图与
    预热器，见 _usage_snap_state_cold）；其余情形它紧跟一次 all-time 折叠
    （_usage_snapshot_window_from_days 先折到文件尾才发现日桶不够用），
    行级记忆几乎全中：同一批行刚在 all-time 半算过价与日键。窗口外的行由
    skip 挡在解析之前，这条路只付窗口内那批行。价表照样在本函数开头取一次。
    """
    pricing = _pricing_inputs(pricing_on)
    days = {}

    def fold(row):
        at = row.get("at") or 0
        if since and at < since:
            return
        if until and at > until:
            return
        key = _local_day_key(at)
        bucket = days.get(key)
        if bucket is None:
            bucket = days[key] = _empty_stats()
        _bind__fold_usage_snapshot(row, bucket, r, None, None, pricing_on,
                             pricing=pricing)

    _, error = _scan_usage_from(
        0, fold,
        skip=lambda line: _bind__line_outside_window(line, since or None,
                                               until or None),
        skip_raw=lambda raw: _bind__line_outside_window_bytes(raw, since or None,
                                                        until or None))
    if error is not None:
        _log(f"usage snapshot read failed: {error}")
    snap = _empty_stats()
    for key in sorted(days):
        _add_usage_snapshot(snap, days[key])
    return snap

def _scan_usage_snapshot_window_hours(r, since, until, pricing_on=None):
    """窗口半的冷路径：整段扫一遍，先按小时分桶再相加。

    小时层状态不可用（还没折过、被剪枝、折叠出错、那天的格点不成立）时走
    这里。结果必须与小时桶状态给出的窗口半逐字节一致：窗口起点是本地整点
    （until 给出时终点也落在同一套格点上），两边装的是同一批行、同一个
    「按（日，小时）分组」的求和口径，只是桶一个现折、一个存量。

    分组与 _usage_hour_bucket 同一套算术（日键 + 离午夜多少个 3600 秒），
    但这里对 at 早于本地午夜的行照折不误（键可以是负的）：状态侧那种行会
    把整张小时表摘掉、窗口退回这条路径，所以这条路径必须把它们算进去。
    排序按 (日键, 序号) 数值序，与状态侧的遍历顺序一致。

    价表在本函数开头取一次，行级记忆（见「行级结果记忆」）跟着这一批扫描
    走：同一批行通常刚在 all-time 半算过价与日键，这里几乎全中。
    """
    pricing = _pricing_inputs(pricing_on)
    hours = {}
    day_ats = {}

    def fold(row):
        at = row.get("at") or 0
        if since and at < since:
            return
        if until and at > until:
            return
        key = _local_day_key(at)
        day_at = day_ats.get(key)
        if day_at is None:
            day_at = day_ats[key] = _day_key_start(key)
        hour = int((at - day_at) // 3600)
        bucket = hours.get((key, hour))
        if bucket is None:
            bucket = hours[(key, hour)] = _empty_stats()
        _bind__fold_usage_snapshot(row, bucket, r, None, None, pricing_on,
                             pricing=pricing)

    _, error = _scan_usage_from(
        0, fold,
        skip=lambda line: _bind__line_outside_window(line, since or None,
                                               until or None),
        skip_raw=lambda raw: _bind__line_outside_window_bytes(raw, since or None,
                                                        until or None))
    if error is not None:
        _log(f"usage snapshot read failed: {error}")
    snap = _empty_stats()
    for key in sorted(hours):
        _add_usage_snapshot(snap, hours[key])
    return snap

def _scan_usage_analytics_window_days(realm, since, until, stop_at=None,
                                      pricing_on=None):
    """窗口半 analytics 的冷路径：按日分桶再相加（见 snapshot 版）。"""
    pricing = _pricing_inputs(pricing_on)
    days = {}

    def fold(row):
        at = row.get("at") or 0
        if since is not None and at < since:
            return
        if until is not None and at > until:
            return
        key = _local_day_key(at)
        maps = days.get(key)
        if maps is None:
            maps = days[key] = _new_analytics_maps()
        _bind__fold_usage_analytics(row, realm, maps, _ANALYTICS_WINDOW, pricing_on,
                              pricing=pricing)

    _, error = _scan_usage_from(
        0, fold, stop_at=stop_at,
        skip=lambda line: _bind__line_outside_window(line, since, until),
        skip_raw=lambda raw: _bind__line_outside_window_bytes(raw, since, until))
    if error is not None:
        _log("compute_usage_analytics failed: %s" % error)
    out = _new_analytics_maps()
    for key in sorted(days):
        _add_analytics_window_maps(out, days[key])
    return out

def _scan_usage_analytics_window_hours(realm, since, until, stop_at=None,
                                       pricing_on=None):
    """窗口半 analytics 的冷路径（起点整小时）：按小时分桶再相加。

    小时层不可用（还没折过、被剪枝、折叠出错、until 切在桶中间）时走这里。
    结果必须与小时桶状态给出的窗口半逐字节一致：两边装的是同一批行、同一个
    「按小时分组」的求和口径，只是桶一个现折、一个存量。

    分桶与折叠侧同一条规则（离那天的本地午夜多少秒）；本地午夜落在不存在
    的小时里时这一天的小时键会变成负数，求和照样把它算进去（分组只是浮点
    结合顺序的载体），所以这条冷路径不依赖格点是否成立。

    价表在本函数开头取一次，行级记忆（见「行级结果记忆」）跟着这一批扫描走。
    """
    pricing = _pricing_inputs(pricing_on)
    days = {}

    def fold(row):
        at = row.get("at") or 0
        if since is not None and at < since:
            return
        if until is not None and at > until:
            return
        key = _local_day_key(at)
        day = days.get(key)
        if day is None:
            day = days[key] = (_day_key_start(key), {})
        day_at, hours = day
        hour = str(int((at - day_at) // 3600))
        maps = hours.get(hour)
        if maps is None:
            maps = hours[hour] = _new_analytics_maps()
        _bind__fold_usage_analytics(row, realm, maps, _ANALYTICS_WINDOW, pricing_on,
                              pricing=pricing)

    _, error = _scan_usage_from(
        0, fold, stop_at=stop_at,
        skip=lambda line: _bind__line_outside_window(line, since, until),
        skip_raw=lambda raw: _bind__line_outside_window_bytes(raw, since, until))
    if error is not None:
        _log("compute_usage_analytics failed: %s" % error)
    out = _new_analytics_maps()
    for key in sorted(days):
        _day_at, hours = days[key]
        for hour in sorted(hours, key=int):
            _add_analytics_window_maps(out, hours[hour])
    return out

_series_state = {}

_series_state_lock = threading.Lock()

_SERIES_CREDITS_KEEP = 50

_SERIES_MINUTE_WINDOW = 6 * 3600

_SERIES_MINUTE_RING_CAP = 720

def _new_series_bucket(at):
    """一个时间序列桶；键序与 _usage_timeseries_uncached 的输出逐字一致。"""
    return {"at": at, "requests": 0, "errors": 0, "prompt_tokens": 0,
            "completion_tokens": 0, "reasoning_tokens": 0, "cached_tokens": 0,
            "total_tokens": 0, "credit": 0.0}

def _feed_series_bucket(bucket, row):
    """一行折进一个序列桶（日桶或小时桶）。

    口径与 _usage_timeseries_uncached 的折叠逐条一致：completed 计 requests
    与令牌，其它结果（含客户端中止）计 errors；credit 只要不是客户端中止就
    累加。
    """
    outcome = row_outcome(row)
    if outcome == "completed":
        bucket["requests"] += 1
        for field in ("prompt_tokens", "completion_tokens", "reasoning_tokens",
                      "cached_tokens", "total_tokens"):
            bucket[field] += (row.get(field) or 0)
    else:
        bucket["errors"] += 1
    if outcome != "client_aborted":
        bucket["credit"] += (row.get("credit") or 0)

def _series_credit_entry(at, row):
    """一条计费行的载荷：整段扫描与增量缓冲共用的字段表。

    两边的条目会出现在同一个响应的 credits 数组里，键序也是响应字节的
    一部分，所以只能有一份定义。
    """
    return {"at": at, "iso": row.get("iso") or "",
            "model": row.get("model") or "",
            "account": row.get("account") or "",
            "credit": row.get("credit") or 0,
            "total_tokens": row.get("total_tokens") or 0}

def _series_credit_push(credits, row, at):
    """把一条带 credit 的行放进「最近 50 条」缓冲。

    整段扫描返回的 credits 是窗口内按 at 倒序的前 50 条；缓冲里始终留着
    最新的一批（至少 50 条，涨到 100 条时裁回 50），于是任何后缀窗口
    （today/week/month 都是）的前 50 条都在这批里——比缓冲最旧一条还旧的
    行不可能是窗口的前 50 条。at 相同时两边都是稳定排序，顺序（日志顺序）
    一致。
    """
    credits.append(_bind__series_credit_entry(at, row))
    if len(credits) > _SERIES_CREDITS_KEEP * 2:
        credits.sort(key=lambda item: item.get("at") or 0, reverse=True)
        del credits[_SERIES_CREDITS_KEEP:]

def _series_minute_key(at):
    """行 -> 它所属的分钟桶键：epoch 分钟（向下取整）。

    键用 epoch 分钟而不是「离本地午夜多少秒」：分钟窗口的起点是任意分钟格点
    （自定义区间的 since），不锚在本地午夜上，所以桶的格点也取绝对分钟；
    这样跨午夜、跨小时都是同一张表，切片不必按天分组。
    """
    return int(at // 60)

def _fold_usage_series_minute(state, row, at):
    """一行折进分钟环（与日/小时桶同一 realm 过滤、同一折叠口径）。

    保留线以下的桶不建（建了也会被下一次剪枝丢掉）：窗口要服务得上的行都在
    max_at - 6h 之上，更早的行折进来只是白建一个马上被剪的桶。
    """
    key = _series_minute_key(at)
    if key * 60 < state["max_at"] - _SERIES_MINUTE_WINDOW:
        return
    minutes = state["minutes"]
    bucket = minutes.get(key)
    if bucket is None:
        bucket = minutes[key] = _new_series_bucket(key * 60)
        if len(minutes) > _SERIES_MINUTE_RING_CAP:
            _prune_series_minutes(state)
    _feed_series_bucket(bucket, row)

def _prune_series_minutes(state):
    """丢掉保留线（max_at - 6h）以下的分钟桶。

    只按 max_at 剪，不跟日桶的 32 天剪枝线：分钟环的覆盖范围就是它自己的
    保留窗口，与日桶保留多少天无关。判定与 _fold_usage_series_minute 的
    跳过条件同一条（桶的 at 严格小于保留线），两边不会出现「建的桶马上被剪」
    或「剪了还需要的桶」。
    """
    horizon = state["max_at"] - _SERIES_MINUTE_WINDOW
    minutes = state["minutes"]
    for key in [k for k in minutes if k * 60 < horizon]:
        del minutes[key]

def _fold_usage_series(row, r, state):
    """一行折进时间序列状态：日桶 + 小时桶 + 分钟环 + credit 缓冲。"""
    at = row.get("at") or 0
    if at > state["max_at"]:
        # 折过的最大 at：窗口上界（hi=now）只要不低于它，存量桶就都在窗口内。
        # 越界的行（时钟回拨/补写）会让它偏大，那只是更保守，方向安全。
        state["max_at"] = at
    bucket = _usage_day_bucket(state, row, r, _day_series_bucket)
    if bucket is None:
        return
    _feed_series_bucket(bucket, row)
    # 分钟环放在小时桶的午夜兜底之前：兜底会 return（那一天的 hours 摘掉），
    # 而分钟环与日/小时格点无关，漏折一行就会让它的覆盖出现空洞。
    _fold_usage_series_minute(state, row, at)
    if at < bucket["at"]:
        # 本地午夜落在不存在的小时里（极少数时区的夏令时正好在午夜切换）：
        # 这一天的行放不进小时格点，把 hours 摘掉让切片对这一天整体退回扫描
        # （日桶本身照常，step=86400 的切片不受影响）。
        bucket.pop("hours", None)
        return
    # 小时子桶按「离那天的本地午夜多少秒」切：窗口起点是本地午夜时，窗口
    # 序列的桶序号 k = 天序号*24 + 小时序号（夏令时不在日边界上时也一样，
    # 因为两边都是纯 epoch 算术；日边界被夏令时挪动的情形由 _series_slice
    # 的格点校验挡住）。键写成字符串，与 JSON 往返后的形状一致。
    hour = str(int((at - bucket["at"]) // 3600))
    sub = bucket["hours"].get(hour)
    if sub is None:
        sub = bucket["hours"][hour] = _new_series_bucket(
            bucket["at"] + int(hour) * 3600)
    _feed_series_bucket(sub, row)
    if (row.get("credit") or 0) > 0:
        _series_credit_push(state["credits"], row, at)

def _usage_series_state_ready(r):
    """把 `r` 的时间序列状态推进到文件尾；返回 (state, offset, error)。

    调用方必须已持有 _series_state_lock。时间序列折叠不算价，所以状态只带
    realm 指纹（行没有 realm 字段时 row_realm() 会读它）。

    状态里的 `minutes_from` 是分钟环的完整线：从零折起（含 refold）时它是
    None（环对整份日志完整）；采用了一份没有分钟环的旧 checkpoint 时，环只
    对采用点之后折进来的行完整，那条线就是采用时的 max_at（见
    _usage_cache_adopt_series）。
    """
    state = _series_state.get(r)
    if state is None:
        state = _series_state[r] = {
            "days": {}, "days_floor": None, "max_at": 0, "credits": [],
            "minutes": {}, "minutes_from": None,
            "hits": [], "hits_overflow": False,
            "offset": 0, "key": None, "realm": None, "tail": b""}
    realm = _realm_inputs()
    log_key = _usage_log_key()
    if state["key"] is None:
        # 全新状态（进程刚起来）：先问 checkpoint，问不到才从零折起。
        if not _usage_cache_adopt_series(r, state, log_key, realm):
            state.update({"days": {}, "days_floor": None, "max_at": 0,
                          "credits": [], "minutes": {}, "minutes_from": None,
                          "hits": [], "hits_overflow": False,
                          "offset": 0, "tail": b""})
    elif state["realm"] != realm or not _log_resume_ok(state, log_key):
        state.update({"days": {}, "days_floor": None, "max_at": 0,
                      "credits": [], "minutes": {}, "minutes_from": None,
                      "hits": [], "hits_overflow": False,
                      "offset": 0, "tail": b""})
    state.update({"realm": realm, "key": log_key})
    offset, error = _scan_usage_from(
        state["offset"], lambda row: _fold_usage_series(row, r, state))
    if error is None:
        state["offset"] = offset
        state["tail"] = _log_tail_signature(offset)
        # 折叠途中的剪枝是按上限触发的，收尾再剪一次，落盘的环就是保留窗口
        # 以内的那一批（状态不折时这里也不花时间：环大小 <= 上限）。
        _prune_series_minutes(state)
    return state, offset, error

def _series_output_bucket(bucket):
    """存量桶 -> 输出桶（键序固定；日桶的 hours 子表不进输出）。"""
    return {"at": bucket["at"], "requests": bucket["requests"],
            "errors": bucket["errors"], "prompt_tokens": bucket["prompt_tokens"],
            "completion_tokens": bucket["completion_tokens"],
            "reasoning_tokens": bucket["reasoning_tokens"],
            "cached_tokens": bucket["cached_tokens"],
            "total_tokens": bucket["total_tokens"], "credit": bucket["credit"]}

def _series_minute_grid_ok(lo):
    """窗口起点能否落在分钟环的格点上：lo 必须是 60 的整数倍。

    整段扫描的桶边界是 lo + k*60，存量分钟桶的边界是 epoch 分钟的整数倍；
    两组边界一一对应（可以整桶取用）当且仅当 lo 自己落在格点上。面板的
    datetime-local 输入给的就是整分钟（fromLocalInputValue 只到分钟），
    手写的带小数的 since 一律退回整段扫描。
    """
    return int(lo) == lo and int(lo) % 60 == 0

def _series_window_day_key(lo):
    """窗口起点 lo 的本地日键；取值超出平台 epoch 范围时返回 None。

    _local_day_key 走 time.localtime，手写的极大 since（例如 6e18）会让它抛
    OSError——那只是「这个窗口服务不了」的一种，按退回整段扫描处理，不该把
    端点打成 500。分钟切片拿这个键做 days_floor 覆盖判断，拿不到就退回扫描。
    """
    try:
        return _local_day_key(lo)
    except (OSError, OverflowError, ValueError):
        return None

def _series_closed_cut_ok(state, lo_i, hi, step):
    """闭窗口的右边界能否由存量桶回答：hi 落在桶格点上，且直到它没有整秒行。

    桶按 at 严格切分（日/小时桶锚在本地午夜，分钟环锚在 epoch 分钟），所以
    hi 落在与桶同一条格点上时，「[lo, hi] 的行」与「at < hi 的桶」只差
    「恰好落在 hi 上的行」；那一刻有整秒行时桶切不出它，只能退回整段扫描
    （见 _closed_window_edge_ok）。取值离谱的 hi（手写 URL）按不成立处理，
    退回整段扫描——与 _series_window_day_key 的取值保护同一个用意。
    """
    if not _closed_window_edge_ok(state, hi):
        return False
    if step == 60:
        try:
            return _series_minute_grid_ok(hi)
        except (OverflowError, ValueError):
            return False
    try:
        hi_i = int(hi)
    except (OverflowError, ValueError):
        return False
    if hi_i != hi:
        return False
    return (hi_i - lo_i) % step == 0

def _series_slice_minutes(state, realm, lo, hi, day_key):
    """分钟环的切片；不满足对齐/覆盖条件时返回 None（退回整段扫描）。

    成立条件（缺一不可，任何一条不成立就退回整段扫描——正确性优先）：
      * 窗口起点是分钟格点（见 _series_minute_grid_ok）；
      * hi 不低于折过的最大 at：否则窗口上界会切进桶里，而桶是聚合值，
        切不出一半来（与日/小时切片同一条）。hi 切进数据里（闭窗口）时
        还要过闭窗口闸门（见 _series_closed_cut_ok）：hi 落在分钟格点上、
        且直到那一刻没有整秒行，才按「at < hi 的桶」切，恰好落在 hi 上的
        行由边沿账挡回整段扫描；
      * 窗口起点不早于 max_at - 6h：环的保留线，更早的窗口环里没有桶；
      * 窗口起点晚于 minutes_from：环只从那条线之后才完整（采用过没有
        分钟环的旧 checkpoint 时才有这条线，见 _usage_series_state_ready）；
      * 每个桶的 at 落在键*60 上且不晚于 max_at（形状校验之外的防御，
        与 _series_slice 对小时子桶的格点校验同一个用意）。
    输出桶与整段扫描逐条相同（同一批行、同一个网格、同一个累加口径），
    credits 与日/小时切片共用下面同一段选择。
    """
    minutes = state.get("minutes")
    if not minutes:
        # 空环（或状态里没有环）：这一份状态没有任何行落在保留窗口里。空环
        # 答不出窗口里的行，也不能把窗口静默答成空序列——退回整段扫描，
        # 由扫描给出真值（正确的空序列也由它给）。
        return None
    lo_i = int(lo)
    cut = False
    if hi < state["max_at"]:
        # 上界切进环里：闭窗口闸门不成立就退回整段扫描（结果不变）。
        if not _series_closed_cut_ok(state, lo_i, hi, 60):
            return None
        cut = True
    if not _series_minute_grid_ok(lo):
        return None
    if lo_i < state["max_at"] - _SERIES_MINUTE_WINDOW:
        return None
    minutes_from = state.get("minutes_from")
    if minutes_from is not None and lo_i <= minutes_from:
        return None
    if day_key is None:
        # 直接调用（测试）时补上；取值离谱（见 _series_window_day_key）就退回。
        day_key = _series_window_day_key(lo)
        if day_key is None:
            return None
    if not _days_cover(state, day_key):
        return None
    series = []
    for key in sorted(minutes):
        sub = minutes[key]
        at = int(sub["at"])
        if at != key * 60 or at > state["max_at"]:
            return None
        if at < lo_i:
            continue
        if cut and at >= hi:
            # 闭窗口：hi 那一刻归后一桶（桶按 at 严格切分），只取 at < hi
            # 的桶；那一刻有整秒行时上面已经退回。
            break
        out = _series_output_bucket(sub)
        # 整段扫描的桶 at 是 lo + k*60，类型跟着 lo 走（int 或 float）；
        # 存量桶的 at 是整数，这里按 lo 的类型对齐，两边的 JSON 字节才一致。
        out["at"] = int(at) if isinstance(lo, int) else float(at)
        series.append(out)
    return _series_payload(state, realm, lo, hi, 60, series)

def _series_payload(state, realm, lo, hi, step, series):
    """切片载荷的公共部分：窗口头 + credit 历史。

    credit 历史：缓冲按 at 倒序稳定排序后取窗口内的前 50 条——与整段扫描
    的选择逐条相同（见 _series_credit_push 的论证）。窗口的两端都要过滤：
    缓冲收的是整份日志的计费行，闭窗口的上界切进缓冲里时（hi < max_at），
    at > hi 的行不属于窗口，整段扫描不会收它们，切片也必须裁掉。
    """
    credits = sorted(state["credits"], key=lambda item: item.get("at") or 0,
                     reverse=True)
    credits = [c for c in credits
               if lo <= (c.get("at") or 0) <= hi][:_SERIES_CREDITS_KEEP]
    return {"ok": True, "realm": realm or "all",
            "bucket_seconds": step, "since": lo, "until": hi,
            "series": series, "credits": credits}

def _series_slice(state, realm, lo, hi, step, day_key):
    """窗口序列 = 日桶/小时桶/分钟环的切片；不满足对齐条件时返回 None。

    成立条件（缺一不可，任何一条不成立就退回整段扫描——正确性优先）：
      * 窗口起点是本地午夜（day_key 由 _window_day_key 给出）；
      * 桶宽是 3600 或 86400（与窗口对齐的两种）；
      * days_floor 覆盖窗口起点（剪枝/更早的天没折过就只能整段扫）；
      * hi 不低于折过的最大 at，否则窗口上界会切掉桶里的行；hi 切进数据里
        （闭窗口）时还要过闭窗口闸门（见 _series_closed_cut_ok）：hi 落在
        同一套桶格点上、且直到那一刻没有整秒行，才按「at < hi 的桶」切，
        恰好落在 hi 上的行由边沿账挡回整段扫描；
      * 每个桶的 at 落在 lo + k*step 的格点上。这一条同时挡住夏令时：日长
        不是 86400 秒的那天之后，每一天的本地午夜都不再落在 86400 的格点上，
        于是自动退回整段扫描。时区没有夏令时（cn/路由器）时恒真。

    桶宽 60 走分钟环（条件见 _series_slice_minutes），它不要求窗口起点是
    本地午夜，只要求落在分钟格点上。
    """
    if step == 60:
        return _series_slice_minutes(state, realm, lo, hi, day_key)
    if step not in (3600, 86400):
        return None
    lo_i = int(lo)
    cut = False
    if hi < state["max_at"]:
        # 上界切进桶里：闭窗口闸门不成立就退回整段扫描（结果不变）。
        if not _series_closed_cut_ok(state, lo_i, hi, step):
            return None
        cut = True
    if not _days_cover(state, day_key):
        return None
    series = []
    done = False
    for key in sorted(state["days"]):
        if key < day_key or done:
            continue
        bucket = state["days"][key]
        day_at = int(bucket["at"])
        if (day_at - lo_i) % 86400:
            return None
        if step == 86400:
            if cut and day_at >= hi:
                # 闭窗口：hi 那一刻归后一桶（桶按 at 严格切分），只取
                # at < hi 的桶；那一刻有整秒行时上面已经退回。这一天及其后
                # 的桶都在窗口外，done 把循环收口。
                done = True
                continue
            series.append(_series_output_bucket(bucket))
            continue
        hours = bucket.get("hours")
        if hours is None:
            # 这一天的小时格点不成立（见 _fold_usage_series 的午夜兜底）：
            # 整个窗口退回整段扫描，不能只跳过这一天。
            return None
        for hour in sorted(hours, key=int):
            sub = hours[hour]
            if int(sub["at"]) != day_at + int(hour) * 3600:
                return None
            if (int(sub["at"]) - lo_i) % 3600:
                return None
            if cut and int(sub["at"]) >= hi:
                # 闭窗口的右边界（放在格点校验之后——错开的桶要先退回扫描）。
                done = True
                break
            series.append(_series_output_bucket(sub))
    return _series_payload(state, realm, lo, hi, step, series)

_USAGE_CACHE_NAME = "usage-aggregate-cache.json"

_USAGE_CACHE_KIND_NAME = "usage-aggregate-cache-%s.json"

_USAGE_CACHE_SCHEMA = 5

_USAGE_CACHE_LEGACY_SCHEMA = 3

def _usage_cache_enabled():
    """落盘总开关，默认开；WB_USAGE_CACHE=0 关。

    每次调用都读环境变量而不是在导入时定死：现场用它紧急关掉，测试用它在一
    个进程里来回切，而一次 os.environ.get 的开销在刷新路径上可以忽略。
    """
    return os.environ.get("WB_USAGE_CACHE", "1").strip().lower() not in (
        "0", "false", "no", "off")

def _usage_cache_path():
    """升级前单文件（v3）的路径；只读回退与探针脚本用。

    每次调用重算，而不是在导入时算成常量：--usage-dir、测试和探针脚本都会
    在导入之后改 _usage_dir()，常量会写到旧目录去。
    """
    return os.path.join(_usage_dir(), _USAGE_CACHE_NAME)

def _usage_cache_kind_path(kind):
    """某一类状态的 checkpoint 路径（v4 布局；同上，每次调用重算）。"""
    return os.path.join(_usage_dir(), _USAGE_CACHE_KIND_NAME % kind)

def _usage_cache_min_bytes():
    """写盘节流：折叠推进不足这么多字节就不写。默认 1MB。

    1MB 是「重启后最多回放多少」的上限——路由器上扫描约 0.5s/MB，回放 1MB
    等于冷启动成本多半秒；而日志每天涨 6MB 上下，正常流量下一天也未必触发
    一次。写小了是写放大（路由器 flash 写入慢且费寿命），写大了重启变慢。
    """
    return ca_env.number("WB_USAGE_CACHE_MIN_BYTES", 1024 * 1024,
                         minimum=0, integer=True, zero_ok=True)

def _usage_cache_min_seconds():
    """写盘节流：距上次尝试不足这么多秒就不写。默认 900s（15 分钟）。

    这条兜住「字节阈值还没到、但偏移已经推进了一点」的情况：不设它，一段
    短流量之后停下的日志要等到下次凑满 1MB 才会落盘。15 分钟让面板开着时
    一天最多约百次写盘（每次几十 KB），对 flash 友好；重启回放的上限则是
    min(1MB, 15 分钟流量)。
    """
    return ca_env.number("WB_USAGE_CACHE_MIN_SECONDS", 900.0,
                         minimum=0.0, zero_ok=True)

_usage_cache_lock = threading.Lock()

_usage_cache_write_lock = threading.Lock()

_usage_cache_kind_cache = {}

_USAGE_CACHE_LEGACY_UNREAD = object()

_usage_cache_legacy_data = _USAGE_CACHE_LEGACY_UNREAD

_usage_cache_progress = {}

_usage_cache_checkpointed = {}


def _usage_cache_forget():
    """忘掉本进程读过的 checkpoint（模拟一次重启；测试与探针用）。

    读记忆按「类」记账，所以要清的是一个集合；调用点不许持有任何状态锁，
    本函数自己取 _usage_cache_lock（与读取路径同一把）。
    """
    global _usage_cache_legacy_data
    with _usage_cache_lock:
        _usage_cache_kind_cache.clear()
        _usage_cache_legacy_data = _USAGE_CACHE_LEGACY_UNREAD

def _usage_cache_kind_entries(kind):
    """某一类状态的条目列表（读一次、按类记忆）；没有可用来源时返回 None。

    本类文件不存在或读不出时回退到升级前的单文件里对应的那一节：升级后的
    第一次刷新因此不必把整个日志重折一遍。本类文件一旦存在（schema 与 kind
    都对得上）就是唯一来源，旧文件不再参与该类——旧文件里那份可能更旧，也
    可能已经和日志对不上，位置校验各自负责。

    调用点可能在状态锁内（采用阶段），所以本函数会取 _usage_cache_lock；
    反向的锁序不存在——写盘路径取状态锁之前一定先放开本锁，见
    _usage_cache_maybe_save。
    """
    if not _usage_cache_enabled():
        return None
    with _usage_cache_lock:
        if kind not in _usage_cache_kind_cache:
            entries = _bind__usage_cache_read_kind(kind)
            if entries is None:
                entries = _usage_cache_read_legacy_kind(kind)
            _usage_cache_kind_cache[kind] = entries
        return _usage_cache_kind_cache[kind]

def _usage_cache_read_kind(kind):
    """读某一类的 checkpoint 文件并做顶层校验；任何一步不成立都返回 None。

    None 和「文件不存在」同义：调用方按没有缓存处理，绝不因此报错。
    调用方持有 _usage_cache_lock（解析在锁内做，与 v3 的单文件读取一致）。
    """
    try:
        with _open(_bind__usage_cache_kind_path(kind), "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    # 先看类型再看值：JSON 的 true 在 Python 里等于 1，schema: true 不能算
    # 「版本 1」。
    if not _usage_cache_int(data.get("schema")):
        return None
    if data["schema"] != _USAGE_CACHE_SCHEMA:
        return None
    # kind 标签是双保险：文件被复制/改名成另一类的名字时，宁可当没有缓存。
    if data.get("kind") != kind:
        return None
    entries = data.get("entries")
    if not isinstance(entries, list):
        return None
    return entries

def _usage_cache_read_legacy_kind(kind):
    """升级前单文件（v3）里某一类的条目，或 None；文件只解析一次。

    调用方持有 _usage_cache_lock。条目列表是解析结果的一部分，采用路径从
    它里面 pop（取过即删），与 v3 时的用法一致。
    """
    global _usage_cache_legacy_data
    if _usage_cache_legacy_data is _USAGE_CACHE_LEGACY_UNREAD:
        _usage_cache_legacy_data = _bind__usage_cache_read_legacy_file()
    data = _usage_cache_legacy_data
    if not isinstance(data, dict):
        return None
    entries = data.get(kind)
    if not isinstance(entries, list):
        return None
    return entries

def _usage_cache_read_legacy_file():
    """升级前的单文件（v3）解析结果，或 None。

    只做顶层校验（对象 + schema 恰好是 3）。不校验它的 kind 字段——v3 的
    文件本来就没有这个字段，各类小节就是顶层键。任何一步不成立都返回 None。
    """
    try:
        with _open(_bind__usage_cache_path(), "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not _usage_cache_int(data.get("schema")):
        return None
    if data["schema"] != _USAGE_CACHE_LEGACY_SCHEMA:
        return None
    return data

_usage_cache_digest_memo = {}

def _object_digest(obj):
    """一段 JSON 内容摘要，按对象身份记忆；算不出来返回 None。

    记忆表的值强引用对象本身，所以 id() 不会被回收复用；超过几条就整体清空
    ——正常进程里价表对象只在价格变化时换代，这里只是给长期运行兜底。
    """
    hit = _usage_cache_digest_memo.get(id(obj))
    if hit is not None and hit[0] is obj:
        return hit[1]
    try:
        payload = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha1(payload).hexdigest()
    except Exception:
        return None
    if len(_usage_cache_digest_memo) > 8:
        _usage_cache_digest_memo.clear()
    _usage_cache_digest_memo[id(obj)] = (obj, digest)
    return digest

def _realm_inputs_key(inputs):
    """realm 指纹本来就是值比较（不是身份），JSON 化后原样可比。"""
    if inputs is None:
        return None
    realm, accounts = inputs
    return [realm, [[uid, r] for uid, r in accounts]]

_USAGE_CACHE_SNAPSHOT_NUMBERS = tuple(
    k for k, v in _empty_stats().items()
    if isinstance(v, (int, float)) and not isinstance(v, bool))

_USAGE_CACHE_SNAPSHOT_MAPS = ("by_model", "by_model_realm", "by_model_acct")

_USAGE_CACHE_ANALYTICS_NUMBERS = tuple(_new_analytics_stat().keys())

_USAGE_CACHE_BUCKET_NUMBERS = ("requests",) + USAGE_FIELDS

_USAGE_CACHE_SERIES_NUMBERS = tuple(_new_series_bucket(0).keys())

def _usage_cache_number(value):
    """折叠累加的数字。bool 是 int 的子类，必须挡掉。"""
    return isinstance(value, (int, float)) and not isinstance(value, bool)

def _usage_cache_int(value):
    """严格整数：JSON 里写成 12345.0 的不算。"""
    return isinstance(value, int) and not isinstance(value, bool)

def _usage_cache_counts_ok(counts):
    """{str: 数字} 形状的计数表（models / realms）。"""
    if not isinstance(counts, dict):
        return False
    for key, value in counts.items():
        if not isinstance(key, str) or not _usage_cache_number(value):
            return False
    return True

def _usage_cache_bucket_ok(bucket):
    """一个 by_model* 桶：折叠会就地累加这些键。"""
    if not isinstance(bucket, dict):
        return False
    for field in _USAGE_CACHE_BUCKET_NUMBERS:
        if not _usage_cache_number(bucket.get(field)):
            return False
    return _usage_cache_counts_ok(bucket.get("accounts"))

def _usage_cache_snapshot_bucket_ok(snap):
    """一个窗口半快照桶的形状（all-time 半、日桶、小时桶共用）。

    少一个键，折叠或 _copy_usage_snapshot() 就会半路抛错，那次刷新报出半份
    数字——校验必须挡在采用之前。
    """
    if not isinstance(snap, dict):
        return False
    for field in _USAGE_CACHE_SNAPSHOT_NUMBERS:
        if not _usage_cache_number(snap.get(field)):
            return False
    for field in _USAGE_CACHE_SNAPSHOT_MAPS:
        if not isinstance(snap.get(field), dict):
            return False
    for _, bucket in snap["by_model"].items():
        if not _usage_cache_bucket_ok(bucket):
            return False
    for _, realms in snap["by_model_realm"].items():
        if not isinstance(realms, dict):
            return False
        for _, bucket in realms.items():
            if not _usage_cache_bucket_ok(bucket):
                return False
    for _, realms in snap["by_model_acct"].items():
        if not isinstance(realms, dict):
            return False
        for _, accts in realms.items():
            if not isinstance(accts, dict):
                return False
            for _, bucket in accts.items():
                if not _usage_cache_bucket_ok(bucket):
                    return False
    return True

def _usage_cache_snapshot_ok(snap):
    """窗口半快照桶 + 它可能挂着的小时子表（见 _usage_hour_bucket）。

    小时子表的校验与时间序列那份（_usage_cache_series_bucket_ok）同一套：
    键是数字字符串（折叠侧从一开始就写 str(序号)，与 JSON 往返后的形状
    一致），子桶形状同快照桶且不再嵌表（表只挂在日桶上）。at 是格点，
    没有它求和侧就做不了格点校验，所以这里也要求它是数字。
    """
    if not _usage_cache_snapshot_bucket_ok(snap):
        return False
    hours = snap.get("hours")
    if hours is None:
        return True
    if not isinstance(hours, dict):
        return False
    for hour, sub in hours.items():
        if not (isinstance(hour, str) and hour.isdigit()):
            return False
        if not isinstance(sub, dict) or "hours" in sub:
            return False
        if not _usage_cache_number(sub.get("at")):
            return False
        if not _usage_cache_snapshot_bucket_ok(sub):
            return False
    return True

def _usage_cache_stat_ok(stat):
    """一个 analytics 统计桶：折叠会就地累加它的每一个字段。"""
    if not isinstance(stat, dict):
        return False
    for field in _USAGE_CACHE_ANALYTICS_NUMBERS:
        if not _usage_cache_number(stat.get(field)):
            return False
    return True

def _usage_cache_models_ok(models):
    """analytics 的 {model: {requests, tokens, reasoning}} 表。"""
    if not isinstance(models, dict):
        return False
    for mid, stat in models.items():
        if not isinstance(mid, str) or not isinstance(stat, dict):
            return False
        for field in ("requests", "tokens", "reasoning"):
            if not _usage_cache_number(stat.get(field)):
                return False
    return True

def _usage_cache_analytics_window_ok(maps):
    """窗口形状的 analytics maps（日桶/小时桶）：同一批表，装的是 window 那一半。

    与 _usage_cache_analytics_ok 是两份形状，不能互相顶替：日桶只折窗口半，
    少 all_time/all_models 两个键，用 all-time 的校验器会把整份 analytics
    entry 拒掉（连它自己那份 all-time 也一起丢），窗口就退回整段扫描。
    """
    if not isinstance(maps, dict):
        return False
    if not _usage_cache_stat_ok(maps.get("summary")):
        return False
    accts, models, keys = maps.get("accts"), maps.get("models"), maps.get("keys")
    if not isinstance(accts, dict) or not isinstance(models, dict) or not isinstance(keys, dict):
        return False
    for uid, entry in accts.items():
        if not isinstance(uid, str) or not isinstance(entry, dict):
            return False
        for field in ("nickname", "realm", "domain"):
            if not isinstance(entry.get(field), str):
                return False
        if not _usage_cache_stat_ok(entry.get("window")):
            return False
        if not _usage_cache_models_ok(entry.get("window_models")):
            return False
    for mid, entry in models.items():
        if not isinstance(mid, str) or not isinstance(entry, dict):
            return False
        if not isinstance(entry.get("model"), str):
            return False
        if not _usage_cache_stat_ok(entry.get("window")):
            return False
    for kid, entry in keys.items():
        if not isinstance(kid, str) or not isinstance(entry, dict):
            return False
        if not isinstance(entry.get("key"), str):
            return False
        if not _usage_cache_stat_ok(entry.get("window")):
            return False
        if not _usage_cache_models_ok(entry.get("window_models")):
            return False
        if not _usage_cache_counts_ok(entry.get("realms")):
            return False
        if not _usage_cache_number(entry.get("last_at")):
            return False
    return True

def _usage_cache_analytics_hours_ok(hours):
    """analytics 日桶的小时子表：{小时键: 窗口形状 maps + at}。

    小时键是数字字符串（JSON 的对象键只能是字符串，折叠侧从一开始就用
    str(小时序号)），子桶就是一份窗口形状 maps 再带它自己的 at——形状与
    时间序列的小时子表同一个道理。
    """
    if not isinstance(hours, dict):
        return False
    for hour, sub in hours.items():
        if not (isinstance(hour, str) and hour.isdigit()):
            return False
        if not isinstance(sub, dict) or "hours" in sub:
            return False
        if not _usage_cache_number(sub.get("at")):
            return False
        if not _usage_cache_analytics_window_ok(sub):
            return False
    return True

def _usage_cache_analytics_day_ok(bucket):
    """analytics 的日桶：窗口形状 maps + at（本地午夜）+ 可选的 hours 子表。

    hours 缺席是合法状态，不是损坏：剪枝线（_prune_day_buckets 的 hours_keep
    一段）会把保留窗口之外的旧天的小时表摘掉，本地午夜落在不存在的小时里那天
    也会被摘掉；只折窗口半的日桶在「这天没有小时表」时照旧回答按日对齐的窗口，
    而整点窗口本来就由求和侧按 hours is None 退回整段扫描
    （_analytics_window_from_hours），所以采纳仍然正确。与
    _usage_cache_snapshot_ok / _usage_cache_series_bucket_ok 对 hours 的容忍
    同一套规矩。

    at 则必须留着：旧版本写下的日桶没有这个键（也就没有小时层），在这里被拒，
    升级后 analytics 整体重折一次、小时层立刻就有历史可借。只放任 hours 缺席，
    这次一次性代价就不会被剪枝线反复引燃——否则只要还在折新行，剪枝线天天把旧天
    的小时表摘掉，整份状态就天天被判废、每次进程启动都要付一次全量重折。
    """
    if not isinstance(bucket, dict):
        return False
    if not _usage_cache_number(bucket.get("at")):
        return False
    hours = bucket.get("hours")
    if hours is not None and not _usage_cache_analytics_hours_ok(hours):
        return False
    return _usage_cache_analytics_window_ok(bucket)

def _usage_cache_analytics_ok(maps):
    """analytics all-time maps：summary/accts/models/keys 四张表。"""
    if not isinstance(maps, dict):
        return False
    if not _usage_cache_stat_ok(maps.get("summary")):
        return False
    accts, models, keys = maps.get("accts"), maps.get("models"), maps.get("keys")
    if not isinstance(accts, dict) or not isinstance(models, dict) or not isinstance(keys, dict):
        return False
    for uid, entry in accts.items():
        if not isinstance(uid, str) or not isinstance(entry, dict):
            return False
        for field in ("nickname", "realm", "domain"):
            if not isinstance(entry.get(field), str):
                return False
        if not _usage_cache_stat_ok(entry.get("all_time")):
            return False
        if not _usage_cache_models_ok(entry.get("all_models")):
            return False
    for mid, entry in models.items():
        if not isinstance(mid, str) or not isinstance(entry, dict):
            return False
        if not isinstance(entry.get("model"), str):
            return False
        if not _usage_cache_stat_ok(entry.get("all_time")):
            return False
    for kid, entry in keys.items():
        if not isinstance(kid, str) or not isinstance(entry, dict):
            return False
        if not isinstance(entry.get("key"), str):
            return False
        if not _usage_cache_stat_ok(entry.get("all_time")):
            return False
        if not _usage_cache_models_ok(entry.get("all_models")):
            return False
        if not _usage_cache_counts_ok(entry.get("realms")):
            return False
        if not _usage_cache_number(entry.get("last_at")):
            return False
    return True

def _usage_cache_buckets_ok(buckets):
    """by_account 的 {account: 桶}：折叠会就地累加每个桶。"""
    if not isinstance(buckets, dict):
        return False
    for key, bucket in buckets.items():
        if not isinstance(key, str) or not isinstance(bucket, dict):
            return False
        if not isinstance(bucket.get("account"), str):
            return False
        for field in ("requests", "prompt_tokens", "completion_tokens",
                      "reasoning_tokens", "cached_tokens", "total_tokens"):
            if not _usage_cache_number(bucket.get(field)):
                return False
        if not _usage_cache_counts_ok(bucket.get("models")):
            return False
    return True

def _usage_cache_remaining_ok(entry):
    """剩余用量折叠：事件表 + 每个 (账号, 模型) 的 at/cum 两个平行列表。

    cum 必须单调（回退=负增量=坏数据）且与 at 等长、base 不可能超过 cum[0]
    ——这些是加载后一切查询的前提，坏一条就会静默算出错数字，所以逐元素走
    一遍：一次重启付 1~3ms，换掉一次全量冷扫。
    `at` **不要求有序**：写入侧的 at 是请求完成时刻，多线程下会回退几毫秒
    （真机日志与路由器自己写出的 checkpoint 都踩过），旧版在这里整份拒绝、
    每次重启都退回冷扫。加载端改为由 _pair_repair 做一次稳定排序（配对不变、
    前缀和重算），所以有序性校验搬到了那里，形状检查留在这里。
    """
    if not isinstance(entry, dict):
        return False
    if not _usage_cache_int(entry.get("offset")) or entry.get("offset") <= 0:
        return False
    if not isinstance(entry.get("tail"), str):
        return False
    key = entry.get("key")
    if not isinstance(key, list) or len(key) != 3 or not all(
            _usage_cache_int(v) for v in key):
        return False
    file_pos = entry.get("file")
    if not isinstance(file_pos, dict) or not _usage_cache_int(file_pos.get("offset")):
        return False
    if not isinstance(file_pos.get("tail"), str):
        return False
    file_key = file_pos.get("key")
    if not isinstance(file_key, list) or len(file_key) != 3 or not all(
            _usage_cache_int(v) for v in file_key):
        return False
    events = entry.get("events")
    if not isinstance(events, list) or len(events) > _REMAINING_MAX_EVENTS:
        return False
    for event in events:
        if not isinstance(event, dict):
            return False
        if not isinstance(event.get("account"), str) or not isinstance(event.get("model"), str):
            return False
        for field in ("at", "reset", "sample"):
            if not _usage_cache_number(event.get(field)):
                return False
    usage = entry.get("usage")
    if not isinstance(usage, dict):
        return False
    for pair_key, pair in usage.items():
        if (not isinstance(pair_key, str) or "\x1f" not in pair_key
                or not isinstance(pair, dict)):
            return False
        at = pair.get("at")
        cum = pair.get("cum")
        if not isinstance(at, list) or not isinstance(cum, list) or len(at) != len(cum):
            return False
        if not _usage_cache_int(pair.get("head")) or not _usage_cache_int(pair.get("base")):
            return False
        if pair["head"] < 0 or pair["head"] > len(at) or pair["base"] < 0:
            return False
        for value in at:
            if not _usage_cache_number(value):
                return False
        last_cum = None
        for value in cum:
            if not _usage_cache_int(value):
                return False
            if last_cum is not None and value < last_cum:
                return False
            last_cum = value
        # base 是「保留区之前那段的累计和」，cum 从最早一行累计且含被裁前缀，
        # 所以 base 不可能超过 cum[0]。旧版压缩把 base 累加过（第二次起重复
        # 计入前缀），这样的条目必须整份拒绝——否则左端落在保留区之前的区间
        # 求和会算出负数（真机面板显示过 -1293.5M）。
        if cum and pair["base"] > cum[0]:
            return False
    return True

def _usage_cache_day_key_ok(key):
    """日键必须是 "YYYY-MM-DD"：窗口与日桶的比较靠的就是这个形状。"""
    return (isinstance(key, str) and len(key) == 10 and key[4] == "-"
            and key[7] == "-")

def _usage_cache_days_ok(days, floor, bucket_ok):
    """按日分桶的表：{日键: 桶}，floor 是「对哪些天完整」的下界（日键或 None）。

    桶的形状由调用方给（snapshot / analytics / 时间序列各一套），日键与
    floor 的形状在这里统一校验：键不是日期的桶永远不会被窗口选中，但也说明
    这份状态不是我们写出来的，直接拒绝更干净。
    """
    if not isinstance(days, dict):
        return False
    if floor is not None and not _usage_cache_day_key_ok(floor):
        return False
    for key, bucket in days.items():
        if not _usage_cache_day_key_ok(key) or not bucket_ok(bucket):
            return False
    return True

def _usage_cache_series_bucket_ok(bucket):
    """时间序列桶：9 个数字；日桶还带 hours 子表（小时键是数字字符串）。

    小时键写成字符串是 JSON 往返决定的（JSON 的对象键只能是字符串），折叠
    侧因此从一开始就用 str(小时序号)，加载回来的状态与现折的状态形状一致。
    """
    if not isinstance(bucket, dict):
        return False
    for field in _USAGE_CACHE_SERIES_NUMBERS:
        if not _usage_cache_number(bucket.get(field)):
            return False
    hours = bucket.get("hours")
    if hours is None:
        return True
    if not isinstance(hours, dict):
        return False
    for hour, sub in hours.items():
        if not (isinstance(hour, str) and hour.isdigit()):
            return False
        if not isinstance(sub, dict) or "hours" in sub:
            return False
        for field in _USAGE_CACHE_SERIES_NUMBERS:
            if not _usage_cache_number(sub.get(field)):
                return False
    return True

def _usage_cache_series_minutes_ok(rows):
    """分钟环的落盘形状：[分钟, 8 个数字] 的严格升序列表。

    None 是合法的（旧版 checkpoint 没有分钟环这个键）：采用端把它当「环只
    从采用点之后才完整」处理（见 _usage_cache_adopt_series），所以这里放行
    而不是拒整份。行首必须是真整数（JSON 里 12345.0 不算）、严格递增——
    递增同时钉住「没有重复分钟」；其余 8 个必须是折叠累加出来的数字。
    """
    if rows is None:
        return True
    if not isinstance(rows, list):
        return False
    last = None
    for row in rows:
        if not isinstance(row, list) or len(row) != 1 + len(_SERIES_MINUTE_FIELDS):
            return False
        minute = row[0]
        if not _usage_cache_int(minute):
            return False
        if last is not None and minute <= last:
            return False
        last = minute
        for value in row[1:]:
            if not _usage_cache_number(value):
                return False
    return True

def _usage_cache_minutes_state(rows):
    """落盘行 -> 折叠时的字典桶（键是 epoch 分钟整数）。

    还原出的桶与冷折出来的逐字段同类型（int 的字段来自 JSON 的整数写法，
    credit 是浮点），所以「采用后再切片」与「冷折后切片」的输出逐字节一致。
    """
    out = {}
    for row in rows or []:
        key = int(row[0])
        bucket = _new_series_bucket(key * 60)
        for index, field in enumerate(_SERIES_MINUTE_FIELDS, start=1):
            bucket[field] = row[index]
        out[key] = bucket
    return out

def _usage_cache_credits_ok(credits):
    """credit 缓冲：{at, iso, model, account, credit, total_tokens} 的列表。"""
    if not isinstance(credits, list):
        return False
    for item in credits:
        if not isinstance(item, dict):
            return False
        for field in ("at", "credit", "total_tokens"):
            if not _usage_cache_number(item.get(field)):
                return False
        for field in ("iso", "model", "account"):
            if not isinstance(item.get(field), str):
                return False
    return True

def _usage_cache_hits_ok(hits, overflow):
    """闭窗口边沿账的落盘形状：[整秒 epoch] 列表 + 严格 bool 溢出标记。

    旧版 checkpoint 没有这两个键（entry.get 给 None）→ 拒：升级后第一次刷新
    重折一次（与 v3→v4「缺小时表的 snapshot/analytics 被拒、一次性重折」
    同一套处置）。账是「直到某刻没有行落在整秒上」的证明，缺了它闭窗口只能
    退回扫描（正确但慢），宁可重折一次把它补全。
    """
    if not isinstance(hits, list) or not isinstance(overflow, bool):
        return False
    for value in hits:
        if not _usage_cache_int(value):
            return False
    return True

def _usage_cache_take(kind, realm=None):
    """从 checkpoint 里取出一份状态（取过即删），没有合适的返回 None。

    snapshot/analytics 按 realm 匹配（JSON 的 null 表示不限 realm），
    by_account / remaining 只有一份。逐份取用：同一份不会被第二次采用，也就
    不存在「先取走、校验失败、下个 realm 又拿到一份脏状态」的路径。

    只解析、只取用调用方要的那一类文件：其余四类连文件都不打开。
    """
    entries = _usage_cache_kind_entries(kind)
    if not isinstance(entries, list):
        return None
    # 取走这一步也要在锁里：两个 realm 的首次刷新可能同时到这里，一个
    # 边遍历边 pop、另一个也在 pop，遍历就会跳过条目。跳过的后果只是这次
    # 不采用（安全方向），但少一次竞争就少一个要解释的路径。
    with _usage_cache_lock:
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            if kind not in ("by_account", "remaining"):
                # realm 字段必须显式存在且类型正确：realm=None 的折叠（全部
                # realm）和某个具体 realm 的折叠是两份不同的状态，缺字段的
                # 条目一旦被 None 匹配走，就会把「只折了一个 realm」的数字
                # 当成「全部 realm」报出去。
                entry_realm = entry.get("realm")
                if "realm" not in entry or not (entry_realm is None
                                                or isinstance(entry_realm, str)):
                    continue
                if entry_realm != realm:
                    continue
            entries.pop(index)
            return entry
    return None

def _usage_cache_position_ok(entry, log_key):
    """校验一份状态的 (offset, key, tail)；不合格返回 None。

    复用 #189 的两个原语而不是另造一套：offset 必须仍落在同一个文件的现有
    字节里（dev/ino 相同、当前 size >= offset），并且 offset 前的最后 64 字节
    与写下时一致——文件被替换、截短、copytruncate 后重写都会被这两条挡住。
    """
    offset = entry.get("offset")
    key = entry.get("key")
    tail_hex = entry.get("tail")
    if not _usage_cache_int(offset) or offset <= 0:
        return None
    if not isinstance(key, list) or len(key) != 3 or not all(
            _usage_cache_int(v) for v in key):
        return None
    if not isinstance(tail_hex, str):
        return None
    try:
        tail = bytes.fromhex(tail_hex)
    except ValueError:
        return None
    if not _log_offset_holds(tuple(key), log_key, offset):
        return None
    if _log_tail_signature(offset) != tail:
        return None
    return offset, tail

def _usage_cache_fingerprints_ok(entry, pricing_used_ok, realm_key):
    """「用到的价」与 realm 指纹必须和当前进程读到的一致。

    价格一侧由调用方用 _pricing_used_unchanged(entry["pricing"], pricing)
    判好（记录形状不符、价表读不出来、总开关翻转都在那里返回 False），这里
    只把它和 realm 一侧一起收口。任一侧取不到（None）都算不一致：取不到就
    意味着「折叠当时读了什么」已经无法确认，缓存不能当有效用。
    """
    if not pricing_used_ok or realm_key is None:
        return False
    return entry.get("realm_inputs") == realm_key

def _usage_cache_note_adopted(kind, offset):
    """采用成功后的节流初始化：刚加载的 offset 不算「有新字节要写」。

    不初始化的话，重启后第一次刷新会把「offset 从 0 涨到文件尾」当成一次大
    推进，白白重写一份内容相同的文件。
    """
    with _usage_cache_lock:
        if offset > _usage_cache_progress.get(kind, 0):
            _usage_cache_progress[kind] = offset
        if offset > _usage_cache_checkpointed.get(kind, 0):
            _usage_cache_checkpointed[kind] = offset
        _set_usage_cache_last_attempt(time.time())

def _usage_cache_adopt_snapshot(r, state, log_key, pricing, realm):
    """把 checkpoint 里对应 realm 的 snapshot 折叠装进 state；成功返回 True。

    调用方持有 _usage_snap_state_lock，并且只在 state 全新时调用：采用只把
    offset/tail 往前挪，折叠逻辑一行不动。

    闭窗口的边沿账（hits/hits_overflow）是这一份的必填项：旧版 checkpoint
    没有这两个键，会被拒 → 升级后第一次刷新重折一次（一次性代价，与
    v3→v4 缺小时表时的处置一致）。
    """
    entry = _usage_cache_take("snapshot", r)
    if entry is None:
        return False
    position = _usage_cache_position_ok(entry, log_key)
    if position is None:
        return False
    if not _usage_cache_fingerprints_ok(
            entry, _pricing_used_unchanged(entry.get("pricing"), pricing),
            _realm_inputs_key(realm)):
        return False
    snap = entry.get("snap")
    if not _usage_cache_snapshot_ok(snap):
        return False
    days = entry.get("days")
    floor = entry.get("days_floor")
    if not _usage_cache_days_ok(days, floor, _usage_cache_snapshot_ok):
        return False
    hours_floor = entry.get("hours_floor_at")
    if hours_floor is not None and not _usage_cache_number(hours_floor):
        return False
    hits = entry.get("hits")
    overflow = entry.get("hits_overflow")
    if not _usage_cache_hits_ok(hits, overflow):
        return False
    offset, tail = position
    state.update({"snap": snap, "offset": offset, "tail": tail,
                  "days": days, "days_floor": floor,
                  "hours_floor_at": _hours_floor_on_adopt(days, hours_floor),
                  "hits": list(hits), "hits_overflow": overflow,
                  # 「用到的价」记录跟着状态一起装进来：后续增量折叠继续往
                  # 这份记录里加，下一次判废拿它比对当前价表。
                  "pricing": _copy_pricing_record(entry.get("pricing"))})
    _usage_cache_note_adopted("snapshot", offset)
    return True

def _usage_cache_adopt_by_account(state, log_key):
    """by_account 折叠的采用；这一份没有价格/realm 指纹（折叠不读它们）。"""
    entry = _usage_cache_take("by_account")
    if entry is None:
        return False
    position = _usage_cache_position_ok(entry, log_key)
    if position is None:
        return False
    buckets = entry.get("buckets")
    if not _usage_cache_buckets_ok(buckets):
        return False
    offset, tail = position
    state.update({"buckets": buckets, "offset": offset, "tail": tail})
    _usage_cache_note_adopted("by_account", offset)
    return True

def _usage_cache_adopt_remaining(state, log_key):
    """剩余用量折叠的采用；同样没有价格/realm 指纹（折叠不读它们）。

    事件日志的位置在这里单独校验：它很小，位置对不上就整份放弃——冷读一遍
    两个文件比「先采用一半、再发现对不上」简单得多。
    每个 pair 还要过一遍 _pair_repair：旧版写出的缓冲按日志顺序排列，`at`
    可能回退几毫秒，这里统一整理成按 `at` 稳定排序的规范形态（有序的文件
    上它就是一次 O(n) 的核对）。整理不了的（负增量=坏数据）整份放弃。
    """
    entry = _usage_cache_take("remaining")
    if entry is None or not _usage_cache_remaining_ok(entry):
        return False
    position = _usage_cache_position_ok(entry, log_key)
    if position is None:
        return False
    try:
        file_state = {"offset": entry["file"]["offset"],
                      "key": tuple(entry["file"]["key"]),
                      "tail": bytes.fromhex(entry["file"]["tail"])}
    except ValueError:
        return False
    if not _log_resume_ok(file_state, _usage_log_key(LIMIT_EVENTS_FILE),
                          LIMIT_EVENTS_FILE):
        return False
    offset, tail = position
    usage = {}
    for pair_key, pair in entry["usage"].items():
        uid, _, model = pair_key.partition("\x1f")
        buf = {"at": list(pair["at"]), "cum": list(pair["cum"]),
               "head": pair["head"], "base": pair["base"]}
        if not _pair_repair(buf):
            return False
        usage[(uid, model)] = buf
    state["log"] = {"offset": offset, "key": tuple(entry["key"]), "tail": tail}
    state["file"] = file_state
    state["usage"] = usage
    state["events"] = [dict(event) for event in entry["events"]]
    state["keys"] = {(event["account"], event["model"], float(event["reset"]))
                     for event in state["events"]}
    _usage_cache_note_adopted("remaining", offset)
    return True

def _usage_cache_adopt_analytics(realm, state, log_key, pricing, realm_inputs):
    """analytics all-time 折叠的采用；闭窗口的边沿账是必填项（见 snapshot 版）。"""
    entry = _usage_cache_take("analytics", realm)
    if entry is None:
        return False
    position = _usage_cache_position_ok(entry, log_key)
    if position is None:
        return False
    if not _usage_cache_fingerprints_ok(
            entry, _pricing_used_unchanged(entry.get("pricing"), pricing),
            _realm_inputs_key(realm_inputs)):
        return False
    maps = entry.get("maps")
    if not _usage_cache_analytics_ok(maps):
        return False
    days = entry.get("days")
    floor = entry.get("days_floor")
    if not _usage_cache_days_ok(days, floor, _usage_cache_analytics_day_ok):
        return False
    max_at = entry.get("max_at")
    if not _usage_cache_number(max_at):
        return False
    hits = entry.get("hits")
    overflow = entry.get("hits_overflow")
    if not _usage_cache_hits_ok(hits, overflow):
        return False
    offset, tail = position
    state.update({"maps": maps, "offset": offset, "tail": tail,
                  "days": days, "days_floor": floor, "max_at": max_at,
                  "hits": list(hits), "hits_overflow": overflow,
                  "pricing": _copy_pricing_record(entry.get("pricing"))})
    _usage_cache_note_adopted("analytics", offset)
    return True

def _usage_cache_adopt_series(r, state, log_key, realm_inputs):
    """时间序列状态的采用；这一份只有 realm 指纹（折叠不算价）。"""
    entry = _usage_cache_take("series", r)
    if entry is None:
        return False
    position = _usage_cache_position_ok(entry, log_key)
    if position is None:
        return False
    realm_key = _realm_inputs_key(realm_inputs)
    if realm_key is None or entry.get("realm_inputs") != realm_key:
        return False
    days = entry.get("days")
    floor = entry.get("days_floor")
    if not _usage_cache_days_ok(days, floor, _usage_cache_series_bucket_ok):
        return False
    max_at = entry.get("max_at")
    if not _usage_cache_number(max_at):
        return False
    credits = entry.get("credits")
    if not _usage_cache_credits_ok(credits):
        return False
    minutes = entry.get("minutes")
    if not _usage_cache_series_minutes_ok(minutes):
        return False
    minutes_from = entry.get("minutes_from")
    if minutes_from is not None and not _usage_cache_number(minutes_from):
        return False
    hits = entry.get("hits")
    overflow = entry.get("hits_overflow")
    if not _usage_cache_hits_ok(hits, overflow):
        return False
    if minutes is None:
        # 旧版 checkpoint（没有分钟环这个键）：这一份状态是能用的（日/小时桶
        # 与 credits 都在），只是分钟环要从采用点之后才开始折。把完整线记成
        # 采用时的 max_at——前缀里所有行的 at 都 <= 它，所以起点晚于它的窗口
        # 只碰得到之后折进来的行，环对它们是完整的；早于它的窗口一律退回
        # 整段扫描（见 _series_slice_minutes）。
        minutes = []
        minutes_from = max_at
    offset, tail = position
    state.update({"days": days, "days_floor": floor, "max_at": max_at,
                  "credits": credits, "offset": offset, "tail": tail,
                  "minutes": _usage_cache_minutes_state(minutes),
                  "minutes_from": minutes_from,
                  "hits": list(hits), "hits_overflow": overflow})
    _usage_cache_note_adopted("series", offset)
    return True

def _usage_cache_days_copy(days, copy_bucket):
    """日桶表的深拷贝（序列化在锁外做，桶必须和活状态脱钩）。"""
    return {key: copy_bucket(bucket) for key, bucket in (days or {}).items()}

def _copy_series_day(bucket):
    """一个时间序列日桶的深拷贝（含 hours 子表）。"""
    copy = dict(bucket)
    copy["hours"] = {h: dict(sub) for h, sub in (bucket.get("hours") or {}).items()}
    return copy

def _copy_snapshot_day(bucket):
    """一个窗口半日桶的深拷贝（含 hours 子表，见 _usage_hour_bucket）。"""
    copy = _copy_usage_snapshot(bucket)
    hours = bucket.get("hours")
    if hours is not None:
        copy["hours"] = {h: _copy_usage_snapshot(sub)
                         for h, sub in hours.items()}
    return copy

_SERIES_MINUTE_FIELDS = ("requests", "errors", "prompt_tokens",
                         "completion_tokens", "reasoning_tokens",
                         "cached_tokens", "total_tokens", "credit")

def _usage_cache_minutes_copy(minutes):
    """分钟环的落盘形态：按分钟升序的 [分钟, 8 个数字] 行。

    形状与内存里的字典桶不同（键换成行首的整数、字段名省掉），这是刻意的
    体积预算：环最多 361 个桶（6 小时），字典形状每个桶 ~150 字节、满环要
    50KB 级，位置数组把每个桶压到 40~50 字节（本机真实数据实测 52）。形状
    差异只存在于落盘/加载这一层：加载端（_usage_cache_minutes_state）还原
    成与冷折完全一样的字典桶，切片与输出的字节不受影响。排序写出而不是按
    插入顺序，是为了让文件内容与折叠顺序无关（冷折与「采用后再折」写出的
    这份字节一致）。状态里没有环（不该发生，但落盘不靠断言）时写 null：
    加载端按「环不完整」处理。
    """
    if minutes is None:
        return None
    rows = []
    for key in sorted(minutes or {}):
        bucket = minutes[key]
        rows.append([int(key)] + [bucket.get(field)
                                  for field in _SERIES_MINUTE_FIELDS])
    return rows

def _usage_cache_snapshot_entry(realm, state):
    """一份 snapshot 状态的 JSON 形态；不适合落盘时返回 None。

    只写「折叠成功过」的状态：错误路径会把 offset 归零，这里直接跳过——
    offset 为 0 的缓存没有任何加速作用，写进去只会让加载端白校验一遍。
    """
    offset = state.get("offset") or 0
    tail = state.get("tail")
    if offset <= 0 or not isinstance(tail, bytes) or state.get("snap") is None:
        return None
    # 「用到的价」记录（T15；见「用到的价」状态指纹一节）：形状不合格就不写。
    # 价格估算体系移除后折叠不再读任何价，record 恒为 None —— 这种状态**仍然
    # 值得落盘**（缓存的价值在跳过 2.7 万行重扫，与计价无关），校验交给
    # offset / tail / 日志指纹。只有「有记录但形状坏了」才跳过。
    record = state.get("pricing")
    if record is not None and not _pricing_record_ok(record):
        return None
    realm_inputs = state.get("realm")
    realm_key = _realm_inputs_key(realm_inputs)
    if realm_key is None:
        return None
    if not _realm_fold_reproducible(realm_inputs[1]):
        # 这次折叠的归属冷进程复现不了（见 _realm_fold_reproducible）：写下去
        # 会被按新归属当成有效。宁可这次不写，等池就绪/重载后再写。
        return None
    return {"realm": realm, "offset": offset,
            "key": list(state["key"] or (0, 0, 0)), "tail": tail.hex(),
            # 记录的深拷贝在锁内做，序列化在锁外做（同下面几份深拷贝）。
            "pricing": _copy_pricing_record(record), "realm_inputs": realm_key,
            # 深拷贝在锁内做，序列化在锁外做（见 _usage_cache_collect）。
            "snap": _copy_usage_snapshot(state["snap"]),
            # 按日分桶的窗口半：与 all-time 半同一次扫描折出来的，位置也
            # 跟着同一条 offset/tail 校验，不另设一套。日桶里还挂着小时
            # 子表（T9 的小时层），深拷贝必须跟着一起做。
            "days": _usage_cache_days_copy(state.get("days"),
                                           _copy_snapshot_day),
            "days_floor": state.get("days_floor"),
            # 小时层的剪枝线（见 _hours_cover）：缺了它重启后的小时层要么
            # 不折（None 直接挡住 _usage_hour_bucket），要么服务了被剪过的
            # 天——两者都不对，所以它和日桶一起落盘。
            "hours_floor_at": state.get("hours_floor_at"),
            # 闭窗口的边沿账（见 _closed_window_hit_record）：直到某刻没有行
            # 落在整秒上的证明。旧版 checkpoint 没有这两个键，采用端因此
            # 拒整份、升级后一次性重折。
            "hits": list(state["hits"]),
            "hits_overflow": bool(state["hits_overflow"])}

def _usage_cache_by_account_entry(state):
    """by_account 折叠的 JSON 形态；同上，只写折叠成功过的。"""
    offset = state.get("offset") or 0
    tail = state.get("tail")
    buckets = state.get("buckets")
    if offset <= 0 or not isinstance(tail, bytes) or not isinstance(buckets, dict):
        return None
    return {"offset": offset, "key": list(state["key"] or (0, 0, 0)),
            "tail": tail.hex(),
            # 深拷贝：序列化在锁外做，桶里的 models 必须和活状态脱钩。
            "buckets": {k: dict(v, models=dict(v.get("models") or {}))
                        for k, v in buckets.items()}}

def _usage_cache_remaining_entry(state):
    """剩余用量折叠的 JSON 形态；同上，只写折叠成功过的。

    两份位置都要带上：usage.jsonl 的（加载端靠 _usage_cache_position_ok
    校验）和事件日志的（很小，加载端整份比对）。缓冲以 "uid\\x1fmodel" 为
    键——JSON 的对象键只能是字符串。
    """
    log = state.get("log") or {}
    file_slot = state.get("file") or {}
    events = state.get("events")
    usage = state.get("usage")
    offset = log.get("offset") or 0
    tail = log.get("tail")
    if offset <= 0 or not isinstance(tail, bytes):
        return None
    if not isinstance(events, list) or not isinstance(usage, dict):
        return None
    buffers = {}
    for (uid, model), pair in usage.items():
        if not isinstance(pair, dict):
            return None
        buffers["%s\x1f%s" % (uid, model)] = {
            "at": list(pair.get("at") or ()),
            "cum": list(pair.get("cum") or ()),
            "head": int(pair.get("head") or 0),
            "base": int(pair.get("base") or 0),
        }
    return {"offset": offset, "key": list(log.get("key") or (0, 0, 0)),
            "tail": tail.hex(),
            "file": {"offset": int(file_slot.get("offset") or 0),
                     "key": list(file_slot.get("key") or (0, 0, 0)),
                     "tail": (file_slot.get("tail") or b"").hex()},
            "events": [dict(event) for event in events],
            "usage": buffers}

def _usage_cache_analytics_entry(realm, state):
    """analytics all-time 折叠的 JSON 形态；同上。"""
    offset = state.get("offset") or 0
    tail = state.get("tail")
    if offset <= 0 or not isinstance(tail, bytes):
        return None
    record = state.get("pricing")
    if record is not None and not _pricing_record_ok(record):
        return None          # 同 snapshot：记录存在但形状坏了才不写
    realm_inputs = state.get("realm")
    realm_key = _realm_inputs_key(realm_inputs)
    if realm_key is None:
        return None
    if not _realm_fold_reproducible(realm_inputs[1]):
        return None          # 同 snapshot：这次折叠的归属冷进程复现不了
    return {"realm": realm, "offset": offset,
            "key": list(state["key"] or (0, 0, 0)), "tail": tail.hex(),
            "pricing": _copy_pricing_record(record), "realm_inputs": realm_key,
            "maps": _copy_analytics_all_time(state["maps"]),
            "days": _usage_cache_days_copy(state.get("days"),
                                           _copy_analytics_window_maps),
            "days_floor": state.get("days_floor"),
            # 折过的最大 at：小时层靠它判断 until 有没有切掉桶里的行。
            "max_at": state.get("max_at") or 0,
            # 闭窗口的边沿账（见 _closed_window_hit_record）：旧版 checkpoint
            # 没有这两个键，采用端因此拒整份、升级后一次性重折。
            "hits": list(state["hits"]),
            "hits_overflow": bool(state["hits_overflow"])}

def _usage_cache_series_entry(realm, state):
    """时间序列状态的 JSON 形态；同上，只写折叠成功过的。

    这一份最大（日桶 + 24 小时子桶 × 保留天数），所以深拷贝只拷桶本身，
    credit 缓冲是 dict 列表、直接浅拷外层。分钟环再压一层：落盘用位置数组
    而不是字典桶（见 _usage_cache_minutes_copy），满环 361 个桶也就 10KB
    量级（本机实测每桶 52 字节），字典形状会平白多出几十 KB。
    """
    offset = state.get("offset") or 0
    tail = state.get("tail")
    if offset <= 0 or not isinstance(tail, bytes):
        return None
    realm_key = _realm_inputs_key(state.get("realm"))
    if realm_key is None:
        return None
    return {"realm": realm, "offset": offset,
            "key": list(state["key"] or (0, 0, 0)), "tail": tail.hex(),
            "realm_inputs": realm_key,
            "days": _usage_cache_days_copy(state.get("days"), _copy_series_day),
            "days_floor": state.get("days_floor"),
            "max_at": state.get("max_at") or 0,
            "credits": [dict(item) for item in (state.get("credits") or [])],
            "minutes": _usage_cache_minutes_copy(state.get("minutes")),
            "minutes_from": state.get("minutes_from"),
            # 闭窗口的边沿账（见 _closed_window_hit_record）：旧版 checkpoint
            # 没有这两个键，采用端因此拒整份、升级后一次性重折。
            "hits": list(state["hits"]),
            "hits_overflow": bool(state["hits_overflow"])}

def _usage_cache_collect_kind(kind):
    """逐把取一类状态，做锁外可序列化的深拷贝；返回 (entries, offset) 或 None。

    每次只取一类：写盘路径按类分别调用，只重写「有推进的那一类」。状态各自
    加锁、各自拷贝，各类之间不强求同一个瞬间：加载端对每份分别校验 offset/
    tail/指纹，一份新一份旧也各自成立。锁是逐把拿、随即放开的，不存在嵌套
    ——写盘路径不能制造「snapshot -> analytics」这样的锁序边。

    entries 为空（状态都归零/不可复现）时返回 None：没得写就不写，等下一次
    折叠成功再落盘。offset 是该类各 realm 状态里的最远位置。
    """
    if kind == "snapshot":
        entries = []
        done = 0
        with _usage_snap_state_lock:
            for realm, state in _usage_snap_state.items():
                entry = _usage_cache_snapshot_entry(realm, state)
                if entry is not None:
                    entries.append(entry)
                    done = max(done, state["offset"])
        return (entries, done) if entries else None
    if kind == "by_account":
        with _byacct_state_lock:
            entry = _usage_cache_by_account_entry(_byacct_state)
            if entry is None:
                return None
            return [entry], _byacct_state["offset"]
    if kind == "analytics":
        entries = []
        done = 0
        with _analytics_state_lock:
            for realm, state in _analytics_state.items():
                entry = _usage_cache_analytics_entry(realm, state)
                if entry is not None:
                    entries.append(entry)
                    done = max(done, state["offset"])
        return (entries, done) if entries else None
    if kind == "series":
        entries = []
        done = 0
        with _series_state_lock:
            for realm, state in _series_state.items():
                entry = _usage_cache_series_entry(realm, state)
                if entry is not None:
                    entries.append(entry)
                    done = max(done, state["offset"])
        return (entries, done) if entries else None
    if kind == "remaining":
        with _remaining_state_lock:
            entry = _usage_cache_remaining_entry(_remaining_state)
            if entry is None:
                return None
            return [entry], entry["offset"]
    return None

def _usage_cache_write_kind(kind, entries):
    """原子写一类状态的 checkpoint：同目录临时文件 + os.replace。

    直接在目标文件上写，崩在中间会留下半份 JSON；加载端虽然能识别（解析失败
    按没有缓存处理），但一份完整的旧文件更省事。不 fsync：这是一份加速件，
    掉电后写坏或丢掉的，加载端一律当没有缓存，不值得为它多刷一次盘。

    不排序键：checkpoint 里 dict 的键顺序就是折叠时的插入顺序（先出现的先
    排），加载回来必须与冷启动逐字节一致——响应的 JSON 字节里键序是可见的，
    而冷启动折叠出的顺序正是这份插入顺序。排序只留给 _object_digest() 那种
    「只要内容一样就算一样」的指纹。

    盘上「本进程还没碰过」的 realm 条目原样保留：一类里按 realm 分条目，
    写盘只重写活跃 realm 的那些；不保留的话，重启后先折的 realm 触发一次写盘
    就会把别的 realm 的旧条目整份清掉，那些 realm 下次请求只能重折（真机
    实测：重启后先请求 realm=all 再请求 realm=cn，cn 重折 15s）。保留的
    条目仍要过加载端的逐条校验，位置/指纹对不上照样被拒——宁可多扫一次。
    """
    if kind in ("snapshot", "analytics", "series"):
        live_realms = {entry.get("realm") for entry in entries}
        with _usage_cache_lock:
            old = _bind__usage_cache_read_kind(kind) or []
        keep = [e for e in old
                if isinstance(e, dict) and e.get("realm") not in live_realms]
        if keep:
            entries = list(entries) + keep
    payload = {"schema": _USAGE_CACHE_SCHEMA, "kind": kind,
               "written_at": time.time(), "entries": entries}
    path = _bind__usage_cache_kind_path(kind)
    tmp = path + ".tmp"
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    try:
        with _open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _usage_cache_maybe_save(kind, offset):
    """一次折叠成功后，按节流阈值决定要不要把「有推进的类」落盘。

    调用点必须在状态锁之外：这里要逐把取状态，在状态锁里再取别的状态锁
    会构成锁序环（snapshot -> analytics 与反向同时存在）。任何异常都吞掉——
    落盘失败只损失一次加速，不能影响这次刷新。

    写盘按类分开（v4）：没推进的类连文件都不重写——旧布局里一份文件装五类，
    任何一类推进都要整份重写；现在单视图进程只重写自己那一类的几十 KB。

    写哪几类：字节阈值到点的类（progress - checkpointed >= min_bytes）里，写
    调用方那一类（它刚折完，状态最新）和真正推进过的类；计时器到点而没有任何
    类到字节阈值时，写所有推进过的类。字节阈值设成 0（测试/探针的强制写）时
    「到点」对所有折过的类都成立，过滤器把没推进过的那些留在原地——旧布局里
    它们的内容与盘上逐字节相同，重写只是写放大。
    """
    if not _usage_cache_enabled():
        return
    try:
        # 串行化整段写盘：两个请求线程可能同时判定「该写」，而临时文件名是
        # 固定的（path + ".tmp"，和 save_runtime_override 一致），两个写者
        # 同时打开同一个临时文件会互相截断。等锁的一方在锁里会重新判定一遍，
        # 第一个写者已经把 checkpointed 推上去，于是它多半直接返回。
        with _usage_cache_write_lock:
            now = time.time()
            with _usage_cache_lock:
                if offset > _usage_cache_progress.get(kind, 0):
                    _usage_cache_progress[kind] = offset
                min_bytes = _usage_cache_min_bytes()
                min_seconds = _usage_cache_min_seconds()
                due_kinds = [k for k in _usage_cache_progress
                             if _usage_cache_progress.get(k, 0)
                             - _usage_cache_checkpointed.get(k, 0) >= min_bytes]
                # 计时器分支只在**确有推进**时才允许触发：进度没动时写出的
                # 是一份与上次逐字节相同的 checkpoint，纯写放大——面板开着
                # 就每 900s 白写一份 120KB（复现见套件 [7]）。空闲重写对
                # 「重启后免冷扫」没有任何贡献，只有日志增长才值得落盘。
                advanced = [k for k in _usage_cache_progress
                            if _usage_cache_progress.get(k, 0)
                            > _usage_cache_checkpointed.get(k, 0)]
                if not due_kinds and (not advanced
                                      or (now - _bind__usage_cache_last_attempt())
                                      < min_seconds):
                    return
                # 记「尝试」而不是「成功」：只读文件系统上失败会一直成立，
                # 不退避的话每次刷新都去试写一遍。
                _set_usage_cache_last_attempt(now)
                write_kinds = [k for k in due_kinds
                               if k == kind or k in advanced] or advanced
            # 某一类收集不出东西（状态归零/归属不可复现）就跳过它：其余类照常
            # 落盘，互不牵连——这是拆文件的意义所在。
            for advanced_kind in write_kinds:
                try:
                    collected = _usage_cache_collect_kind(advanced_kind)
                    if collected is None:
                        continue
                    entries, done = collected
                    _usage_cache_write_kind(advanced_kind, entries)
                except Exception as exc:
                    _log("usage aggregate cache write failed (%s): %s"
                        % (advanced_kind, exc))
                    continue
                with _usage_cache_lock:
                    if done > _usage_cache_checkpointed.get(advanced_kind, 0):
                        _usage_cache_checkpointed[advanced_kind] = done
    except Exception as exc:
        _log("usage aggregate cache write failed: %s" % exc)

def parse_rate_limit_reset(detail):
    """Pull the reset time out of an upstream 429 body, if it names one.

    Upstream answers code 6004 with a reset wall clock, but the wording is
    not fixed: the English form is "... your usage will reset at
    2026-09-19 18:29:03 UTC+8 ...", the Chinese form is "... 将在
    2026-10-09 14:44:59 UTC+8 重置 ...". Matching only the English form left
    every cn 429 without a reset time, so it read as an account-level soft
    limit and cooled the whole credential instead of parking just the
    throttled model. Returns an epoch or None. Kept tolerant on purpose: an
    unparseable body must not break the request path.
    """
    if not detail:
        return None
    m = re.search(r"(?:reset at|将在)\s*"
                  r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})", detail)
    if not m:
        return None
    stamp = m.group(1).replace("T", " ")
    tz = re.search(r"UTC([+-]\d{1,2})(?::?(\d{2}))?", detail)
    offset = 0
    if tz:
        hours = int(tz.group(1))
        minutes = int(tz.group(2) or 0)
        offset = hours * 3600 + (minutes * 60 if hours >= 0 else -minutes * 60)
    try:
        base = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S")) - time.timezone
        return base - offset
    except Exception:
        return None

def _cache_etag(kind, key, built_at):
    """给带 TTL 缓存的只读接口派生一个强校验符（ETag）。

    由 (接口名, 缓存键, 缓存条目的构建时刻) 三者派生，**不是**对响应字节做哈希：

      - 构建时刻在两次重建之间是恒定的，所以"数字没变"的轮询回 304；缓存一重建
        它必然变化，客户端立刻拿到新数据。哈希响应字节恰好相反——payload 里有
        time.time() 派生的字段（/usage 的 started/since、/usage/timeseries 的
        桶边界与 until），同一份缓存被序列化两次都不逐字节相同，tag 会永远不命中，
        每次轮询照样重传 10~100KB，还白搭一次全量序列化 + 哈希的 CPU。
      - (键, 时刻) 都是现成的，一次 sha1 只哈希几十字节的键文本；哈希整个响应体
        则要先把 JSON 序列化出来，在 5 秒一轮的热路径上反而更贵。

    键文本进摘要而不是直接拼进 tag：缓存键里含调用方给的 realm，它可能带引号 /
    反斜杠（`?realm=a"b` 一路原样进键），拼出来会发出一个畸形的 ETag 头；摘要
    则永远是合法的 etagc 字符。摘要只取 16 个十六进制位：它只需要在"同一实例的
    少量缓存条目"之间区分，不是安全边界。
    """
    stamp = "%x" % int(built_at * 1_000_000)
    digest = hashlib.sha1(("%s\x1f%s" % (kind, key)).encode("utf-8")).hexdigest()[:16]
    return '"%s-%s"' % (stamp, digest)


# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_series_credit_entry'] = _series_credit_entry
_BINDINGS['_STATS_TTL'] = _STATS_TTL
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_line_outside_window'] = _line_outside_window
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_line_outside_window_bytes'] = _line_outside_window_bytes
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_recent_backward_page'] = _recent_backward_page
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_recent_index_page'] = _recent_index_page
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_row_cost'] = _row_cost
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_scan_usage_snapshot_window_hours'] = _scan_usage_snapshot_window_hours
_BINDINGS['_scan_usage_snapshot_window_days'] = _scan_usage_snapshot_window_days
_BINDINGS['_scan_usage_snapshot_window'] = _scan_usage_snapshot_window
_BINDINGS['_scan_usage_analytics_window_hours'] = _scan_usage_analytics_window_hours
_BINDINGS['_scan_usage_analytics_window_days'] = _scan_usage_analytics_window_days
_BINDINGS['_scan_usage_analytics_window'] = _scan_usage_analytics_window
_BINDINGS['_fold_usage_snapshot'] = _fold_usage_snapshot
_BINDINGS['_fold_usage_analytics'] = _fold_usage_analytics
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_usage_cache_kind_path'] = _usage_cache_kind_path
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_usage_cache_path'] = _usage_cache_path
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_usage_cache_read_kind'] = _usage_cache_read_kind
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_usage_cache_read_legacy_file'] = _usage_cache_read_legacy_file
# 默认绑定指向真身；ca_proxy bind() 后改走宿主全局（测试可 patch）。
_BINDINGS['_usage_timeseries_scan'] = _usage_timeseries_scan

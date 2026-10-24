#!/usr/bin/env python3
"""CodeArts Agent（华为云码道）-> OpenAI-compatible reverse proxy.
Reuses the credentials the desktop app already stored on this machine
(%%LOCALAPPDATA%%\\CodeBuddyExtension\\Data\\Public\\auth\\*.info), so no separate
login is needed. Exposes:
    GET  /v1/models
    POST /v1/chat/completions     (stream=true and stream=false)
    GET  /health
Only the Python standard library is required.
    python3 ca_proxy.py                    # bind 127.0.0.1:8788
    python3 ca_proxy.py --port 9000
    python3 ca_proxy.py --api-key sk-local # require a bearer token
Launchers: start-codearts-hub.bat / start-codearts-hub-lan.bat on Windows,
start-codearts-hub.command (or ./start-codearts-hub.sh) on macOS/Linux.
"""
import argparse
import bisect
import hashlib
import heapq
import ipaddress
from collections import deque
import re
import json
import os
# 本模块的几个常量在 import 阶段就算出来（下面那段 ca_* 导入之前），所以
# ca_env 必须跟标准库放在一起，不能等 ca_* 那一块再导。
import ca_env
# 单请求体上限。默认值从 50MB 收紧到 16MB，是「内存护栏」：body 先整体读成 bytes、
# 再 decode 成 str、再 json.loads 成对象，实测 50MB body 的 decode+parse 峰值约
# 109MB、单请求峰值约 160MB；而读 body 发生在 chat 信号量 acquire 之前、线程数又
# 没有上限，路由器（可用内存约 480MB）上几个并发大 body 就能把机器打穿。
# 权衡：另一条路是把 body 读取也纳入 chat 信号量，但那会改动 401/404/413 早退与
# 503 的先后语义、并让慢客户端占着 slot 拖住信号量；只收紧默认值保守得多——16MB
# 对正常客户端绰绰有余（Codex 1M token 上下文的 JSON 也只有几 MB），确需更大可
# 显式设 WB_MAX_PAYLOAD_BYTES，内存代价由运维者自己拍板。
MAX_PAYLOAD_BYTES = ca_env.number("WB_MAX_PAYLOAD_BYTES", 16 * 1024 * 1024,
                                  minimum=1024, integer=True)  # 16MB limit
# Upstream chat calls may hold a handler thread for up to 600s, and every
# request gets its own thread, so an unbounded pool lets a handful of slow
# clients pin hundreds of threads and the memory behind them. Bound the number
# of chat/responses requests in flight; dashboard and management calls are not
# affected. Excess callers wait briefly, then get a 503 instead of queueing
# forever.
#
# The ceiling is a fixed 32 by default, which has nothing to do with how many
# accounts the pool holds: a 200-account gateway and a 5-account gateway share
# it. (The old WB_MAX_CONCURRENT_CHAT=auto sizing died with the account pool.)
_CHAT_SLOTS_ENV = os.environ.get("WB_MAX_CONCURRENT_CHAT", "32").strip().lower()
CHAT_SLOTS_AUTO = _CHAT_SLOTS_ENV in ("auto", "pool", "dynamic")
CHAT_SLOTS_FLOOR = 32
try:
    MAX_CONCURRENT_CHAT = CHAT_SLOTS_FLOOR if CHAT_SLOTS_AUTO else int(_CHAT_SLOTS_ENV)
except ValueError:
    MAX_CONCURRENT_CHAT = CHAT_SLOTS_FLOOR
CHAT_SLOT_WAIT_SECONDS = ca_env.number("WB_CHAT_SLOT_WAIT", 30.0,
                                       minimum=0.0, zero_ok=True)

#: 本地拒绝（按 key 并发上限、网关排队满）时给的 Retry-After（秒）。
#:
#: 这类 429/503 不是上游限流，而是**我们自己**的闸：排队的人通常几秒内就
#: 走掉。给 5 秒既不至于让客户端立刻再撞一次，也不会让它按分钟级退避。
LOCAL_RETRY_AFTER_SECONDS = ca_env.number("WB_LOCAL_RETRY_AFTER", 5,
                                          minimum=1, integer=True)
import select
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import ca_activity
import ca_catalog
import ca_codearts
import ca_protocol
import ca_webtools
import ca_stream
import ca_egress
import ca_logstore
import ca_settings

import ca_upstream_pool

# 用量读取/聚合域（2026-10-24 拆出）：实现住 ca_usage，这里 re-export
# 保持 Handler 与测试的 P.<name> 访问不变；bind 的 lambda 在调用时读
# 本模块全局，patch P.ACCOUNTS_DIR / P.log 等仍然生效。
import ca_usage
from ca_usage import (  # noqa: F401 —— re-export
    DEFAULT_REALM,
    KEY_BUCKET_ANON,
    KEY_BUCKET_BEFORE,
    LIMIT_EVENTS_FILE,
    LIMIT_WINDOW_SECONDS,
    USAGE_FIELDS,
    _ANALYTICS_ALL,
    _ANALYTICS_WINDOW,
    _AT_PREFIX,
    _AT_PREFIX_B,
    _CLOSED_WINDOW_HITS_MAX,
    _ESTIMATE_KEEP_DAYS,
    _ESTIMATE_SCHEMA,
    _ESTIMATE_SEGMENT_DAYS,
    _ESTIMATE_WEIGHTS,
    _PERF_REC_LEN,
    _PERF_STATE_MAX,
    _PRICED_FIELDS,
    _REALM_KEY,
    _REALM_KEY_LEN,
    _RECENT_INDEX_REALM_CAP,
    _RECENT_INDEX_REALM_MAX,
    _RECENT_INDEX_SCHEMA,
    _RECENT_INDEX_SEGMENT,
    _REMAINING_KEEP_SECONDS,
    _REMAINING_MAX_EVENTS,
    _ROW_MEMO_MAX,
    _SERIES_CREDITS_KEEP,
    _SERIES_MINUTE_FIELDS,
    _SERIES_MINUTE_RING_CAP,
    _SERIES_MINUTE_WINDOW,
    _STATS_TTL,
    _TAIL_SIGNATURE,
    _USAGE_CACHE_ANALYTICS_NUMBERS,
    _USAGE_CACHE_BUCKET_NUMBERS,
    _USAGE_CACHE_KIND_NAME,
    _USAGE_CACHE_LEGACY_SCHEMA,
    _USAGE_CACHE_LEGACY_UNREAD,
    _USAGE_CACHE_NAME,
    _USAGE_CACHE_SCHEMA,
    _USAGE_CACHE_SERIES_NUMBERS,
    _USAGE_CACHE_SNAPSHOT_MAPS,
    _USAGE_CACHE_SNAPSHOT_NUMBERS,
    _USAGE_DAY_KEEP_DAYS,
    _USAGE_DAY_SNAPSHOT_FIELDS,
    _USAGE_HOUR_KEEP_DAYS,
    _USAGE_HOUR_KEEP_HOURS,
    _ZERO_COST,
    _account_realm_map,
    _add_analytics_models,
    _add_analytics_stat,
    _add_analytics_window_maps,
    _add_usage_bucket,
    _add_usage_snapshot,
    _analytics_all_time,
    _analytics_cache,
    _analytics_hour_bucket,
    _analytics_lock,
    _analytics_row_values,
    _analytics_scope,
    _analytics_state,
    _analytics_state_advance,
    _analytics_state_cold,
    _analytics_state_lock,
    _analytics_state_ready,
    _analytics_window,
    _analytics_window_from_days,
    _analytics_window_from_hours,
    _budget_means,
    _bump_analytics_models,
    _byacct_cache,
    _byacct_lock,
    _byacct_state,
    _byacct_state_lock,
    _cache_etag,
    _cap_anchor,
    _cap_anchors,
    _cap_window_start,
    _closed_window_edge_ok,
    _closed_window_hit_record,
    _copy_analytics_all_time,
    _copy_analytics_models,
    _copy_analytics_window_maps,
    _copy_pricing_record,
    _copy_series_day,
    _copy_snapshot_day,
    _copy_usage_bucket,
    _copy_usage_snapshot,
    _count_usage_line,
    _day_analytics_bucket,
    _day_key_start,
    _day_series_bucket,
    _day_snapshot_bucket,
    _days_cover,
    _drop_events,
    _empty_stats,
    _epoch_or_none,
    _estimate_budget_entry_ok,
    _estimate_daily_cache,
    _estimate_daily_lock,
    _estimate_daily_read,
    _estimate_daily_stamp,
    _estimate_daily_sync,
    _estimate_daily_view,
    _estimate_daily_write,
    _estimate_day_keys,
    _extract_usage,
    _feed_analytics,
    _feed_series_bucket,
    _fold_cost,
    _fold_remaining,
    _fold_usage_analytics,
    _fold_usage_by_account,
    _fold_usage_series,
    _fold_usage_series_minute,
    _fold_usage_snapshot,
    _hour_window_key,
    _hours_cover,
    _hours_floor_on_adopt,
    _line_outside_window,
    _line_outside_window_bytes,
    _local_day_key,
    _local_hour_start,
    _local_midnight,
    _log_complete_frontier,
    _log_offset_holds,
    _log_resume_ok,
    _log_tail_signature,
    _merge_event,
    _new_analytics_hour_bucket,
    _new_analytics_maps,
    _new_analytics_stat,
    _new_series_bucket,
    _new_window_snapshot_bucket,
    _object_digest,
    _pair_append,
    _pair_buffer,
    _pair_repair,
    _pair_trim,
    _perf_apply,
    _perf_at_token,
    _perf_block,
    _perf_cache,
    _perf_drop_oldest,
    _perf_fold,
    _perf_line_entry,
    _perf_lock,
    _perf_new_agg,
    _perf_new_bucket,
    _perf_payload,
    _perf_pop_last,
    _perf_push,
    _perf_put,
    _perf_rebuild,
    _perf_state,
    _perf_stats_incremental,
    _perf_stats_scope,
    _perf_stats_uncached,
    _perf_trim_states,
    _priced_note,
    _pricing_inputs,
    _pricing_record_close,
    _pricing_record_new,
    _pricing_record_ok,
    _pricing_timeline_digest,
    _pricing_timeline_memo,
    _pricing_unchanged,
    _pricing_used_unchanged,
    _prune_day_buckets,
    _prune_hour_buckets,
    _prune_series_minutes,
    _range_sum,
    _range_sum_open,
    _realm_fold_reproducible,
    _realm_inputs,
    _realm_inputs_key,
    _recent_backward_page,
    _recent_index_add_realm,
    _recent_index_adopt,
    _recent_index_blank,
    _recent_index_dirty,
    _recent_index_enabled,
    _recent_index_extend,
    _recent_index_fold_line,
    _recent_index_lock,
    _recent_index_maybe_write,
    _recent_index_min_bytes,
    _recent_index_min_seconds,
    _recent_index_page,
    _recent_index_parse,
    _recent_index_payload,
    _recent_index_read,
    _recent_index_ready,
    _recent_index_realm_map_json,
    _recent_index_realm_name,
    _recent_index_realm_ok,
    _recent_index_restart,
    _recent_index_resume_ok,
    _recent_index_snapshot,
    _recent_index_stamp,
    _recent_index_state,
    _recent_index_total,
    _recent_index_write,
    _remaining_archive_day,
    _remaining_archive_due,
    _remaining_archive_segments,
    _remaining_budgets,
    _remaining_cache,
    _remaining_cache_lock,
    _remaining_payload,
    _remaining_payload_locked,
    _remaining_refresh,
    _remaining_state,
    _remaining_state_lock,
    _row_cost,
    _row_day_memo,
    _row_memo_at,
    _row_memo_env_cap,
    _row_memo_tz,
    _row_memo_tz_changed,
    _scan_daily_usage,
    _scan_usage_analytics_window,
    _scan_usage_analytics_window_days,
    _scan_usage_analytics_window_hours,
    _scan_usage_from,
    _scan_usage_snapshot_window,
    _scan_usage_snapshot_window_days,
    _scan_usage_snapshot_window_hours,
    _series_cache,
    _series_closed_cut_ok,
    _series_credit_entry,
    _series_credit_push,
    _series_lock,
    _series_minute_grid_ok,
    _series_minute_key,
    _series_output_bucket,
    _series_payload,
    _series_slice,
    _series_slice_minutes,
    _series_state,
    _series_state_lock,
    _series_window_day_key,
    _snap_cache,
    _snap_lock,
    _tail_lines,
    _timeline_at_value,
    _timeline_row_at,
    _usage,
    _usage_alltime_snapshot,
    _usage_by_account_buckets,
    _usage_by_account_uncached,
    _usage_cache_adopt_analytics,
    _usage_cache_adopt_by_account,
    _usage_cache_adopt_remaining,
    _usage_cache_adopt_series,
    _usage_cache_adopt_snapshot,
    _usage_cache_analytics_day_ok,
    _usage_cache_analytics_entry,
    _usage_cache_analytics_hours_ok,
    _usage_cache_analytics_ok,
    _usage_cache_analytics_window_ok,
    _usage_cache_bucket_ok,
    _usage_cache_buckets_ok,
    _usage_cache_by_account_entry,
    _usage_cache_checkpointed,
    _usage_cache_collect_kind,
    _usage_cache_counts_ok,
    _usage_cache_credits_ok,
    _usage_cache_day_key_ok,
    _usage_cache_days_copy,
    _usage_cache_days_ok,
    _usage_cache_digest_memo,
    _usage_cache_enabled,
    _usage_cache_fingerprints_ok,
    _usage_cache_forget,
    _usage_cache_hits_ok,
    _usage_cache_int,
    _usage_cache_kind_cache,
    _usage_cache_kind_entries,
    _usage_cache_kind_path,
    _usage_cache_legacy_data,
    _usage_cache_lock,
    _usage_cache_maybe_save,
    _usage_cache_min_bytes,
    _usage_cache_min_seconds,
    _usage_cache_minutes_copy,
    _usage_cache_minutes_state,
    _usage_cache_models_ok,
    _usage_cache_note_adopted,
    _usage_cache_number,
    _usage_cache_path,
    _usage_cache_position_ok,
    _usage_cache_progress,
    _usage_cache_read_kind,
    _usage_cache_read_legacy_file,
    _usage_cache_read_legacy_kind,
    _usage_cache_remaining_entry,
    _usage_cache_remaining_ok,
    _usage_cache_series_bucket_ok,
    _usage_cache_series_entry,
    _usage_cache_series_minutes_ok,
    _usage_cache_snapshot_bucket_ok,
    _usage_cache_snapshot_entry,
    _usage_cache_snapshot_ok,
    _usage_cache_stat_ok,
    _usage_cache_take,
    _usage_cache_write_kind,
    _usage_cache_write_lock,
    _usage_day_bucket,
    _usage_day_buckets_enabled,
    _usage_day_keep_days,
    _usage_hour_bucket,
    _usage_hour_keep_days,
    _usage_hour_keep_hours,
    _usage_keep_setting,
    _usage_log_key,
    _usage_series_state_ready,
    _usage_snap_state,
    _usage_snap_state_advance,
    _usage_snap_state_cold,
    _usage_snap_state_lock,
    _usage_snap_state_ready,
    _usage_snapshot_scope,
    _usage_snapshot_uncached,
    _usage_snapshot_window,
    _usage_snapshot_window_from_days,
    _usage_snapshot_window_from_hours,
    _usage_timeseries_scan,
    _usage_timeseries_scope,
    _usage_timeseries_uncached,
    _window_day_key,
    _window_day_key_safe,
    _window_hour_aligned,
    _window_hour_key_safe,
    _window_sample,
    detect_model_realm,
    match_realm,
    normalize_realm,
    parse_rate_limit_reset,
    range_window,
    realm_scope,
    row_matches_realm,
    row_outcome,
    row_realm,
    usage_analytics_etag,
    usage_by_account,
    usage_by_account_etag,
    usage_snapshot,
    usage_snapshot_etag,
    usage_timeseries,
    usage_timeseries_etag,
)
ca_usage.bind(
    log=lambda *a, **k: log(*a, **k),
    accounts_dir=lambda: ACCOUNTS_DIR,
    usage_dir=lambda: USAGE_DIR,
    usage_log=lambda: USAGE_LOG,
    current_realm=lambda: CURRENT_REALM,
    open=lambda *a, **k: open(*a, **k),
    _series_credit_entry=lambda *a, **k: _series_credit_entry(*a, **k),
    _STATS_TTL=lambda: _STATS_TTL,
    _line_outside_window=lambda *a, **k: _line_outside_window(*a, **k),
    _line_outside_window_bytes=lambda *a, **k: _line_outside_window_bytes(*a, **k),
    _recent_backward_page=lambda *a, **k: _recent_backward_page(*a, **k),
    _recent_index_page=lambda *a, **k: _recent_index_page(*a, **k),
    _row_cost=lambda *a, **k: _row_cost(*a, **k),
    _scan_usage_snapshot_window=lambda *a, **k: _scan_usage_snapshot_window(*a, **k),
    _scan_usage_snapshot_window_days=lambda *a, **k: _scan_usage_snapshot_window_days(*a, **k),
    _scan_usage_snapshot_window_hours=lambda *a, **k: _scan_usage_snapshot_window_hours(*a, **k),
    _scan_usage_analytics_window=lambda *a, **k: _scan_usage_analytics_window(*a, **k),
    _scan_usage_analytics_window_days=lambda *a, **k: _scan_usage_analytics_window_days(*a, **k),
    _scan_usage_analytics_window_hours=lambda *a, **k: _scan_usage_analytics_window_hours(*a, **k),
    _fold_usage_snapshot=lambda *a, **k: _fold_usage_snapshot(*a, **k),
    _fold_usage_analytics=lambda *a, **k: _fold_usage_analytics(*a, **k),
    _usage_cache_kind_path=lambda *a, **k: _usage_cache_kind_path(*a, **k),
    usage_cache_last_attempt=lambda: _usage_cache_last_attempt,
    _set_usage_cache_last_attempt=lambda v: globals().__setitem__(
        "_usage_cache_last_attempt", v),
    _usage_cache_path=lambda *a, **k: _usage_cache_path(*a, **k),
    _usage_cache_read_kind=lambda *a, **k: _usage_cache_read_kind(*a, **k),
    _usage_cache_read_legacy_file=lambda *a, **k: _usage_cache_read_legacy_file(*a, **k),
    _usage_timeseries_scan=lambda *a, **k: _usage_timeseries_scan(*a, **k),
)
import ca_prompt
import ca_modelsdev
import ca_probes
import ca_updates
IS_WINDOWS = os.name == "nt"


def launcher_hint(port):
    """Platform-appropriate launcher command for starting on another port."""
    if IS_WINDOWS:
        return "start-codearts-hub.bat %d" % port
    return "./start-codearts-hub.sh %d" % port
def port_owner_hint(port):
    """Command that lists the process holding a local TCP port."""
    if IS_WINDOWS:
        return "netstat -ano | findstr :%d" % port
    return "lsof -nP -iTCP:%d -sTCP:LISTEN" % port
#: 当前生效的上游出口。WorkBuddy 账号池与国际版都已移除，网关只服务码道，
#: 所以出口名就是 ``codearts``。
#:
#: 环境变量保留：现场调试时仍可以强制成别的名字（比如灰度一套新出口），但
#: 认不出来的值一律归一到 ``codearts``。
CURRENT_REALM = ca_env.text("WB_PROXY_DEFAULT_REALM", "codearts").lower()
#: 唯一还存在的出口。用量行里的 ``realm`` 字段写的就是它。
#:
#: 以前这里写的是 ``cn`` —— 那是 WorkBuddy 账号池时代「国内版」出口的名字。
#: 账号池删掉之后，码道请求的每一行仍然被贴着 ``cn``，面板上看到的也是
#: 「国内版 (China)」，与实际在跑的上游对不上。现在统一成 ``codearts``，
#: ``cn`` / ``intl`` 只作为**历史行**的别名存在（见 normalize_realm）。


# 这里原来有一份 CN_EXCLUSIVE 清单和 exclusive_realm()：国际版移除后它们
# 没有任何调用点（模型到出口的映射已在 detect_model_realm 里恒等于
# CURRENT_REALM），删掉以免有人以为改清单能改行为。
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


#: 正在处理的请求数。优雅退出的等待条件：它归零（或者等满超时）。
_INFLIGHT_REQUESTS = {"count": 0}
_INFLIGHT_LOCK = threading.Lock()
#: 收到 SIGTERM 之后不再接新请求（监听 socket 上来的立即回 503）。
_SHUTTING_DOWN = {"flag": False}
#: 收尾线程句柄（只允许一个，见 install_sigterm_handler）。
_DRAIN_THREAD = {"thread": None}


def running_in_container():
    """是不是跑在容器里（docker / podman）。

    退出预算要跟着这个变：``docker stop`` 默认给 SIGTERM 之后 **10 秒**就
    SIGKILL，比宿主机上 systemd 的 90 秒短得多。沿用 25 秒的 grace 就必然
    在收尾做到一半时被 SIGKILL —— 那正是这轮要修的东西（进程说没就没，
    在跑的请求既没有错误记录也没有用量记录）。
    """
    return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


#: SIGTERM 之后最多等在跑的请求这么久，然后强制退出。
#:
#: 25 秒是宿主机上的默认值：短于「客户端自己的超时」，又长于一次正常的收尾
#: （写完 [DONE] + 一次 6 秒的 idle）。
#:
#: **容器里默认 8 秒**：要留出余量在 docker 的 10 秒 SIGKILL 之前自己走完
#: 收尾。想等更久就用 compose 的 ``stop_grace_period`` 配合
#: ``CODEARTS_SHUTDOWN_GRACE`` 一起放大（两个都要，只放一个没用）。
SHUTDOWN_GRACE_SECONDS = ca_env.number(
    "CODEARTS_SHUTDOWN_GRACE",
    8.0 if running_in_container() else 25.0,
    minimum=0.0, zero_ok=True)


def request_started():
    with _INFLIGHT_LOCK:
        _INFLIGHT_REQUESTS["count"] += 1


def request_finished():
    with _INFLIGHT_LOCK:
        if _INFLIGHT_REQUESTS["count"] > 0:
            _INFLIGHT_REQUESTS["count"] -= 1


def inflight_requests():
    with _INFLIGHT_LOCK:
        return _INFLIGHT_REQUESTS["count"]


def begin_shutdown():
    _SHUTTING_DOWN["flag"] = True


def shutting_down():
    return bool(_SHUTTING_DOWN["flag"])


def install_console_close_handler():
    """Release the port when the console window is closed by the user.
    Windows does not kill child processes when a console window closes, so
    the proxy (started by the .bat as a child of cmd.exe) would survive and
    keep the port bound - the next launch then wrongly reports "another
    proxy is already running".
    Closing the window raises CTRL_CLOSE_EVENT in every process attached to
    that console, which is exactly the signal we want. Registering a handler
    for it is event-driven, so unlike polling a parent pid there is no
    chance of a false positive. Harmless when started without a console.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        CTRL_CLOSE_EVENT = 2
        CTRL_LOGOFF_EVENT = 5
        CTRL_SHUTDOWN_EVENT = 6
        def _handler(event):
            if event in (CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT):
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
                os._exit(0)
            return False
        handler = PHANDLER_ROUTINE(_handler)   # keep the callback referenced
        if not ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True):
            return None
        return handler
    except Exception:
        return None


def wait_for_inflight(grace=None):
    """等在跑的请求结束，**最多** grace 秒。返回仍未结束的条数。

    为什么必须等：``systemctl restart`` / ``docker stop`` 默认给 SIGTERM，
    然后 10 秒后 SIGKILL。不处理 SIGTERM 就是「进程说没就没」—— 在跑的请求
    既没有错误记录也没有用量记录（10-23 有 6 个请求就是这么消失的），
    ``finally`` 里的 idle 也发不出去，上游那几条会话一直挂着占名额
    （10-22 每次重启后跟着一串 TM.00001041 就是这么来的）。

    25 秒是刻意选的（宿主机）：短于「客户端自己的超时」，又长于一次正常的
    收尾（写完 [DONE] + 一次 6 秒的 idle）。容器里默认值见
    ``SHUTDOWN_GRACE_SECONDS``：docker 只给 10 秒。
    """
    grace = SHUTDOWN_GRACE_SECONDS if grace is None else grace
    deadline = time.time() + max(0.0, float(grace))
    while inflight_requests() > 0 and time.time() < deadline:
        time.sleep(0.1)
    return inflight_requests()


def _run_bounded(fn, seconds, name):
    """跑 fn，最多等 seconds 秒。超时就把它丢在后台（daemon），自己不阻塞。

    收尾动作（补发 idle）里有网络调用，单条最坏 6 秒。总预算被
    ``SHUTDOWN_GRACE_SECONDS`` 钉死，所以这里必须能放弃 —— 与其为了收尾把
    进程拖过 SIGKILL 线（那样连自己刚写的日志都会被截断），不如把没做完的
    留给下一次启动的 reap（它本来就幂等）。
    """
    if seconds <= 0.05:
        return False
    done = threading.Event()

    def _target():
        try:
            fn()
        except Exception as exc:            # noqa: BLE001
            log("shutdown: %s failed: %r" % (name, exc))
        finally:
            done.set()

    threading.Thread(target=_target, name="shutdown-" + name, daemon=True).start()
    return done.wait(seconds)


def install_sigterm_handler(server, on_shutdown=None):
    """SIGTERM → 停止接新请求、等在跑的收尾、补发 idle。

    **信号处理器里只做「点灯 + 起线程」**（2026-10-23）。以前它自己在主线程
    里等满 25 秒：那段时间主线程不跑 accept 循环，注释里承诺的「新连接拿
    503」根本没人应答（连接堆在 backlog 里，进程退出时被 RST）；第二次
    Ctrl+C 落在同一个处理器上，被 `shutting_down()` 直接 return 吞掉，只能
    等 grace 走完。

    现在的分工：
      · 处理器：置位、起一个收尾线程（第一次），第二次信号立刻退出；
      · 收尾线程：等在跑的请求跑完（此时主线程仍在 accept，新连接收 503）
        → 停 accept（``server.shutdown()`` 必须在别的线程调）→ 补发 idle；
      · 主线程：``serve_forever()`` 返回后 join 收尾线程再关 socket。

    返回注册好的 handler（调用方要持有引用，不然可能被回收）。
    Windows 上 SIGTERM 一般来自 ``os.kill`` / 服务管理器；``signal.signal``
    照样支持，所以这里不区分平台。
    """
    def _drain():
        grace = SHUTDOWN_GRACE_SECONDS
        # 预算分两段：先让在跑的请求自己收尾（它们会写账、发 idle），再补一遍
        # 登记表里剩下的会话。给补发留 1/4（至少 1 秒），其余给请求。
        reserve = min(max(1.0, grace * 0.25), grace)
        left = wait_for_inflight(max(0.0, grace - reserve))
        if left:
            log("shutdown: %d request(s) still running after %.0fs; "
                "their sessions will be reaped on next start"
                % (left, max(0.0, grace - reserve)))
        # 先停 accept：这之后 serve_forever 返回，主线程 join 本线程再关 socket。
        # shutdown() 会阻塞到 serve_forever 退出，所以只能在这里（另一个线程）调。
        try:
            server.shutdown()
        except Exception:
            pass
        if on_shutdown is not None:
            remaining = max(1.0, grace * 0.25)
            if not _run_bounded(on_shutdown, remaining, "cleanup"):
                log("shutdown: cleanup did not finish within %.0fs; "
                    "leftover sessions will be reaped on next start" % remaining)
        log("shutdown: bye")

    def _handler(_signum, _frame):
        if shutting_down():
            # 第二次 Ctrl+C / 第二次 SIGTERM：不再等，直接走。用户已经表达了
            # 「别磨了」，继续拖只会让终端卡在那儿。
            log("shutdown: second signal - exiting now, %d request(s) abandoned"
                % inflight_requests())
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(1)
        begin_shutdown()
        log("shutdown: signal %s received, draining %d request(s), grace %.0fs"
            % (_signum, inflight_requests(), SHUTDOWN_GRACE_SECONDS))
        thread = threading.Thread(target=_drain, name="shutdown-drain")
        # 非 daemon：主线程退出解释器时会等它，收尾一定能走完（在 grace 内）。
        thread.daemon = False
        thread.start()
        _DRAIN_THREAD["thread"] = thread

    try:
        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError) as exc:
        log("shutdown: cannot install signal handler: %r" % (exc,))
        return None
    return _handler


# WorkBuddy 上游的地址常量（UPSTREAM / CHAT_PATH / MODELS_PATH）随账号池一起
# 删除：网关现在只有码道一条上游，留着它们只会让人以为还有第二条路。
DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant."

# ---------------------------------------------------------------------------
# Background-model redirection (desktop clients).
#
# A desktop client's model picker only governs the MAIN chat thread. Its
# built-in "model routing config" (codex-apps/protocol/src/model-routing-config.ts)
# sends background work - memory generation, ambient suggestions, ephemeral
# generation, automations - to its own hard-coded models. Those requests hit
# this gateway on the same key as normal traffic, so they keep burning paid
# credits even when a free model is selected in the UI.
#
# Rewrite them to a free target so the client features keep working without
# spending credits. Override without editing code:
#   WB_BACKGROUND_MODEL_NAMES="gpt-5.6-terra,gpt-5.6-luna,gpt-5.3-codex"
#   WB_BACKGROUND_MODEL_TARGET="deepseek-v4.1-flash"
# ---------------------------------------------------------------------------
BACKGROUND_MODEL_TARGET = os.environ.get("WB_BACKGROUND_MODEL_TARGET", "deepseek-v4.1-flash")
BACKGROUND_MODEL_NAMES = tuple(
    m.strip().lower()
    for m in os.environ.get(
        "WB_BACKGROUND_MODEL_NAMES",
        "gpt-5.6-terra,gpt-5.6-luna,gpt-5.3-codex",
    ).split(",")
    if m.strip()
)


def _apply_background_model_alias(payload):
    """Rewrite known client background-task models to a free target model."""
    if not isinstance(payload, dict):
        return
    name = payload.get("model")
    if not isinstance(name, str):
        return
    if name.strip().lower() not in BACKGROUND_MODEL_NAMES:
        return
    payload["model"] = BACKGROUND_MODEL_TARGET
    log("alias: background model %s -> %s" % (name, BACKGROUND_MODEL_TARGET))
class BodyTooLarge(Exception):
    """Raised when a request body exceeds the configured cap."""
    def __init__(self, length):
        super(BodyTooLarge, self).__init__(length)
        self.length = length
class BadJSON(Exception):
    """Raised when a request body is present but not a JSON object."""
# CORS is only needed by browser-based chat clients that call the OpenAI-style
# API from another origin. Management routes (accounts, settings, usage,
# panel) serve the dashboard, which is same-origin, so they get no
# ACAO header - that keeps a stray page on the LAN from reading their replies.
CORS_PATH_PREFIXES = ("/v1", "/chat", "/completions", "/models", "/responses")
# Management paths that happen to live under /v1 must not be treated as API:
# /v1/usage reports account-level spend and is gated by the panel session.
MANAGEMENT_PATH_PREFIXES = ("/v1/usage", "/usage", "/accounts", "/settings",
                            "/panel", "/logs")
def cors_origin_allowed(path):
    """True when the OpenAI-style API path should advertise CORS."""
    path = (path or "").split("?")[0]
    if path.startswith(MANAGEMENT_PATH_PREFIXES):
        return False
    return path.startswith(CORS_PATH_PREFIXES)
_lock = threading.Lock()
_login_lock = threading.Lock()
_chat_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHAT)

#: 「响应已经发出去了」的哨兵。`_error` / `_anthropic_error` 返回它，让
#: 「返回 (error, result)」形态的调用方能用 `if error is not None` 判出
#: 「已回过响应、不要再碰 result」。见 _error 的注释。
RESPONDED = object()
_login_attempts = {}  # ip -> list of timestamp
def _prune_login_attempts(now=None, window=60):
    """Drop stale per-IP entries so the dict cannot grow without bound.
    Caller must hold _login_lock.
    """
    now = now or time.time()
    for ip in list(_login_attempts.keys()):
        recent = [t for t in _login_attempts[ip] if now - t < window]
        if recent:
            _login_attempts[ip] = recent
        else:
            del _login_attempts[ip]
# --------------------------------------------------- 面板登录限流的来源判定
# 限流按「客户端 IP」分桶（每 IP 5 次失败 / 60 秒），但反代部署下 socket 对端
# 永远不是真实客户端：路由器上 nginx 把 ai.home 转给 127.0.0.1:8788，所有请求
# 的对端都是 127.0.0.1。若照旧拿对端地址当键，任意一个人连错 5 次密码，就会把
# 所有经反代的用户、连同跑在同一台机器上的缓存预热器一起锁死 60 秒——实测里
# 预热器被 429 打掉后直接打印"登录失败（http=429），跳过本轮"，缓存转冷，
# 用户点开统计页要付一次全表扫描。所以键要取「真实来源」，且只在对端可信时
# 才读代理头：对端是回环地址（本机代理）或显式列进 WB_TRUSTED_PROXIES 的代理
# 时，按 X-Real-IP（优先）或 X-Forwarded-For 的第一个地址分桶；其余对端一律
# 忽略这两个头、仍按对端地址分桶——公网客户端不能靠伪造头换个桶绕过限流。
def parse_trusted_proxies(raw):
    """解析 WB_TRUSTED_PROXIES：逗号分隔的 IP 或 CIDR（如 10.0.0.1,fd00::/8）。
    解析不了的条目直接丢弃：一个笔误不该让网关起不来。
    """
    entries = []
    for item in str(raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            entries.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(entries)
TRUSTED_PROXIES = parse_trusted_proxies(os.environ.get("WB_TRUSTED_PROXIES", ""))
def peer_is_trusted(peer_ip):
    """对端是否有资格代表它的客户端说话：回环（本机反代）或显式配置的代理。"""
    try:
        addr = ipaddress.ip_address(str(peer_ip))
    except ValueError:
        return False
    # Windows 双栈下连 127.0.0.1 的对端会显示成 ::ffff:127.0.0.1。ipaddress 在
    # Python 3.13 之前不把 IPv4-mapped 地址算作回环（.is_loopback 为 False），
    # 于是本机反代的请求会被当成不可信来源，限流桶退化成所有客户端共用一个。
    mapped = addr.ipv4_mapped if addr.version == 6 else None
    if addr.is_loopback or (mapped is not None and mapped.is_loopback):
        return True
    for net in TRUSTED_PROXIES:
        if addr.version == net.version and addr in net:
            return True
    return False
_PROXY_HEADER_IP_MAX = 64  # 最长的 IPv6 文本也到不了 46 字符，再长就是垃圾
def _proxy_header_ip(value):
    """从代理头里取一个合法 IP 的规范文本；取不到返回 None（绝不抛异常）。

    接受裸 IPv4/IPv6，也接受 nginx 变体可能写出的 host:port / [v6]:port；
    多值（含逗号）、超长、其余畸形串一律判为不可用，由调用方决定回退。
    """
    text = str(value or "").strip()
    if not text or len(text) > _PROXY_HEADER_IP_MAX or "," in text:
        return None
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1:
        # v4:port 形式；裸 IPv6 至少两个冒号，不会被这里截断
        host, _, port = text.partition(":")
        if port.isdigit():
            text = host
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None
def login_rate_limit_key(peer_ip, headers):
    """限流键：对端可信时取代理头里的真实客户端 IP，否则取对端地址。

    X-Real-IP 优先（nginx 里放的就是真实来源），其次 X-Forwarded-For 的
    第一个（链上最左是最初的客户端）。头不可用就退回对端地址：宁可让经
    反代的客户端共用一个桶（退化为旧行为），也不能拿解析不出来的串当键。

    **前面还有 Cloudflare 时**：nginx 写的 ``$remote_addr`` 是 CF 边缘节点，
    所有用户会缩到少数几个出口 IP 共用一个桶，限速就会误伤正常用户。正确
    做法在 nginx 侧，不是在这里放宽：配 ``set_real_ip_from``（CF 的段）+
    ``real_ip_header CF-Connecting-IP``，nginx 会把 ``$remote_addr`` 改成真实
    客户端地址，这个函数拿到的 X-Real-IP 自然就是对的。不要改成「直接信
    CF-Connecting-IP」—— 那个头客户端能自己写，nginx 默认原样转发，等于把
    限流键交给攻击者任意选择。
    """
    if not peer_is_trusted(peer_ip):
        return peer_ip
    real = _proxy_header_ip(headers.get("X-Real-IP") if headers else None)
    if real:
        return real
    forwarded = (headers.get("X-Forwarded-For") if headers else None) or ""
    first = forwarded.split(",")[0]
    via_chain = _proxy_header_ip(first)
    if via_chain:
        return via_chain
    return peer_ip
_models_cache = {DEFAULT_REALM: {"at": 0.0, "data": None}}
#: 目录来源追踪（面板展示用）：每个 realm 最近一次构建/刷新清单的出处。
#: source 取值见 catalog_meta()；fetched_at 是网关拿到这批数据的时刻；
#: file_mtime 是桌面缓存文件自己的写入时刻（仅配置文件来源，可能远早于
#: fetched_at——那正是「清单是不是新鲜」的证据）。与 _models_cache 同批更新。
_catalog_meta = {}
# Usage accounting: every upstream response carries a usage block, and the
# proxy also records one JSONL line per request. Defaults to a folder next to
# this script; override with --usage-dir or WB_PROXY_USAGE_DIR.
USAGE_DIR = os.environ.get("WB_PROXY_USAGE_DIR") \
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage")
USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
_usage_cache_last_attempt = time.time()
DASHBOARD_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
# Web-panel access control. The panel is gated by its own password (default
# "admin"), independent of the /v1 API key. Sessions live in memory only, so a
# restart forces browsers to log in again.
PANEL = ca_settings.PanelSessions()
API_KEY_FILE_SET = False
def configured_keys():
    """Panel-managed API keys, always read fresh so panel edits apply at once."""
    try:
        return ca_settings.api_keys(ACCOUNTS_DIR)
    except Exception as exc:
        # **读不出来不等于没有 key**：返回空表会让 auth_required() 落到
        # 「launcher 兜底」甚至「不需要 key」。所以这里让异常继续上抛给
        # auth_required()，由它 fail closed。
        log("could not read api keys: %s" % exc)
        raise
def panel_keys_configured():
    """True once the panel has held a key (live, disabled, or deleted).

    The launcher fallback exists for deployments whose panel was never
    configured. Counting deleted rows here keeps removing the last key from
    reviving that fallback - and from turning the gateway into an open relay.
    """
    try:
        if ca_settings.api_keys(ACCOUNTS_DIR, include_deleted=True):
            return True
        return bool(ca_settings.api_key_override(ACCOUNTS_DIR)[1])
    except Exception as exc:
        log("could not read api key history: %s" % exc)
        return True
def auth_required():
    """Whether /v1 calls must present a key at all.

    **配置文件读不出来时 fail closed**（2026-10-23）：``ca_settings.load`` 在
    解析失败时返回空 dict，而空 dict 的语义是「全新安装、没配过」，于是
    一次磁盘抖动 / 半截写入就把 API key 检查整条关掉 —— 变成一个谁都能用
    的开源网关。同样的空结果还会按 (mtime, size) 缓存，故障过去之后只要文件
    没变就一直是关的。现在读失败一律当成「必须验 key」。

    判据必须是 ``load()`` **这一次**的结果：``configured_keys()`` 会先读一次
    配置，读完 ``last_load_error()`` 反映的就是本次读盘的结果。
    """
    try:
        keys = configured_keys()
    except Exception:
        # 读 key 表本身就抛了：当成「有 key、必须验」。
        return True
    if ca_settings.last_load_error():
        return True
    if ca_settings.auth_disabled(ACCOUNTS_DIR):
        return False
    # Any stored row counts, enabled or not: disabling a key must not switch
    # checking off. Turning auth off is the explicit auth_disabled toggle.
    if keys:
        return True
    # Every row was deleted: fail closed until the panel gets a key again.
    if panel_keys_configured():
        return True
    return bool(API_KEY)
def identify_key(supplied):
    """Return the key entry a caller used, or None when nothing matches.
    Once the panel has ever held a key, those keys are the only accepted
    credentials - otherwise a launcher key left in a .bat file would silently
    keep working after the panel was locked down, and deleting the last panel
    key would bring that launcher key back.
    """
    extra = () if panel_keys_configured() else (API_KEY,)
    return ca_settings.match_api_key(ACCOUNTS_DIR, supplied, extra_keys=extra)
# 进程启动时刻。快照的 "started"/"since" 从这里取（_usage_snapshot_uncached
# 是它唯一的读者）；requests/ttft/by_model 那些累计字段没有任何读者——每个
# 聚合都重读 usage.jsonl——所以请求路径不再维护它们。


def range_query(query):
    """Pull the three range parameters out of a parsed query string.

    parse_qs hands every key back as a list, and an older panel that sends
    none of them at all is the normal case, so every lookup falls back to
    None - which range_window() reads as "no filter on that side".
    """
    def first(name):
        values = query.get(name) or [None]
        return values[0] if values else None
    return first("range"), first("since"), first("until")
def record_usage(model, usage, stream=None, elapsed_ms=None, ttft_ms=None, gen_ms=None, fp=None,
                account=None, outcome="completed", key=None, effort=None,
                requested_model=None):
    """Record one finished request as exactly one JSONL row.

    A request without a usage block still gets a row (flagged usage_missing):
    skipping it entirely used to drop the request from the request count,
    success rate and latency samples, not just from the token totals.

    outcome is the terminal state: completed / client_aborted /
    upstream_aborted / failed. It is deliberately not called status, because
    status already means the HTTP status code on error rows.

    key is the settings id of the client API key that paid for the request,
    never the secret itself. It is passed in explicitly rather than read from
    a thread-local: one keep-alive thread serves many requests, so an implicit
    channel would attribute spend to the wrong key silently, while a missed
    call site only shows up as an extra "no key" row.

    effort is the reasoning effort the request actually ran at, as resolved by
    build_upstream_body(). It is written only when the model has one: a model
    without reasoning controls has nothing to report, and rows written before
    this field existed cannot be told apart from it anyway.
    """
    # 模型健康熔断的成败记账（官方 smart-router 的对应物）：完整跑完一轮
    # 就是这个模型的成功信号，连败计数清零。
    if outcome == "completed":
        note_model_result(model, True)
    fields = _extract_usage(usage) or {}
    usage_missing = not fields
    # 积分：上游不按请求返回扣了多少，用码道自己的计费档按公式算
    #（公式来自本机客户端的 calculateTurnCredits：价×token/1e6/倍率）。
    # 拿不到该模型档位（免费/未定价）就不写，保持 0 而不是编一个数。
    if not fields.get("credit"):
        estimated = ca_codearts.credit_for_usage(
            model, fields.get("prompt_tokens"), fields.get("cached_tokens"),
            fields.get("completion_tokens"))
        if estimated:
            fields["credit"] = estimated
    row = {
        "at": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "stream": bool(stream),
        "outcome": outcome,
        "elapsed_ms": elapsed_ms,
        "ttft_ms": ttft_ms,
        "gen_ms": gen_ms,
    }
    if requested_model and requested_model != model:
        row["requested_model"] = requested_model
    if usage_missing:
        row["usage_missing"] = True
    row.update(fields)
    if fp:
        row.update(fp)
    if account:
        row["account"] = account
    # 账号池已移除：行上的 realm 一律是唯一那个出口。
    row["realm"] = normalize_realm(CURRENT_REALM)
    # Always written, even when the caller presented no key. The empty value is
    # what separates "ran without a key" from rows written before the field
    # existed; the dashboard reports those as two different buckets, and a
    # missing field is the only evidence of the cutover that survives.
    row["key"] = key or ""
    # 价格策略引用。价格估算体系已下线，字段保留为空串（历史行里可能有值，
    # 读取侧一律不依赖它）。
    row["cost_policy"] = ""
    # Only when the request had one: the panel shows a chip for rows that carry
    # the field, and a model without reasoning controls has nothing to report.
    if effort:
        row["reasoning_effort"] = effort
    # Derived per-request rates (None-safe).
    if gen_ms and gen_ms > 0:
        row["tokens_per_sec"] = round(fields.get("completion_tokens", 0) / (gen_ms / 1000.0), 2)
    # Share the denominator with the aggregate view (compute_usage_analytics),
    # otherwise the per-request row and the rollup disagree on the same data.
    if fields.get("prompt_tokens", 0) > 0:
        row["cache_hit_pct"] = round(fields.get("cached_tokens", 0) * 100.0
                                     / fields["prompt_tokens"], 1)
    _persist_usage(row, "usage persist failed")
    try:
        t_tokens = fields.get("total_tokens", 0)
        dur = f" {elapsed_ms:.0f}ms" if elapsed_ms is not None else ""
        acc_tag = f" acct={account[:8]}" if account else ""
        speed_tag = f" {row.get('tokens_per_sec', 0)}t/s" if row.get("tokens_per_sec") else ""
        miss_tag = " usage=missing" if usage_missing else ""
        log(f"chat done: model={model}{acc_tag}{dur} tokens={t_tokens} (in={fields.get('prompt_tokens',0)} out={fields.get('completion_tokens',0)}){speed_tag}{miss_tag}", tag="chat")
    except Exception:
        pass
    return row


def _persist_usage(row, fail_label):
    """Append one usage row as a JSONL line.

    usage-summary.json used to be rewritten on every single request - a full
    json.dumps of the running totals, a uniquely named temp file and an
    os.replace, plus the deep copy that fed it. Nothing in the tree ever
    loads that file (every aggregate re-reads usage.jsonl), so the work was
    pure overhead on the request path. One append per request now.
    """
    try:
        os.makedirs(USAGE_DIR, exist_ok=True)
        with open(USAGE_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception as exc:
        log("%s: %s" % (fail_label, exc))

def record_error(model, status, message, elapsed_ms=None, account=None,
                 usage=None, stream=None, ttft_ms=None, gen_ms=None, fp=None,
                 outcome="failed", key=None):
    """Record one failed request as exactly one JSONL row.

    Passing the account uid records which account the request was bound to, so
    per-realm success rates attribute the failure by fact instead of falling
    back to guessing from the model name.

    The usage argument carries whatever the upstream had already reported when
    a stream broke. An aborted stream used to write an error row AND a usage
    row, so one request counted as both a failure and a success; the token
    totals stay accurate here without inflating the request count.

    status stays the HTTP status code; outcome is the terminal state, so the
    two never disagree about what the field means.

    key is the client API key's settings id, same as record_usage. It is the
    only way a rejected request can be attributed to a key, so failures on the
    key's model whitelist still land on the right row instead of vanishing
    into the unattributed bucket.
    """
    # 健康熔断：只有 5xx / 上游中断 / 0203 算模型失败；限流与参数错不算。
    if _health_counts_failure(status, message, outcome):
        note_model_result(model, False)
    fields = _extract_usage(usage) or {}
    row = {
        "at": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "error": True,
        "outcome": outcome,
        "status": status,
        "message": str(message)[:200],
        "elapsed_ms": elapsed_ms,
    }
    if stream is not None:
        row["stream"] = bool(stream)
    if ttft_ms is not None:
        row["ttft_ms"] = ttft_ms
    if gen_ms is not None:
        row["gen_ms"] = gen_ms
    row.update(fields)
    if fp:
        row.update(fp)
    if account:
        row["account"] = account
        row["realm"] = normalize_realm(CURRENT_REALM)
    row["key"] = key or ""
    _persist_usage(row, "error persist failed")
    dur = f" {elapsed_ms:.0f}ms" if elapsed_ms is not None else ""
    # 账号与终态也带上看板日志。上面那段本来就把 account 写进了 JSONL，但日志
    # 行一直没打出来——出错时最想知道的「哪个账号、什么终态」反而要回去翻
    # usage.jsonl，而 chat done 那条早就有 acct= 了，两侧不对称。
    acc_tag = f" acct={account[:8]}" if account else ""
    log(f"request error: model={model}{dur}{acc_tag} status={status} outcome={outcome} msg={str(message)[:180]}",
        level="ERROR", tag="chat")
    return row
def perf_stats(sample=5000, realm=None, ttl=None, range=None, since=None, until=None):
    """Cached wrapper: parsing thousands of rows is CPU-heavy, and the
    dashboard polls this endpoint every few seconds.

    Rebuilds under the lock so a burst of pollers cannot each start their own
    scan of the log. The rebuild itself is incremental: _perf_stats_incremental
    keeps a ring of the last `sample` rows per (sample, realm, window) key and
    only folds the bytes appended since the last rebuild (see there)."""
    ttl = _STATS_TTL if ttl is None else ttl
    r, lo, hi, key = _perf_stats_scope(sample, realm, range, since, until)
    now = time.time()
    with _perf_lock:
        hit = _perf_cache.get(key)
        if hit is not None and (now - hit[0]) < ttl:
            return hit[1]
        data = _perf_stats_incremental(key, key[0], r, lo, hi)
        _perf_cache[key] = (time.time(), data)
    return data


def perf_stats_etag(sample=5000, realm=None, range=None, since=None, until=None):
    """perf_stats() 当前缓存条目的 ETag；条目还不存在时返回 None。

    _json_cached() 会在取数前后各调用一次并比对，两次一致才把 tag 发出去
    （见那里的注释）。所以这里只回答"此刻这条缓存条目的戳是什么"，调用方不需要
    自己安排调用顺序。
    """
    _r, _lo, _hi, key = _perf_stats_scope(sample, realm, range, since, until)
    with _perf_lock:
        hit = _perf_cache.get(key)
    if hit is None:
        return None
    return _cache_etag("perf", repr(key), hit[0])


# ---------------------------------------------------------------------------
# perf 的增量样本（T2）
#
# perf_stats 每次重建都要重读日志末尾 sample 行、逐行 json.loads、把每一行的
# 五个数值往全局与三层模型桶各 append 一次，最后每个桶排序求分位。真机
# 558ms/次，TTL 15 秒——面板开着就是每 15 秒付一次。
#
# 这里按 (sample, realm, 窗口) 各记一份**环形样本状态**：
#   ring     最近 sample 条非空行各自的折叠结果（含尾部半行，deque，手工淘汰）
#   agg      这些行对聚合的贡献：全局计数 + 五个数值双端队列 + 三层模型桶
#   offset   已经折到日志的哪个字节；key/tail 是那条前缀的身份证明
# 于是 TTL 过期后的重建只把 offset 之后的新行并进来、把滑出样本的行撤出去，
# 不再重读也不再重新解析；位置校验不过（截断 / 换文件 / 同尺寸重写）才从
# 日志尾部的样本重建一次。
#
# 口径一个都没动：sample 仍是"最近 sample 行"（不是时间窗）、sample_capped
# 仍表示 tail 被截断、realm/窗口预过滤与分位口径照旧（分位始终从原始样本算，
# D6）；三层桶的存在与顺序、成功率的算法、sample_from 的取值规则全部照抄
# _perf_stats_uncached。这份状态**不落盘**（清单 §1.5：重启付一次冷扫即可，
# 落盘会让 checkpoint 涨几百 KB）。
# 面板实际用到的键就两三个（`?realm=` 一个、带窗口的一个），多出来的按最近
# 使用淘汰，免得用户来回切 range 时状态无限堆积。单份状态的内存与 sample 成
# 正比（本机实测：sample=5000 的环+聚合 ≈ 3.4MB，20000 ≈ 13MB），所以上限压
# 到 4 份——面板的键数装得下，最坏内存 ~14MB；淘汰只是下次重建一次，不影响
# 任何输出。
# ring 条目的形状，见 _perf_line_entry：短元组 = 不贡献聚合的行。


# The dashboard polls every 5s. A TTL shorter than the poll interval makes
# every other poll do the full uncached scan; 15s means at most one rebuild
# per three polls while the numbers stay a few seconds stale at worst.


# ---------------------------------------------------------------------------
# Daily usage counters
#
# The upstream caps a free window at a fixed token budget (code 6004), and by
# the time it answers 429 the window is already spent. This counter lets the
# operator park an account at a threshold instead: usage.jsonl is folded into
# uid -> tokens-since-local-midnight, plus two sibling views of the same rows
# - uid -> credit spent today (the daily credit guard) and
# uid -> {model: tokens} (the per-model daily guard).
# The pool's acquire() folds these totals into _limit_blocked(): an account
# past its panel-set daily guard is skipped, so the next request rotates to
# another account. The scan is incremental (byte offset + per-day totals),
# so the hot path only reads rows that arrived since the last scan.
# ---------------------------------------------------------------------------
_daily_usage = {"day": "", "totals": None, "credits": None, "models": None,
                "offset": 0, "at": 0.0}
_daily_usage_lock = threading.Lock()


def _daily_state_copy(source):
    """Copy the cached per-account counters into a fresh scan state.

    Three views of the same rows: uid -> total tokens, uid -> credit spent,
    uid -> {model: tokens}. The copy keeps a later scan from mutating the
    cached dicts in place while readers hold them.
    """
    return {
        "tokens": dict(source.get("totals") or {}),
        "credits": dict(source.get("credits") or {}),
        "models": {k: dict(v) for k, v in (source.get("models") or {}).items()},
    }


def daily_usage_stats(ttl=None):
    """Today's per-account usage folded from the log, cached for `ttl` seconds.

    Returns {"tokens": uid -> tokens, "credits": uid -> credit spent,
    "models": uid -> {model: tokens}}, or None when the log could not be read
    at all; callers keep that distinct from zero so a failed read never parks
    an account.
    """
    ttl = _STATS_TTL if ttl is None else ttl
    day = time.strftime("%Y-%m-%d")
    now = time.time()
    with _daily_usage_lock:
        c = _daily_usage
        if c["day"] == day and c["totals"] is not None and (now - c["at"]) < ttl:
            return _daily_state_copy(c)
        # A new day keeps the byte offset: everything past it is today's, and
        # the midnight filter drops whatever old rows are still unread.
        if c["day"] == day and c["totals"] is not None:
            state = _daily_state_copy(c)
        else:
            state = {"tokens": {}, "credits": {}, "models": {}}
        offset = int(c["offset"] or 0)
        try:
            size = os.path.getsize(USAGE_LOG)
        except OSError:
            size = 0
        if offset > size:
            state = {"tokens": {}, "credits": {}, "models": {}}
            offset = 0
        try:
            state, offset = _scan_daily_usage(offset, state)
        except Exception as exc:
            log("daily token scan failed: %s" % exc)
            _daily_usage.update({"day": day, "totals": None, "offset": 0,
                                 "at": time.time()})
            return None
        _daily_usage.update({"day": day, "totals": state["tokens"],
                             "credits": state["credits"],
                             "models": state["models"], "offset": offset,
                             "at": time.time()})
        return _daily_state_copy(_daily_usage)


# ---------------------------------------------------------------------------
# Remaining usage estimate
#
# 上游给「账号 × 模型」的免费额度是一个 24 小时窗口：窗口被用满时 429（code
# 6004）会带上重置墙钟（cn「将在 … 重置」），
# 到点计数归零、额度回满。实测（2026-10-10 的 34k 行日志）：重置时刻过后几秒
# 就又开始整额消耗（f793acc1 在 00:50:16 重置，00:50:26 起正常出流），所以
# 「窗口起点 = 重置时刻」；把 429 那一刻往前 24h 的用量加总，跨账号得到高度
# 一致的数字（deepseek-v4.1-flash 7 个样本 179.7M~201.0M），也就是该模型窗口
# 预算的估计值——这个数字上游不给，只能在账号真的撞线时反推。
#
# 数据有两个来源，合并去重（键 = 账号 + 模型 + 重置时刻）：
#   - usage/limit-events.jsonl：撞线发生的那一刻由请求路径记下（note_limit_
#     event），带账号、模型、重置时刻与样本。**必须实时记**：一次请求的重试
#     循环可能接连撞好几个账号，但只有最后那个账号会留下一条带账号归属的
#     429 用量行，其余账号的撞线只在 syslog 里出现过；
#   - usage.jsonl 里带账号的 429 行：本功能上线前就存在的历史由它补出预算，
#     新部署时也能兜住事件文件写失败的场合。
# 样本 = 重置前 24h 内该账号在该模型上的成功用量（429 行自身不算用量）；
# 查询时按区域聚合（先按账号平均、再跨账号平均）得预算，再对每个账号算
# 「自窗口起点以来的用量」：剩余 = 预算 − 已用。
# 还在冷却（重置时刻在未来）的组合窗口已用满，剩余记 0；没有撞线记录（或记录
# 已过期、锚不住当前窗口）的组合没有已知的重置时刻，按最近 24h 用量保守估计
# （窗口起点必然落在最近 24h 内，所以这是剩余量的下界），并在载荷里标 estimated
# 供面板区分。
#
# 分段记账：撞线后，那个窗口的记账在撞线处截断（撞线时刻之后的行不再计入——
# 上游已经拒收，残留的行不算这个窗口的消耗）；恢复时刻起新窗口重新记账，旧
# 窗口的用量不得计进新窗口的已用。窗口起点优先取链上上一个重置时刻（两个重置
# 时刻相隔不到 24h 时才是同一个窗口链），否则取重置时刻 − 24h——实测窗口锚定
# 比「固定 24h 链」复杂（有 48h+ 的空档），所以只用上游给的重置时刻这一个事实。
# 载荷里每行带 segments（每段 start/end/used，截断段标 capped），面板按
# 「上段 + 本段」呈现；预算样本同样按段截断（链式撞线时样本从上一个重置时刻
# 起算，旧窗口的用量不进新窗口的样本）。
#
# 锚点来源除事件日志外还有凭证档的 model_caps（历史持久化格式，账号池已删除）：本次
# 进程没撞过线（日志丢失/被裁）但磁盘上有记录时，冷却、窗口起点与截断点照它算。
#
# 按需过滤：昨天或今天没消耗过的模型不参与剩余用量计算（判定见
# _remaining_activity_floor；撞线锚点本身算消耗证据，冷却中的组合不因旧行被裁
# 掉就消失）。预算样本不因过滤而丢弃——它要撞线才学得到，载荷里标 active=False
# 让面板把它标成「未参与」而不是整条消失（否则每次跨零点面板都抖）。
# 按模型的总剩余 = 可用组的剩余之和：跨账号按 (区域, 模型) 汇总，冷却/已满的
# 组记 0（不参与减法、不把别的组拉低），没有预算的组计入 unknown 不计数。
#
# 按天持久化 + 近 3 天加权（estimate-daily.json）：样本按撞线当天的本地日期
# 分桶，估算是最近 3 天的加权平均（今天 6 / 昨天 3 / 前天 1，就近高权重，只在
# 有样本的天之间归一；某组合 3 天内没有样本就没有预算）。今天用内存里的事件
# 现算；更早的天在跨天时归档进文件、之后直接读——「调昨天的数据不重新计算」。
# 归档发生在构建载荷时发现本地日期变了（或重启后第一次构建）的那一刻：把刚
# 过去的那天算成 {预算, 分段} 合并进文件（该天已在文件里就不覆盖，幂等）。
# 文件里每天的预算是当天样本「先按账号平均、再跨账号平均」的 {avg,min,max,n}；
# 分段是每个 (账号, 模型) 的 pre（当天截断前用量）/ post（当天截断后用量），
# 满足 pre + post == 当天该组合的用量（用户要的「今日截断前 / 截断后」两个数，
# 调昨天的数据不用再算）。保留：预算留最近 3 天（与估算窗口一致），分段只留
# 最近 2 天（用户要求「仅保留到第二天」，多留一天防跨天边界）。
# 归档的计算在状态锁内做（要读事件表与用量缓冲），文件写盘在锁外（与
# checkpoint 同款理由：写盘在状态锁里会构成锁序环）。
#
# 查询侧不做重复计算：
#   - 每个 (账号, 模型) 的用量缓冲是**时间戳 + 累计和**两个列表，窗口
#     求和是两次二分 + 一次相减（O(log n)），不是每次查询把上万行重新加一遍；
#     每行只留时间戳与累计值（旧的 deque-of-tuple 是 tuple + 两个装箱数字），
#     弱设备上省下的是实实在在的内存与遍历；
#   - 载荷挂一个短 TTL（WB_REMAINING_TTL，默认 15 秒）——面板每 5 秒轮询一次，
#     而数字只在用量或撞线发生时变，逐次重建是纯浪费。TTL 内直接返回上次算好的
#     载荷，连日志尾部都不再扫；面板带 If-None-Match 轮询时命中 304，连那点
#     JSON 也不再重传（校验符派生自缓存条目的构建时刻，与其它统计接口同款）。
# ---------------------------------------------------------------------------
# 按天持久化的估算数据（每天的预算口径 + 每个组合的截断前后分段）。与事件
# 日志一样必须跟随 --usage-dir：常量在 import 时按默认目录算过，漏掉它真机上
# 会一直写 ENOENT（2026-10-10 实测 limit-events.jsonl 踩过同一个坑）。
ESTIMATE_DAILY_FILE = os.path.join(USAGE_DIR, "estimate-daily.json")
# recent 的行偏移索引（页 = 日志尾部的第 N 页）。同样必须跟随 --usage-dir：
# 常量在 import 时按默认目录算过，漏掉它换目录后索引会写到旧目录去。
RECENT_INDEX_FILE = os.path.join(USAGE_DIR, "usage-recent-index.json")
# 估算窗口的权重：今天 6 / 昨天 3 / 前天 1，就近高；只在有样本的天之间归一
# （某天没样本就跳过）。
# 保留：预算留最近这么多天（与估算窗口一致，多留无用——估算读不到）；分段
# 只留最近 _ESTIMATE_SEGMENT_DAYS 天（用户要求「仅保留到第二天」，多留一天
# 防跨天边界），更早的天删掉 segments 字段、预算保留到窗口外一天才整条删。
# 缓冲多留 2h：查询侧的窗口起点最远只能到 now-24h，留出余量避免边界丢行。
# 事件只留最近这么多条：预算估计吃的是近期样本，几十条足够，封顶防日志异常
# 时无界增长（每条只记数字与 uid/model，一千条不到 200KB）。文件本身不裁剪，
# 冷启动全读一遍也就几十毫秒。
# 载荷缓存时长（秒）。比面板的 5 秒轮询长、远短于其它统计接口的 900 秒统计 TTL：
# 数字最多滞后这么久，但一轮重建能服务好几轮轮询。
_REMAINING_TTL = ca_env.number("WB_REMAINING_TTL", 15.0, minimum=0.0, zero_ok=True)

# 载荷缓存（与上面的折叠状态分开两把锁：重建要持状态锁做扫描，命中缓存不该等它）。
# estimate-daily.json 的解析缓存：单键元组一次赋值（(路径, mtime_ns, size),
# days），读侧不加锁也不会看到半份缓存；写盘路径主动换掉它，外部改动靠 stat
# 变化发现。路径也在戳里：--usage-dir 换目录后不会被旧目录的戳骗过去。
# 文件读-改-写串行锁：只在 _estimate_daily_sync() 里拿一次，且永远在状态锁
# 之外（归档计算在状态锁内、写盘在锁外，同 checkpoint 的理由）。


#: 签到线程的节拍（秒）。30 分钟足够「每天一次」的精度，失败也能当天补试。
CHECKIN_TICK_SECONDS = ca_env.number("CODEARTS_CHECKIN_TICK", 1800.0,
                                     minimum=60.0)
#: 每天第一次尝试的本地时刻（时:分）。放在零点过 5 分钟，避开上游的日切。
CHECKIN_AT = os.environ.get("CODEARTS_CHECKIN_AT", "00:05")

_CHECKIN_STATE = {}          # uid -> "YYYY-MM-DD"（当天已尝试，无论成败）
_CHECKIN_LOCK = threading.Lock()


def _checkin_local_day():
    return time.strftime("%Y-%m-%d")


def _checkin_due_now():
    """今天第一次尝试的时刻到了没有（本地时区，HH:MM 之后即算到）。"""
    try:
        hh, mm = CHECKIN_AT.split(":")
        target = int(hh) * 60 + int(mm)
    except ValueError:
        target = 5
    now = time.localtime()
    return now.tm_hour * 60 + now.tm_min >= target


def _checkin_once():
    """对所有码道账号尝试一次签到；当天成功/已签的账号跳过。

    任何异常都不外抛 —— 这是后台线程，挂了只会少一次签到，不能拖垮网关。
    """
    try:
        sessions = ca_codearts.load_sessions(ACCOUNTS_DIR)
    except Exception as exc:                     # noqa: BLE001
        log("checkin: cannot load sessions: %s" % exc)
        return
    today = _checkin_local_day()
    for session in sessions:
        acct = session.get("account") or {}
        uid = str(acct.get("id") or "")
        if not uid:
            continue
        with _CHECKIN_LOCK:
            if _CHECKIN_STATE.get(uid) == today:
                continue
            _CHECKIN_STATE[uid] = today          # 先占位，避免并发重复打
        label = acct.get("label") or uid
        try:
            session = ca_codearts.ensure_fresh_session(
                ACCOUNTS_DIR, session, CODEARTS_REFRESH_MARGIN)
        except Exception as exc:                 # noqa: BLE001
            ca_activity.record(uid, label, "cn", ca_activity.TASK_CHECKIN,
                               "scheduler", False, "续期失败: %s" % str(exc)[:120],
                               usage_dir=USAGE_DIR)
            _CHECKIN_STATE[uid] = None           # 失败了允许本周期内再试
            continue
        try:
            res = ca_codearts.welfare_claim_daily(
                session.get("accessKey"), session.get("secretKey"),
                session.get("securitytoken"))
            amount = res.get("amount")
            msg = ("已签到 +%s 积分" % amount) if not res.get("already")                   else "今日已签到（%s 积分）" % (amount or "?")
            log("checkin    : [%s] %s" % (label, msg))
            ca_activity.record(uid, label, "cn", ca_activity.TASK_CHECKIN,
                               "scheduler", True, msg, usage_dir=USAGE_DIR)
        except Exception as exc:                 # noqa: BLE001
            msg = str(exc)[:160]
            log("checkin    : [%s] 失败: %s" % (label, msg), level="WARN")
            ca_activity.record(uid, label, "cn", ca_activity.TASK_CHECKIN,
                               "scheduler", False, msg, usage_dir=USAGE_DIR)
            if ca_codearts.welfare_permanent_failure(exc):
                # 永久失败（渠道下线/活动消失）：当天不再试，但次日仍会重探
                # —— 上游哪天恢复，第二天自然签上。
                continue
            _CHECKIN_STATE[uid] = None           # 可重试失败：本周期内再补
        # 成功或"已签"：状态保持 today，今天不再打扰


def _checkin_loop():
    while True:
        try:
            if _checkin_due_now():
                _checkin_once()
        except Exception as exc:                 # noqa: BLE001 —— 兜底，别死线程
            log("checkin: loop error: %r" % (exc,), level="WARN")
        time.sleep(CHECKIN_TICK_SECONDS)


def start_checkin_scheduler():
    thread = threading.Thread(target=_checkin_loop, name="codearts-checkin",
                              daemon=True)
    thread.start()
    log("checkin     : scheduler on (daily at %s local, tick %.0fs)"
        % (CHECKIN_AT, CHECKIN_TICK_SECONDS))


#: STS 巡检间隔（秒）。续期点由 CODEARTS_REFRESH_MARGIN 决定，巡检只要
#: 显著小于它即可；无账号时一轮空转只是一次目录读。
CODEARTS_STS_TICK_SECONDS = ca_env.number("CODEARTS_STS_TICK", 30.0,
                                          minimum=5.0)


def _sts_refresher_once():
    """巡检一遍所有码道账号，STS 快到期的当场续掉。

    请求路径（``_admit`` / 目录刷新）本来就会兜底续，但那是流量驱动的：
    没人发请求就没人续，账号可以从过期一直躺到下一波流量才被发现
    （2026-10-24 实测躺过 41/76 分钟，期间所有请求 502）。这个巡检把
    续期变成时间驱动：空闲也能续，到期前 margin 秒内必然被刷掉。
    """
    try:
        sessions = ca_codearts.load_sessions(ACCOUNTS_DIR)
    except Exception as exc:                     # noqa: BLE001 —— 目录坏了别死线程
        log("sts-refresher: cannot load sessions: %s" % exc, level="WARN")
        return
    for sess in sessions:
        if shutting_down():
            return
        try:
            _ensure_fresh(sess)
        except Exception:                        # noqa: BLE001 —— 失败原因 _ensure_fresh 已记
            continue


def _sts_refresher_loop():
    while True:
        try:
            if not shutting_down():
                _sts_refresher_once()
        except Exception as exc:                 # noqa: BLE001 —— 兜底，别死线程
            log("sts-refresher: loop error: %r" % (exc,), level="WARN")
        time.sleep(CODEARTS_STS_TICK_SECONDS)


def start_sts_refresher():
    thread = threading.Thread(target=_sts_refresher_loop, name="codearts-sts",
                              daemon=True)
    thread.start()
    log("sts        : refresher on (tick %.0fs, margin %.0fs)"
        % (CODEARTS_STS_TICK_SECONDS, CODEARTS_REFRESH_MARGIN))


def remaining_usage(ttl=None):
    """Cached payload: the panel polls every 5s, the numbers change far slower.

    Within the TTL the last payload is returned as is - no rescan of either
    file, no rebuild - which is what makes the 5s polling cost nothing between
    rebuilds. The TTL is deliberately short (WB_REMAINING_TTL, 15s default):
    long enough to serve several polls per rebuild, short enough that a cap or
    a burst of usage shows up while the operator is looking at the panel.
    """
    ttl = _REMAINING_TTL if ttl is None else ttl
    now = time.time()
    with _remaining_cache_lock:
        entry = _remaining_cache
        if entry["data"] is not None and (now - entry["at"]) < ttl:
            return entry["data"]
    # 重建在缓存锁外：它自己会拿状态锁扫描，命中等它的调用不该被拖住。
    data = _remaining_payload()
    with _remaining_cache_lock:
        _remaining_cache.update({"at": time.time(), "built_at": time.time(),
                                 "data": data})
    return data


def remaining_usage_etag():
    """ETag of the current /usage/remaining cache entry, or None.

    与 usage_by_account_etag() 同款：键是常量（这个视图只有一条缓存），配对
    调用由 _json_cached() 保证。轮询在 TTL 内命中同一份载荷 → 同一枚校验符
    → 304；重建后自动换戳。
    """
    with _remaining_cache_lock:
        entry = _remaining_cache
        if entry["data"] is None:
            return None
        built_at = entry["built_at"]
    return _cache_etag("remaining", "all", built_at)


# ---------------------------------------------------------------------------
# Incremental all-time aggregates
#
# The dashboard's all-time panels used to re-read the whole usage.jsonl on
# every cache miss, and the log grows by thousands of rows a day. Those totals
# only change when a row is appended, so each aggregate keeps the byte offset
# it has already folded and a refresh reads just the rows past it - the shape
# daily_usage_stats() already uses for today's counters, truncation guard
# included. A windowed query still walks the file, but the pre-filter above
# drops out-of-window lines before the parse, so it pays only for the rows it
# keeps.
#
# A carried-over total is only valid while everything the fold read is
# unchanged, so a state also carries a fingerprint of its other inputs: the
# price tables (a new policy can re-price a row that has no reference of its
# own) and the realm a row without a realm field is attributed to. When one of
# those moves, the fold starts over - an offset alone would happily keep
# yesterday's prices forever.
#
# One state per realm and per aggregate: each holds a few models and a few
# accounts, so keeping one around costs nothing next to the scan it replaces.
# ---------------------------------------------------------------------------


# How many bytes of the already-counted prefix are read back on every
# refresh to prove that prefix still holds the same bytes. Long enough
# that a rewrite cannot match it by accident, short enough to cost
# nothing on the poll path.


# ---------------------------------------------------------------------------
# 「用到的价」状态指纹（T15）：状态指纹收窄成折叠行真正用到的价
#
# 价表内容一变（哪怕只是新增一个无关模型的价格），带价格指纹的 5 条状态
# （snapshot×3 + analytics×2）此前全部判废、各重折 12-15s；但已折行的成本
# 在设计上就是历史价——带 cost_policy 的行按不可变策略计价，无引用老行由
# 时间线解析（见 _fold_usage_snapshot 的注释："a later price change cannot
# rewrite yesterday's totals"）——所以绝大多数重折是白付。
#
# 这里把状态指纹从「(policies, timeline, pricing_doc) 三张表的对象身份」收窄
# 成一份记录（state["pricing"]，checkpoint 的 "pricing" 字段，schema 5）：
#   * refs           折叠解析出来的每个 pid 的策略内容摘要（_object_digest 按
#                    对象身份记忆，热路径 O(1)）；pid 当时查不到记 None（=该
#                    pid 必须继续缺席，出现即作废）。
#   * timeline       时间线依赖的投影摘要（没有依赖时 None）。
#   * timeline_at    无引用且成本非零的行的 at 上界。
#   * timeline_models 上述行的模型集合。
#   * unresolved     上述行里整条时间线都没提到的模型（解析扫过全部行）。
#   * backfilled     上述行里出现过回填解析（解析扫过全部行）。
#   * builtin        用到内置快照时，内置价目表文档的内容摘要。
#
# 判定侧 _pricing_used_unchanged() 从当前价表重算同一份记录并逐项比对，不等
# 就判废重折；相等的部分保证「重折会给出同样的数」。
#
# 不动的东西：_row_cost / _row_cost_remember（行级记忆代次仍用整表判定）、
# series（不算价）、任何聚合口径与窗口路径。
# ---------------------------------------------------------------------------

# 记录里的固定字段（进程内构造与 checkpoint 采纳都按这一组校验）。


# 时间线投影摘要的记忆：值是一个元组 (时间线对象, 参数键, 摘要)，一次 get 拿全
# （与 _object_digest 的记忆同一个写法）——两个状态锁下的线程同时算也不会读到
# 拼起来的值；元组里握着时间线对象，身份不会被回收复用。


_realm_disk_cache = {"key": None, "map": None}
_realm_disk_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 行级结果记忆：把「同一行算出来的东西」跨视图复用
#
# 一次冷启动里同一份日志被三个视图各扫一遍（snapshot / analytics / series），
# 每一行都要重新算一次本地日键（_local_day_key，strftime 真机 43.4µs/行），
# snapshot 与 analytics 还要各算一次 cost_for_row（真机 72.4µs/行）。这两样都是
# 行的纯函数——日键只看 at（进程内时区固定），定价只看行的定价字段加价表本身
# ——所以第二个视图不必再算：记下结果，直接取。
#
# 记的是结果，不是状态：五个聚合仍各持各的折叠状态（D1/D2/D3 不受影响），这里
# 没有任何一份聚合能被另一个视图借走，只有「这行折进哪天」和「这行值多少钱」
# 两个标量。位置/指纹校验、realm 归属、日桶语义都照旧。
#
# 键不能是行对象 id()：三次扫描各自 json.loads 出各自的行对象，旧对象释放后 id
# 会被复用，按 id 记忆会静默拿到别的行的值。日键按 at 记（纯函数，跨扫描安全）；
# 定价按它真正读的那几个字段记（model / cost_policy / at / 三个 token 数），外加
# 价表代次——代次就是扫描开头取到的那份 _pricing_inputs() 元组，价表换代时元组
# 里的对象不再是同一个，旧条目自然不命中（判定与 _pricing_unchanged 同一条规则）。
# 同一代次内的价表内容按定义不变，所以命中值必然等于现算值。
#
# 两张表都必须有界（路由器上不能拿内存换速度换到失控）：上限按条目数，满了以后
# 只收「不比表里最旧那条更旧」的行。扫描总是从头往尾走，表里留住的因此是最近的
# 一批行，第二个视图走到尾部照样命中，被拒的只是已经过去的头段。单条体积实测
# 日键 60B、定价 402B（键里留着行的模型名/时间戳/三个 token 数），所以两张表的
# 上限分开给，都可用环境变量调（WB_ROW_MEMO_MAX / WB_ROW_COST_MEMO_MAX，
# 0 = 关掉这张表）。
#
# 不落盘：扫描期的临时记忆，重启后重算一遍即可（清单 §1.5）。
# ---------------------------------------------------------------------------

# 条目上限（条数，不是字节）。默认按「典型日志装得下大半、内存留在个位数 MB」
# 给：日键表 6.4 万条（≤3.8MB）；定价表 16384 条（≤6.3MB）。日志更大、内存又
# 宽裕的部署可以把 _ROW_COST_MEMO_MAX 调到行数以上，拿满跨视图复用（路由器上
# 整份日志约 4 万行，满覆盖约 15MB）；内存紧的调到 0 就是关掉那张表。
#
# 两个值在导入时从环境变量读一次（WB_ROW_MEMO_MAX / WB_ROW_COST_MEMO_MAX，
# 0 = 关掉那张表）：这是给部署定上限的开关，不是逐次可切的现场开关——而
# os.environ.get 走「键不存在」那条路要 ~2µs，放在每行都走的插入路径上会把
# 省下来的时间原样还回去。运行期要改直接改模块属性（测试就是这么做的）。
_ROW_COST_MEMO_MAX = 16384


_ROW_COST_MEMO_MAX = _row_memo_env_cap("WB_ROW_COST_MEMO_MAX", _ROW_COST_MEMO_MAX)

_row_cost_memo = {}         # (model, cost_policy, at, pt, ct, comp) -> (价表代次, 定价结果)
_row_cost_gen = None        # 定价表当前代次（_pricing_inputs() 的元组）


def _cost_entry(pricing, cost):
    """cost_for_row(details=False) 的返回值 -> 记忆条目（定长元组）。"""
    return (pricing, cost["known"], cost["cny"], cost.get("band"),
            cost.get("rates"), cost.get("source"), cost.get("source_at"),
            cost.get("backfilled"), bool(cost.get("disabled")))


#: 价格估算体系已下线（2026-10-22）：这个网关只按码道积分记账，不再折算
#: OpenRouter / 美元等价花费。所有成本出口统一返回这一份零值。
#:
#: 形状必须与 `ca_pricing.cost_for_row(..., details=False)` 逐键一致，调用方
#: （`_fold_cost`、`_feed_analytics`、面板接口）才不会 KeyError。
#: `known=False` + `disabled=True` 是刻意的组合：`_fold_cost` 据此既不累加、
#: 也不把模型记进 `cost_missing`（那会在面板上冒出「未定价模型」的假告警）。


def _row_cost_remember(key, pricing, cost):
    """把一行的定价结果记进有界表；价表换代时整表作废。

    换代只可能来自价表文件被改写（策略表/时间线/价目表任一新对象），发生时
    旧条目按定义全部失效，直接清掉，别让它们白占位置。判定用的是
    _pricing_unchanged——与状态指纹同一条规则，两处不会漂移。
    """
    global _row_cost_gen
    memo = _row_cost_memo
    if _row_cost_gen is None or not _pricing_unchanged(_row_cost_gen, pricing):
        memo.clear()
        _row_cost_gen = pricing
    cap = _ROW_COST_MEMO_MAX
    if cap <= 0:
        return
    if len(memo) >= cap:
        oldest = next(iter(memo))
        if _row_memo_at(key[2]) < _row_memo_at(oldest[2]):
            # 比表里最旧的还旧：记了也会立刻被顶掉，不如不记
            return
        memo.pop(oldest, None)
    memo[key] = _cost_entry(pricing, cost)


_count_cache = {}
_count_lock = threading.Lock()
# The count only feeds the "N records" label. The poll interval is 5s, so a
# TTL of the same length would miss on nearly every poll; 30s turns a full
# scan per poll into one scan per six polls while the label stays current
# enough for a record total that only ever grows.
_COUNT_TTL = ca_env.number("WB_COUNT_TTL", 30.0, minimum=0.0, zero_ok=True)

# 增量计数的状态（offset/tail/n/n_realm），由 _count_state_lock 保护。
# 与 by_account 折叠同一套位置校验（_usage_log_key + _log_offset_holds +
# _log_tail_signature）：日志被截断、被替换或同尺寸重写时从零重数，宁多扫
# 一次也不能给出错的页数。TTL 缓存按 realm 分键，这份状态则与 realm 无关
# ——一次扫描同时维护总数与每个 realm 的计数，任何 realm 的查询都复用同一
# 条进度，不再各自全量扫一遍。
_count_state_lock = threading.Lock()
_count_state = {"offset": 0, "key": None, "tail": b"", "n": 0, "n_realm": {}}


# Every row this process writes starts with `{"at": <float>,` - record_usage
# and record_error put the timestamp first and json.dumps keeps that order -
# which is what makes the window pre-filter below possible.
# The same prefix as bytes: _line_outside_window_bytes() reads the undecoded
# line, and deriving the bytes from the text keeps the two in step.


def count_usage_rows(realm=None):
    """Cached row count - incremental, substring match instead of a full parse.

    Rows written before the `realm` field existed (they are all error rows)
    have to fall back to the account/model heuristic in row_realm, so those
    few are still parsed properly - once, when the fold first reaches them.

    This runs on every /usage/recent poll purely to render the page total,
    and a full scan of the file dominated that endpoint (measured at ~50% of
    its cost on a 45MB log). The fold is carried over and refreshed with the
    rows appended since the last call, so a poll costs what the new traffic
    costs instead of what the whole log costs; the short TTL still keeps the
    number honest while removing even that from the poll path.
    """
    # 先归一化：桶键就是 realm 字符串本身，字面 "all" 会被当成一个永远不存在
    # 的桶（realm_scope 把它映射成 None = 总数）。
    realm = realm_scope(realm)
    r = realm or ""
    now = time.time()
    with _count_lock:
        hit = _count_cache.get(r)
        if hit is not None and (now - hit[0]) < _COUNT_TTL:
            return hit[1]
    n = _count_usage_rows_uncached(realm)
    with _count_lock:
        _count_cache[r] = (time.time(), n)
    return n


# `"realm"` 的键文本。旧实现拿 `'"realm": "<值>"'` / `'"realm":"<值>"'` 两个
# needle 做子串命中，新实现按同一对间距从行里取字段值（见 _count_usage_line）
# ——口径逐字相同，只是不再为每个 realm 各扫一遍文件。


def _count_usage_scan(state):
    """把日志 offset 之后的每一行折进 state；返回 (offset, error)。

    与 _scan_usage_from 同一套字节纪律（整行推进、半行留给下一趟、解码失败
    即停），但折叠的是**行文本**而不是解析出的 row：计数的总口径里有一类行
    根本不是合法 JSON（总行数照数），而 _scan_usage_from 在 fold 之前就把
    它们丢掉了。逐行调用在这里直接写死（不走回调），全量重数一次要过几万行，
    每行省一次间接调用是这条冷路径上最便宜的一笔。
    """
    offset = state["offset"]
    try:
        with open(USAGE_LOG, "rb") as fh:
            fh.seek(offset)
            while True:
                raw = fh.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    break
                end = offset + len(raw)
                try:
                    line = raw.decode("utf-8").strip()
                except UnicodeDecodeError as exc:
                    return end, exc
                if line:
                    try:
                        _count_usage_line(state, line)
                    except Exception as exc:
                        return end, exc
                offset = end
    except FileNotFoundError:
        pass
    except Exception as exc:
        return offset, exc
    return offset, None


def _count_usage_rows_uncached(realm=None):
    """增量计数：把折叠推进到文件尾，返回 realm 对应的行数。

    状态按「本进程数到哪」记账（offset/tail/n/n_realm），每次调用只数新增
    的字节；位置校验不过（截断、换文件、同尺寸重写）才从零重数。realm 为
    空返回总行数，否则返回该 realm 桶里的行数。
    """
    state = _count_state
    with _count_state_lock:
        log_key = _usage_log_key()
        if not _log_resume_ok(state, log_key):
            state.update({"offset": 0, "tail": b"", "n": 0, "n_realm": {}})
        state["key"] = log_key
        offset, error = _count_usage_scan(state)
        n = state["n"]
        counts = state["n_realm"]
        if error is None:
            state["offset"] = offset
            state["tail"] = _log_tail_signature(offset)
        else:
            # 出错的那一行（非法 UTF-8 才会走到这里）可能已经半折进去了：
            # 这份状态整个作废，下次从零重数——by_account 折叠同款处理。
            # 这一次仍返回已经折到的部分：旧实现的文本层按块解码，坏行落在
            # 第一块里时整次报 0、落在后面时给部分数；新实现稳定地给出坏行
            # 之前的行数，任何情况下都不会更差。
            log("usage count failed: %s" % error)
            state.update({"offset": 0, "tail": b"", "n": 0, "n_realm": {}})
        if not realm:
            return n
        # 桶键是归一后的出口名：传入历史别名（cn / intl）时也要落到同一个桶，
        # 否则「按老区域名查」会稳定返回 0，而总数明明非零。
        return counts.get(normalize_realm(realm), 0)


# ---------------------------------------------------------------------------
# recent 的行偏移索引（页 = 日志尾部的第 N 页）
# ---------------------------------------------------------------------------
#
# recent_usage 的每一页都要从日志尾部往回数到第 N×limit 条记录才定位得到：
# 第 1 页至少要读回一个 256KB 块，realm 过滤命中率低时要读回整个文件，页深
# 越大代价越大。这里给日志建一份行偏移索引——每 64KB 记一条「行边界字节偏移
# + 到该处的累计记录数」，页 N 直接 seek 到起点附近再顺序读回页大小量级的
# 数据，读取量与页深无关。
#
# 索引落在数据目录的独立文件里（不并进 checkpoint：checkpoint 是五份聚合
# 状态的落盘，这份索引的对象只有日志本身，校验与写盘策略都跟着日志走）：
#
#   * 位置校验复用聚合那套现成机制（_usage_log_key + _log_offset_holds +
#     _log_tail_signature，P:2504-2573）：日志被截断、被替换、同尺寸重写都会
#     让索引作废，从零重扫一遍——宁多扫一次，也不给出一页错的记录；
#   * 两个口径都在同一次扫描里现算，不复制第二份实现：页数标签走
#     _count_usage_line（D5：总数含坏 JSON 的非空行），行定位走 recent 自己的
#     row_matches_realm 归属；
#   * 「没带 realm 字段的行」的归属要查活账号池（row_realm），跨进程不一定
#     复现得了：有这类行时，realm 相关的数字只在「活池 == 磁盘归属」且 uid→
#     realm 与折进来时一致时才用索引（_realm_fold_reproducible），否则退回
#     老路——老路永远用活池，永远是当前该有的数字。
# 索引粒度：每 64KB 记一条行边界。4 万行的日志（约 23MB）只有 350 条上下，
# 页读取的起点最多偏一段，读取量是「一段 + 页本身」。
# realm 表容量。真实日志只有 cn（外加没带字段的老行归属，以及已删除区域的
# 历史遗留行），超过这个数说明 realm 字段被人乱写了，索引直接不用（老路照常
# 给出正确结果）。
# realm 值长度上限：手改过的行可以带出很长的值，那只会把索引撑大。


# 索引状态（由 _recent_index_lock 保护）。字段：
#   stamp          —— 上次读到/写下的索引文件戳（外部改动靠它发现）；
#   usable         —— 位置校验通过、可以服务查询；
#   giveup         —— 扫描撞上索引处理不了的行，本进程不再重试（日志换掉才重来）；
#   key/size/tail  —— 与聚合同款的位置信息：索引覆盖到 size（行边界）；
#   realm_map      —— 折进来时的磁盘 uid→realm（realm 数字的指纹）；
#   legacy         —— 日志里有归属要查活池的行；
#   realms/counts/row_counts —— realm 表与两个口径的计数（count 口径只有总数，
#                      recent 口径按段存，供定位）；
#   segs           —— [offset, rows, <row_counts 各列>]，累计值；
#   wrote_size/at  —— 写盘节流（记「尝试」而非成功，失败也退避）。


def recent_usage(limit=100, realm=None, page=1):
    """Paginated rows from the tail of the log (page 1 is latest).

    Reading backward in chunks keeps this in the millisecond range while
    accurately fetching any requested page without missing rows across realms.

    索引可用时页从索引直接定位（见上面那一节）：页数标签与页内容都来自同一次
    扫描，读取量是页大小量级；索引答不了就整段退回 _recent_backward_page()，
    两条路的输出逐字相同。
    """
    try:
        limit = max(1, int(limit))
    except Exception:
        limit = 100
    try:
        page = max(1, int(page))
    except Exception:
        page = 1
    realm = realm_scope(realm)
    index = _recent_index_ready(realm_filtered=bool(realm))
    page_rows = None
    if index is not None:
        total = _recent_index_total(index, realm)
        total_pages = max(1, (total + limit - 1) // limit) if total > 0 else 1
        page = min(page, total_pages)
        page_rows = _recent_index_page(index, realm, page, limit)
        if page_rows is None:
            index = None
    if index is None:
        total = count_usage_rows(realm)
        total_pages = max(1, (total + limit - 1) // limit) if total > 0 else 1
        page = min(page, total_pages)
        page_rows = _recent_backward_page(realm, page, limit)
    # Equivalent-token cost per row at OpenRouter list prices, computed here
    # so every consumer of /usage/recent gets the same number. Each row is
    # priced against the version that was in force when it happened, and says
    # where that price came from. cost_cny stays None for models the version
    # cannot price; cost_band is the index of the conditional band the row
    # landed in (None when the model has one flat price, or none matched).
    # cost_rates / cost_unit / cost_currency / cost_usd_cny / cost_or_id /
    # cost_via / cost_inherited_from / cost_override_from / cost_band_note /
    # cost_via_derived are the same figure taken apart for the panel's hover
    # card: which band's three unit prices, at which rate, matched how. They
    # are all None when the row is unpriced - the panel must say so rather
    # than show a made-up 0.
    for r in page_rows:
        cost = dict(_ZERO_COST)
        r["cost_cny"] = round(cost["cny"], 6) if cost["known"] else None
        r["cost_band"] = cost["band"] if cost["known"] else None
        # cost_policy stays as the row recorded it; cost_source is what the
        # lookup actually resolved to (the same id, or "builtin").
        r["cost_source"] = cost["source"] if cost["known"] else None
        r["cost_source_at"] = cost["source_at"] if cost["known"] else None
        r["cost_backfilled"] = bool(cost["backfilled"]) if cost["known"] else False
        r["cost_rates"] = cost["rates"] if cost["known"] else None
        r["cost_unit"] = cost["unit"] if cost["known"] else None
        r["cost_currency"] = cost["currency"] if cost["known"] else None
        r["cost_usd_cny"] = cost["usd_cny"] if cost["known"] else None
        r["cost_or_id"] = cost["or_id"] if cost["known"] else None
        r["cost_via"] = cost["via"] if cost["known"] else None
        r["cost_inherited_from"] = (cost["inherited_from"] if cost["known"]
                                    else None)
        r["cost_override_from"] = (cost["override_from"] if cost["known"]
                                   else None)
        r["cost_band_note"] = cost["band_note"] if cost["known"] else None
        r["cost_via_derived"] = (bool(cost["via_derived"]) if cost["known"]
                                 else None)
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "usd_cny": 0.0,
        "rows": page_rows
    }
PRICING = None
# CodeArts（华为云）账号登录：与 WorkBuddy 账号池完全独立的一套凭证体系，
# 只共用 accounts/ 目录（落在 accounts/codearts/ 子目录里）。
CODEARTS_LOGIN = None
# Release discovery only - the checker never downloads or installs anything.
UPDATES = None
#: 账号档案目录。默认是仓库里的 accounts/；测试沙箱（tests/run_all.py）用
#: ``WB_PROXY_ACCOUNTS_DIR`` 把它指到临时目录，避免套件把 stub 假数据写进
#: 真实账号 / 用量库（2026-10-25：生产机上跑套件曾写入 8 条假用量行）。
#: 命令行 --accounts-dir 仍然优先（见 main()）。
ACCOUNTS_DIR = os.environ.get("WB_PROXY_ACCOUNTS_DIR") \
    or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'accounts')
def realm_state_file():
    """Path of the persisted realm switch.

    Computed on every access rather than cached in a module constant: the
    constant was built from the default ACCOUNTS_DIR at import time, so a
    later --accounts-dir (or a Docker volume pointing somewhere else) still
    read and wrote the realm switch next to the script - the panel then
    reported an exit that did not match the configured account store.
    """
    return os.path.join(ACCOUNTS_DIR, "active_realm.json")


def load_persisted_realm():
    global CURRENT_REALM
    path = realm_state_file()
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                r = normalize_realm(d.get("realm"))
                CURRENT_REALM = r
                return CURRENT_REALM
        except Exception as e:
            log("could not load active realm: %s" % e)
    return CURRENT_REALM
API_KEY = None
SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT


# The wrapper above holds _byacct_lock while it rebuilds and then calls in
# here, and _usage_by_account_uncached() is also called straight from the
# bench and the tests; a lock of its own keeps the refresh from re-entering
# the wrapper's - that one is not reentrant, so sharing it hung the process
# on the first cache miss.


def compute_usage_analytics(ttl=None, realm=None, range=None, since=None, until=None):
    """Cached analytics payload.

    Unlike perf_stats/usage_snapshot/usage_by_account this used to run
    uncached, re-reading the whole JSONL on every call while the metrics tab
    polls it every 5 seconds. Same shared TTL as its siblings now, and the
    rebuild runs under the lock so parallel pollers do not each scan the log.

    The window joins the cache key for the same reason it does in the other
    readers: the payload's window bucket is what the KPI cards print, and this
    week and this month overlap, so one entry cannot serve both.
    """
    ttl = _STATS_TTL if ttl is None else ttl
    now = time.time()
    lo, hi, cache_key = _analytics_scope(realm, range, since, until)
    with _analytics_lock:
        entry = _analytics_cache.get(cache_key)
        if entry is not None and (now - entry["at"]) < ttl:
            return entry["data"]
        data = _compute_usage_analytics_uncached(realm=realm_scope(realm), since=lo, until=hi)
        _analytics_cache[cache_key] = {"at": time.time(), "data": data}
    return data


# Rows the per-key table folds traffic into when no real key id applies.
# `before` and `anon` are told apart by whether the row carries a `key` field
# at all: rows written before this feature existed have none, and their number
# can only ever shrink, while "no key configured" deployments keep adding rows
# with an empty key. The two need different responses, so they never merge.
KEY_BUCKET_UNKNOWN = "__unknown_key__"
# The per-key model breakdown is capped: a deployment with 50 keys would
# otherwise ship a few thousand pills to a page that repaints every 5 seconds.
# The accounts table can afford to list every model because it has one row per
# upstream account, not one per caller.
KEY_MODEL_TOP_N = 5


# One half of the analytics payload folds into four maps: the window summary,
# the per-account entries, the per-model entries and the per-key entries. The
# all-time half and the windowed half hold the same maps and differ only in
# which stat on each entry they own, so the row fold below is written once and
# told which half it is feeding.


# ---------------------------------------------------------------------------
# analytics 的小时层：自定义区间窗口的就近取值
#
# 日桶只拆得开「起点是本地午夜 + until 开放」的窗口；面板的自定义区间起点是
# 任意时刻，那条路径一直整段扫描（路由器上冷 49.4s）。而 analytics 的 token
# 口径含失败行（见 _feed_analytics），与 snapshot/series 不同，借不了别人的
# 层——所以这里在 analytics 自己的日桶里再挂一层小时子表（analytics 算价，
# 小时桶跟着带成本字段），起点落在「本地午夜 + k*3600」格点上的窗口就是窗口
# 内小时桶之和，O(小时数)。
#
# 与日桶同一条纪律：对齐窗口的求和统一用「按小时分组」的口径，冷扫描
# （_scan_usage_analytics_window_hours）、小时桶、加载 checkpoint 三条路径
# 给出的字节完全一致；非整小时的起点（面板按分钟选的时间）拆不开，仍然整段
# 扫描，正确性优先。WB_USAGE_DAY_BUCKETS=0 一并关掉小时层。
#
# 保留比日桶短得多（WB_USAGE_HOUR_KEEP_HOURS，默认 48h）：小时桶只为近期的
# 自定义窗口服务，每个桶的形状与日桶一样（summary + 每账号/每模型/每 key），
# 跟着 32 天的日桶全留会让 checkpoint 膨胀十几倍。剪枝线以外的天由查询侧按
# 「这一天还有没有 hours」自己表达（没有就退回扫描），所以不另存 floor。
# ---------------------------------------------------------------------------


def _merge_analytics_halves(all_maps, win_maps):
    """Combine the cached all-time fold with the windowed one.

    `win_maps` is `all_maps` itself when no range was selected - every row is
    inside an open window, so the windowed half is the all-time fold over
    again. The halves are copied apart in that case, which is what a second
    pass would have produced without the second pass, and it keeps a caller
    that mutates one half out of the other (and out of the cache).

    An entry only the windowed half knows cannot exist: the windowed pass
    stops where the all-time fold stopped, so every row it saw is already in
    there.
    """
    shared = win_maps is all_maps
    acct_map = {}
    for uid, entry in all_maps["accts"].items():
        win = win_maps["accts"].get(uid)
        if shared:
            window_stat = dict(entry["all_time"])
            window_models = _copy_analytics_models(entry["all_models"])
        elif win is None:
            window_stat = _new_analytics_stat()
            window_models = {}
        else:
            window_stat = win["window"]
            window_models = win["window_models"]
        acct_map[uid] = {
            "uid": uid,
            "nickname": uid,
            "realm": entry["realm"],
            "domain": "",
            "window": window_stat,
            "all_time": dict(entry["all_time"]),
            "window_models": window_models,
            "all_models": _copy_analytics_models(entry["all_models"]),
        }
    model_map = {}
    for m_id, entry in all_maps["models"].items():
        stat = entry["all_time"]
        win = win_maps["models"].get(m_id)
        if shared:
            window_stat = dict(stat)
        elif win is None:
            window_stat = _new_analytics_stat()
        else:
            window_stat = win["window"]
        model_map[m_id] = {"model": m_id, "window": window_stat,
                           "all_time": dict(stat)}
    key_map = {}
    for k_id, km in all_maps["keys"].items():
        win = win_maps["keys"].get(k_id)
        if shared:
            window_stat = dict(km["all_time"])
            window_models = _copy_analytics_models(km["all_models"])
        elif win is None:
            window_stat = _new_analytics_stat()
            window_models = {}
        else:
            window_stat = win["window"]
            window_models = win["window_models"]
        key_map[k_id] = {
            "key": k_id,
            "window": window_stat,
            "all_time": dict(km["all_time"]),
            "window_models": window_models,
            "all_models": _copy_analytics_models(km["all_models"]),
            "realms": dict(km["realms"]),
            "last_at": km["last_at"],
        }
    return {"summary": dict(all_maps["summary"]),
            "window_summary": (dict(all_maps["summary"]) if shared
                               else win_maps["summary"]),
            "accts": acct_map, "models": model_map, "keys": key_map}


# ---------------------------------------------------------------------------
# 按日分桶：窗口半的增量
#
# all-time 半已经是增量（按字节偏移折叠 + 落盘 checkpoint），但窗口半
# （range=today / week / month）仍然是「从头扫到窗口」：窗口越宽扫得越多，
# 路由器上一次 range=week 要 5 秒。窗口的边界全是本地午夜（range_window()），
# 而每行只属于一天，所以只要在折叠时顺手把每一行折进「它所属那天的桶」，
# 任何窗口就退化成「把窗口内的日桶相加」——O(天数)，checkpoint 带着日桶
# 时冷缓存也是瞬间。
#
# 时间边界只认一个规则：行的本地日由行自己的 at 决定（_local_day_key），
# 与 range_window() 的 today/week/month 用的是同一套本地午夜。折叠时刻不
# 参与切天——迟写/补写的行必须落进它时间戳所属的那天，按折叠时刻切会让
# 窗口相加错位。跨夏令时同理：日桶的键是本地日历日，只要窗口起点是本地
# 午夜，「日键 >= 窗口日键」就是「at >= since」的等价写法（见 _window_day_key）。
#
# 已封口的日桶不会再变（新行只落进今天那一桶），窗口相加时旧桶原样复用；
# 状态只在新建桶时剪枝（_prune_day_buckets），剪掉的只是任何窗口都够不到
# 的天。剪枝会抬高 days_floor，任何够不到的天都因此退回整段扫描——宁可多
# 扫一次，不能少算一天。
#
# analytics 的日桶还挂一层小时子表（保留线更短，只给自定义区间用，见
# 「analytics 的小时层」一节）：那不是日桶的一部分，日桶求和原样忽略它。
#
# 浮点求和的口径：窗口 = 日桶逐日相加，与旧实现「整段扫描逐行累加」的区别
# 只是浮点的结合顺序（credit / cost_cny / speed_sum 可能差最后一两个 ulp，
# 整数字段逐位相同）。逐行顺序无法从日聚合还原，这是日桶推导的固有代价；
# 本文件里所有对齐窗口的路径统一用「按日分组」的口径（冷扫描、日桶、加载
# checkpoint 三条路径给出的字节完全一致），把「像没有缓存一样正确」保成
# 路径之间的一致性；analytics 的小时窗口同理，只是分组的粒度换成小时。
# WB_USAGE_DAY_BUCKETS=0 可整体退回旧的逐行口径。
#
# 小时层（T9）：日桶只服务「起点是本地午夜」的窗口，而面板的自定义区间
# （range=custom）起点是任意时刻——最常见的形态就是整点（datetime-local
# 输入框给的是分钟粒度，操作者选整点的概率远高于选 37 分）。于是每个日桶
# 里再挂一张小时子表（_usage_hour_bucket），起点落在本地整点上的窗口由
# 「整小时桶之和」回答：token/requests/credit 与成本字段（cost_cny /
# cost_missing / by_model_acct）全部来自同一份桶，口径与整段扫描一致，不
# 需要像「借时间序列的小时桶」那样丢掉成本列（series 不算价，D3）。
# 小时层比日桶短命（_usage_hour_keep_days），覆盖不到就退回按小时分组的
# 冷路径——两条路径的字节逐字节相同，语义与改动前一致（只是浮点结合顺序
# 按小时而不是按行）。
# ---------------------------------------------------------------------------

# 日桶保留天数：月窗口最多回溯 30 天（当月 1 号），32 天留两天余量。更早的
# 天没有任何窗口够得到，留着只让 checkpoint 白白变大——路由器上每次写盘都
# 要重写整份文件。调小它（WB_USAGE_DAY_KEEP_DAYS）会让更宽的窗口退回整段
# 扫描（结果仍然正确，只是慢）：对 flash 写入敏感的部署可以调到 8，只保周。

# 小时桶保留天数：小时层只服务面板的自定义整点窗口（操作者回头看最近一两
# 天的某个整点），保留 2 天 = 最少 48 小时、最多 72 小时（剪枝按天走，见
# _prune_hour_buckets）。再往前的小时桶没有任何现实窗口够得到，而每个小时
# 桶都是完整的一份窗口半快照（含 by_model_acct 三层结构，实测约 2KB/桶）
# ——路由器上 checkpoint 每多一份都要跟着重写，flash 写入慢且费寿命。覆盖
# 不到的窗口退回冷路径，结果正确，只是慢。WB_USAGE_HOUR_KEEP_DAYS 可调；
# 对 flash 特别敏感的部署可以调到 1（只保今天，24~48 小时）。

# 日桶求和要跳过的字段：started 是每份快照各自的创建时刻，不是累计量。
# 与 _USAGE_CACHE_SNAPSHOT_NUMBERS 同源（同一份构造函数的数字字段），只是
# 在模块加载顺序上不能引用它（那段常量在文件更靠后），所以这里自己推导。


# analytics 小时子表的保留小时数：小时层只为近期的自定义窗口服务，而每个小时
# 桶的形状与日桶一样重（summary + 每账号/每模型/每 key），跟着 32 天的日桶
# 全留会让 checkpoint 膨胀十几倍。48 小时覆盖「从昨天某个整点起」这类最常用
# 的手动窗口，剪枝又在每天新建日桶时跑一次，实际保留 48~72 小时。调大只是让
# checkpoint 变大（层覆盖更宽），调小只是让更早的自定义窗口退回整段扫描
# （结果仍然正确，只是慢）。


# 闭窗口边沿账的上限：只有「at 恰好落在整秒上」的行进账，真实日志里几乎为
# 零（at 是 time.time() 的浮点秒，落在整秒上的概率约百万分之一）。手改过的
# 日志可能有很多，超过上限就停记并留痕——闭窗口退回整段扫描，正确性优先。


# ---------------------------------------------------------------------------
# 时间序列的日/小时/分钟桶
#
# usage_timeseries() 本来就把行按时间装桶，但每次缓存未命中都要整段扫描
# （路由器上 range=week 约 2 秒）。窗口边界同样是本地午夜，而它的桶宽只有
# 3600 与 86400 两种能与窗口对齐；span<=6h 的窗口（自定义区间，选择器
# 见 _usage_timeseries_scope）给出 step=60，边界是任意分钟格点，日/小时桶
# 都答不了——这一档由「最近 6 小时的分钟环」回答（见 _fold_usage_series_minute）。
# 折叠时顺手维护这三层，窗口就是它们的切片：每个输出桶恰好等于一个存量桶
# （不做跨桶相加），所以连浮点求和都是逐位一致的——不像 snapshot/analytics
# 的窗口半需要把日桶相加。
# ---------------------------------------------------------------------------
# credit 历史只保留最近这么多条（整段扫描返回的也是窗口内的前 50 条）。
# 分钟环的保留窗口：6 小时，与选择器给出 step=60 的最大跨度（span<=6h）一一
# 对应。分钟桶比小时桶密 60 倍，跟着日桶的 32 天保留会让 checkpoint 翻好几倍，
# 而更早的窗口本来就该由小时层（step=3600）回答——所以环只留最近 6 小时。
# 保留线用「桶的 at 严格小于 max_at - 窗口」判定，窗口服务条件写成
# lo >= max_at - 窗口；两者一配对，服务得上的窗口需要的桶恰好一个不落
# （窗口起点必须落在分钟格点上，见 _series_minute_grid_ok）。
# 折叠途中环的临时上限：超过就按保留线剪一次。剪枝是 O(环大小)、而环的
# 正常大小 <= 361（6 小时 + 两个端点），720 是给「冷折时环里还堆着更早的
# 桶」留的余量——这样整趟冷折的内存有界（满环约 200KB），不用等折完才剪。


def _top_models(bucket, top_n=KEY_MODEL_TOP_N):
    """Split a model bucket into the N busiest models plus one remainder.

    The remainder is flagged with `other` rather than being recognised by its
    label, so a model genuinely called "(其他)" cannot be mistaken for it.
    """
    items = sorted(bucket.items(), key=lambda kv: (-kv[1]["tokens"], -kv[1]["requests"], kv[0]))
    head = [{"model": mid, "requests": s["requests"], "tokens": s["tokens"],
             "reasoning": s["reasoning"]} for mid, s in items[:top_n]]
    rest = items[top_n:]
    other = None
    if rest:
        other = {
            "model": "(其他)",
            "other": True,
            "models": len(rest),
            "requests": sum(s["requests"] for _, s in rest),
            "tokens": sum(s["tokens"] for _, s in rest),
            "reasoning": sum(s["reasoning"] for _, s in rest),
        }
    return head, other


def _build_key_rows(key_map, realm=None):
    """Merge observed per-key traffic with the configured key roster.

    Every key the panel can still see gets a row even with no traffic in the
    window: a key that was used yesterday and not today is a fact about
    today's spend, and dropping it would read as "the key is gone". A key that
    is disabled *and* idle in this window is dropped, because that row says
    nothing about the selected range.

    The reverse direction matters just as much: an id seen in the log that the
    roster does not know still gets a row, so the per-key table always adds up
    to the per-account table. Those are folded into a single row - ids that
    cannot be named are an anomaly, not a dimension worth splitting.
    """
    key_map = key_map or {}
    rows = {}

    def empty_row(k_id, name, declared_realm, enabled, source):
        return {
            "key": k_id,
            "name": name,
            "realm": declared_realm,
            "enabled": enabled,
            "source": source,
            "window": _new_analytics_stat(),
            "all_time": _new_analytics_stat(),
            "window_models": {},
            "all_models": {},
            "realms": {},
            "last_at": 0,
        }

    for entry in configured_keys():
        k_id = entry.get("id") or ""
        if not k_id:
            continue
        declared = entry.get("realm") or ""
        # A key bound to the other exit can never have rows in this view.
        if realm and declared and declared != realm:
            continue
        rows[k_id] = empty_row(k_id, entry.get("name") or k_id, declared,
                               entry.get("enabled", True) is not False, "panel")
    # The launcher key (--api-key / API_KEY) lives in no settings file, so it
    # is only ever visible as an id in the log. It is not an attribution
    # dimension: once the panel holds any key of its own the launcher key is
    # no longer accepted at all (see identify_key), so an unused one is a
    # permanent zero that says nothing about who spent what. Give it a row
    # only when the log shows it was actually used - the only state in which
    # it carries history worth reconciling.
    if "launcher" not in rows and "launcher" in key_map:
        rows["launcher"] = empty_row("launcher", "启动参数", "", True, "launcher")

    def adopt(row, km):
        row["window"] = km["window"]
        row["all_time"] = km["all_time"]
        row["window_models"] = km["window_models"]
        row["all_models"] = km["all_models"]
        row["realms"] = km["realms"]
        row["last_at"] = km["last_at"]

    unknown = None
    for k_id, km in key_map.items():
        if k_id == KEY_BUCKET_BEFORE:
            rows[k_id] = empty_row(k_id, "(切换前)", "", False, "bucket")
            adopt(rows[k_id], km)
        elif k_id == KEY_BUCKET_ANON:
            rows[k_id] = empty_row(k_id, "(无 key)", "", False, "bucket")
            adopt(rows[k_id], km)
        elif k_id in rows:
            adopt(rows[k_id], km)
        else:
            if unknown is None:
                unknown = rows[KEY_BUCKET_UNKNOWN] = empty_row(
                    KEY_BUCKET_UNKNOWN, "(未知 key)", "", False, "bucket")
            _add_analytics_stat(unknown["window"], km["window"])
            _add_analytics_stat(unknown["all_time"], km["all_time"])
            for tgt, src in ((unknown["window_models"], km["window_models"]),
                             (unknown["all_models"], km["all_models"])):
                for mid, s in src.items():
                    dst = tgt.setdefault(mid, {"requests": 0, "tokens": 0, "reasoning": 0})
                    dst["requests"] += s["requests"]
                    dst["tokens"] += s["tokens"]
                    dst["reasoning"] += s["reasoning"]
            for k_realm, count in km["realms"].items():
                unknown["realms"][k_realm] = unknown["realms"].get(k_realm, 0) + count
            unknown["last_at"] = max(unknown["last_at"], km["last_at"])

    out = []
    for row in rows.values():
        if (row["source"] == "panel" and not row["enabled"]
                and not row["window"]["requests"] and not row["window"]["errors"]):
            continue
        _finalize_analytics_stat(row["window"])
        _finalize_analytics_stat(row["all_time"])
        row["models"], row["models_other"] = _top_models(row["window_models"])
        # A key with no realm binding follows the model it is asked for, so it
        # can serve both exits - and then its credit column adds up two
        # different products' prices. The page has to be able to say so.
        row["cross_realm"] = len([x for x in row["realms"] if x]) > 1
        out.append(row)
    out.sort(key=lambda r: (-r["window"]["total_tokens"], -r["all_time"]["total_tokens"], r["name"]))
    return out


def _finalize_analytics_stat(stat_obj):
        p = stat_obj["prompt_tokens"]
        c = stat_obj["cached_tokens"]
        out = stat_obj["completion_tokens"]
        reas = stat_obj["reasoning_tokens"]
        stat_obj["cache_hit_pct"] = round((c / p * 100), 1) if p > 0 else 0.0
        stat_obj["reasoning_ratio"] = round((reas / out * 100), 1) if out > 0 else 0.0
        stat_obj["ttft_ms_avg"] = round(stat_obj["ttft_sum"] / stat_obj["ttft_n"]) if stat_obj["ttft_n"] > 0 else 0
        stat_obj["speed_avg"] = round(stat_obj["speed_sum"] / stat_obj["speed_n"], 1) if stat_obj["speed_n"] > 0 else 0.0
        stat_obj["elapsed_ms_avg"] = round(stat_obj["elapsed_sum"] / stat_obj["elapsed_n"]) if stat_obj["elapsed_n"] > 0 else 0
        return stat_obj

def _compute_usage_analytics_uncached(realm=None, since=None, until=None):
    """Detailed analytics for Token, Cache, and Reasoning metrics page."""
    # 与 /usage 快照同一条规矩：一次扫描里总开关只问一次，值传进折叠与指纹。
    pricing_on = False
    all_maps, offset = _analytics_all_time(realm, pricing_on)
    if since is None and until is None:
        # An open window covers every row, so the windowed half is the
        # all-time fold over again; the merge copies the two apart.
        win_maps = all_maps
    else:
        # The all-time half is not re-folded: the windowed half comes from
        # the day buckets that fold advanced (or, failing that, from a pass
        # that stops where that fold stopped), so one page never mixes two
        # reads.
        win_maps = _analytics_window(realm, since, until, offset, pricing_on)
    parts = _merge_analytics_halves(all_maps, win_maps)
    acct_map = parts["accts"]
    model_map = parts["models"]
    key_map = parts["keys"]
    # 账号池已移除：分析里的「账号」只是日志行上的标签，没有昵称/区域可补。
    all_summary = parts["summary"]
    window_summary = parts["window_summary"]
    _finalize_analytics_stat(all_summary)
    _finalize_analytics_stat(window_summary)
    for a in acct_map.values():
        _finalize_analytics_stat(a["window"])
        _finalize_analytics_stat(a["all_time"])
    for m in model_map.values():
        _finalize_analytics_stat(m["window"])
        _finalize_analytics_stat(m["all_time"])
    accts_list = sorted(acct_map.values(), key=lambda a: (-a["window"]["total_tokens"], -a["all_time"]["total_tokens"]))
    models_list = sorted(model_map.values(), key=lambda m: (-m["window"]["total_tokens"], -m["all_time"]["total_tokens"]))
    keys_list = _build_key_rows(key_map, realm=realm)
    return {
        # The resolved window travels with the payload so the page can label
        # its first column from what the server actually applied, not from
        # what the panel hoped it sent.
        "window": {"since": since, "until": until},
        "realm": realm or "all",
        # Cost figures are CNY; the panel divides by this rate to show USD.
        "usd_cny": 0.0,
        "summary": {"window": window_summary, "all_time": all_summary},
        "accounts": accts_list,
        "models": models_list,
        # Same rows, folded by the API key that called the gateway instead of
        # by the upstream account that served the call. One key can be served
        # by several accounts and one account can serve several keys, so this
        # is a second view of the same spend, not a breakdown of it.
        "keys": keys_list,
    }


# ---------------------------------------------------------------------------
# 聚合状态落盘（重启后免冷扫）
#
# 上面的几份增量聚合（_usage_alltime_snapshot / _usage_by_account_buckets /
# _analytics_all_time / 时间序列 / 剩余用量）把状态放在模块级字典里，进程一
# 重启就全丢：第一次刷新仍是全量扫一遍日志。日志每天涨一万多行，冷扫描成本
# 跟着线性上升——路由器上 2.7 万行的一次冷启动要 6~8 秒，一个月后接近两分钟。
# 这里把每份状态连同它们的位置信息写进数据目录，重启后第一次刷新只读文件尾
# 部的新增字节。
#
# v4 起**一类状态一份文件**（usage-aggregate-cache-<kind>.json）：五份状态
# 各有各的位置/指纹校验与写入节流，加载端按需解析——只跑 /usage 的进程不再
# 为其余四份（真机上 remaining 一份就比其余加起来还大）付解析成本；写侧也只
# 重写「有推进的那一类」。升级前的单文件（v3）只读兼容：某一类还没有自己的
# 文件时从旧文件里取它那一节（旧文件不重写、也不删除，等各类都落过一次盘就
# 自然被忽略）。
#
# 文件放在数据目录里是刻意的：它和日志同生命周期，跟着 sysupgrade 一起走，
# 也和日志一起被搬走、清掉。读写失败（只读文件系统、磁盘满、权限不足）一律
# 静默降级——checkpoint 只是加速，丢的是一次加速，绝不能影响服务本身。
#
# 加载校验复用 #189 已有的原语，不另造一套：offset 必须仍落在同一个文件的
# 现有字节里（_log_offset_holds），offset 前的最后 64 字节必须与写下时一致
# （_log_tail_signature），再加上价格/realm 指纹和 schema 版本。任何一项对不
# 上就当没有缓存、走全量——宁可多扫一次，也不能给出错的数字。
# ---------------------------------------------------------------------------

# 数据目录下的文件名。usage/*.json 已被 .gitignore 覆盖。
# 带 <kind> 的是 v4 布局（一类一份）；不带的是升级前的单文件，只读不写。
# 状态结构或折叠口径一变就 +1，旧文件整体作废。这是唯一挡在「旧结构喂进新
# 代码」前面的东西，改动状态形状时别忘了它。
# v2：写盘不再排序（v1 用 sort_keys 写，加载回来所有 dict 变字母序，响应
# 与冷启动逐字节不同）。键顺序算状态结构的一部分，所以旧文件必须整体作废
# ——否则那份字母序会一直粘在内存里，直到日志尾部被重写才会被清掉。
# v3：状态多了按日分桶（窗口半的增量）与时间序列的日/小时桶。载荷形状变了，
# 旧文件同样整体作废：升级后第一次刷新做一次全量折叠（一次性代价，之后
# checkpoint 照旧）——这正是把窗口半也变成增量的入场费。
# v4：一类状态一份文件（每份自带 schema 与 kind 标签），并且快照/analytics 的
# 日桶里多了小时子表（整点窗口的小时层）、series 多了分钟环。载荷形状的变化由
# 各类自己的校验器挡住：升级前的单文件（v3）只读兼容，作为各类还没有自己文件
# 时的回退来源——能通过新校验器的段（by_account / series / remaining）照常
# 采纳，通不过的（缺小时表的 snapshot / analytics）在升级后第一次刷新时做一次
# 全量折叠，之后 checkpoint 照旧。
# v5：snapshot / analytics 的 "pricing" 字段从「三张表的内容摘要」（["on", d1,
# d2, d3] / ["off"]）换成「折叠行真正用到的价」记录（T15）。旧条目的字段形状
# 对不上新判定，采纳端直接拒——升级后第一次刷新一次性重折（与 v3→v4 同处置），
# 之后价表再变只按「用到的价」判废（无关模型的价变动不再重折）。
# 升级前唯一布局的版本号：v3 单文件。只出现在只读回退路径上。
# 五类状态的固定集合。测试枚举五份缓存文件时以它为唯一契约源（40 处引用
# 都在测试里）；写盘循环各自按字面量写，别处新增 kind 记得同步这里。
_USAGE_CACHE_KINDS = ("snapshot", "by_account", "analytics", "series",
                      "remaining")


# 写盘串行锁：只被 _usage_cache_maybe_save() 拿一次、且永远是最外层（拿它
# 之后才拿状态锁/节流锁），所以它不参与任何锁序环。
# 进程启动后按「类」只读一次 checkpoint：读到就记下来，读不到也记 None——
# 坏文件、只读文件系统都不该让每次刷新都去解析一遍。只解析调用方真正要的
# 那一类，这正是拆文件的意义（只跑 /usage 的进程不解析 remaining）。
# 升级前的单文件（v3）也只读一次，作为某一类还没有自己文件时的回退来源。
# 写盘节流状态，全部由 _usage_cache_lock 保护：
#   progress[kind]     —— 本进程见过该类状态折叠到的最远 offset；
#   checkpointed[kind] —— 该类状态上次「尝试」落盘时的 offset（失败也记，
#                         只读文件系统上不能每次刷新都去试写一遍）；
#   last_attempt       —— 上次尝试写盘的时刻，时间阈值与失败退避都靠它。
# 按「类」记账而不是记一个总数：某类状态第一次折叠（或中途重扫）时 offset
# 从 0 跳到文件尾，这一类要尽快落盘，而刚采用过 checkpoint 的类不能被别的
# 类的推进带着白写一遍。v4 起写盘也按类分开：只重写「有推进的那一类」。


# 折叠会就地累加/读取的字段集合直接从构造函数推导：上游往 _empty_stats() 或
# _new_analytics_stat() 里加字段时这里自动跟着收——漏一个，放行的缓存就会在
# 折叠半路抛 KeyError，那次刷新报出半份数字（折叠的错误路径只保留已折的
# 部分）。
# 时间序列桶的数字字段（_new_series_bucket 的键，含 at）。从构造函数推导，
# 与上面两条同一个道理：上游加字段时校验自动跟着收。


# 分钟环落盘行的字段顺序：[分钟, 这 8 个数字]（at 由分钟推出，省下每桶 10
# 字节；credit 在最后，与 _new_series_bucket 的键序一致）。


def runtime_settings_view():
    """Current panel-visible settings (never returns the password or the key)."""
    key = API_KEY or ""
    if len(key) > 8:
        masked = key[:4] + "*" * 6 + key[-4:]
    else:
        masked = "*" * len(key)
    keys = []
    for entry in configured_keys():
        raw = entry.get("key") or ""
        keys.append({
            "id": entry.get("id") or "",
            "name": entry.get("name") or "",
            "realm": entry.get("realm") or "",
            "models": list(entry.get("models") or []),
            "enabled": entry.get("enabled", True) is not False,
            "masked": (raw[:4] + "*" * 6 + raw[-4:]) if len(raw) > 8 else "*" * len(raw),
            "source": entry.get("source") or "panel",
            "created_at": entry.get("created_at") or "",
        })
    # Deleted keys are read-only history: the secret is gone, so the panel can
    # only list them (name and dates) and must not offer a copy button.
    deleted_keys = []
    for entry in ca_settings.api_keys(ACCOUNTS_DIR, include_deleted=True):
        if not entry.get("deleted_at"):
            continue
        deleted_keys.append({
            "id": entry.get("id") or "",
            "name": entry.get("name") or "",
            "realm": entry.get("realm") or "",
            "created_at": entry.get("created_at") or "",
            "deleted_at": entry.get("deleted_at") or "",
        })
    return {
        "panel_password_is_default": ca_settings.panel_password_is_default(ACCOUNTS_DIR),
        "api_key_set": bool(key),
        "api_key_set_by_panel": API_KEY_FILE_SET,
        "api_key_masked": masked,
        "auth_required": auth_required(),
        "api_keys": keys,
        "deleted_api_keys": deleted_keys,
        "daily_token_limit": ca_settings.daily_token_limit(ACCOUNTS_DIR),
        "daily_credit_limit": ca_settings.daily_credit_limit(ACCOUNTS_DIR),
        "model_daily_token_limit": ca_settings.model_daily_token_limit(ACCOUNTS_DIR),
        "section_max_height": ca_settings.section_max_height(ACCOUNTS_DIR),
        "ui_language": ca_settings.ui_language(ACCOUNTS_DIR),
        "enable_anthropic_messages": ca_settings.enable_anthropic_messages(ACCOUNTS_DIR),
        "egress_backoff_enabled":
            ca_settings.egress_backoff_enabled(ACCOUNTS_DIR),
        "log_db_enabled": ca_settings.log_db_enabled(ACCOUNTS_DIR),
        "log_db_max_rows": ca_settings.log_db_max_rows(ACCOUNTS_DIR),
        "log_db_max_days": ca_settings.log_db_max_days(ACCOUNTS_DIR),
        "log_db_max_bytes": ca_settings.log_db_max_bytes(ACCOUNTS_DIR),
        "accounts_collapsed": ca_settings.accounts_collapsed(ACCOUNTS_DIR),
        "accounts_separate_tab": ca_settings.accounts_separate_tab(ACCOUNTS_DIR),
        "key_before_hidden": ca_settings.key_before_hidden(ACCOUNTS_DIR),
        "hidden_pages": ca_settings.hidden_pages(ACCOUNTS_DIR),
        "update_check_enabled": ca_settings.update_check_enabled(ACCOUNTS_DIR),
        "upstream": ca_settings.upstream_config(ACCOUNTS_DIR),
        "codearts": ca_settings.codearts_config(ACCOUNTS_DIR),
        "usage": ca_settings.usage_config(ACCOUNTS_DIR),
        "prompt": ca_settings.prompt_config(ACCOUNTS_DIR),
        "accounts_dir": ACCOUNTS_DIR,
        "usage_dir": USAGE_DIR,
        "settings_file": ca_settings.settings_path(ACCOUNTS_DIR),
        "version": "1.7.10",
    }
LOG_BUFFER = deque(maxlen=2000)
_LOG_LOCK = threading.Lock()
_LOG_COUNTER = 0

# 日志级别与模块的自动归类。调用点显式传了 level/tag 就用传的，没传才按内容猜。
#
# 级别：早先只认英文关键字，而本仓大量日志是中文——定价侧的「抓取失败，继续用
# 上一版价格」「首次抓取异常」全被判成 INFO，看板上按 ERROR 筛选根本看不到它们。
# 中文关键字补上后这些才落到正确的级别。英文侧同样收紧了几个明显的漏网（"fail"
# 只认 "failed"，"fail:" 这种短标签一直没被认出来）。
_LOG_ERROR_HINTS = (
    "error", "exception", "failed", "fail:", "reject", "traceback", "errno", "fatal",
    "11-128", "11101", "11140",
    "失败", "异常", "错误", "拒绝", "不可用", "无效",
)
_LOG_WARN_HINTS = (
    "warn", "warning", "retry", "timeout", "throttl",
    "重试", "超时", "告警", "警告", "降级", "限流",
)
# 模块：顺序即优先级，越靠前越先判定。新增的 pricing / egress / upstream /
# update / usage / webtools 都是从原先那个大杂烩 "system" 里拆出来的——这些
# 模块本来就在打日志，只是推断规则不认识它们的词，于是一律归到 system，事后
# 想按模块看某一类问题时筛不出来。原有类别（chat/accounts/catalog/auth/
# settings）的相对顺序保持不变，避免改变既有日志的归类。
_LOG_TAG_HINTS = (
    ("chat", ("chat:", "chat done", "request error", "/v1/chat",
              "/chat/completions", "responses")),
    ("accounts", ("account", "账号", "pool", "imported")),
    ("pricing", ("pricing", "定价", "取价", "价格", "price", "抓取")),
    ("egress", ("egress", "出口", "槽位", "proxy slot", "mihomo")),
    ("upstream", ("upstream", "上游")),
    ("catalog", ("model", "catalog", "模型")),
    ("auth", ("auth", "token", "oauth")),
    ("settings", ("settings", "设置")),
    ("update", ("更新", "release")),
    ("usage", ("usage", "用量")),
)

# 可选的 SQLite 落库（默认关闭）。None = 还没初始化（模块 import 期），启动时按
# settings 建好，之后由面板开关驱动 ca_logstore.LogStore.configure()。关闭时它
# 要么是 None、要么 enabled=False，整条日志路径与上游一字不差：只写内存环形
# 缓冲，不建库、不落盘。
LOG_STORE = None


def _log_db_active():
    return LOG_STORE is not None and LOG_STORE.enabled


#: 日志里把控制字符换成可见的转义写法。上游错误体是自由文本，
#: ``{"error_msg": "bad request\r\n at line 3"}`` 这种形状非常常见。
_CTRL_ESCAPES = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}


def _one_line(msg):
    """把任意文本压成**一条**日志记录。

    换行转义成两个字面字符 ``\\n``（不是真的换行），其余 C0 控制字符与
    ``\\x7f`` 一并转义。日志行是「时间 + 一条消息」的结构，任何裸换行都会在
    后面凭空多出一条没有时间戳的行 —— 落进 stderr、sqlite 和面板是三份同样
    的错误，而看日志的人会把后半截当成另一个事件。

    快速路径不建列表：绝大多数日志里一个控制字符都没有，字符串里扫一次就够。
    """
    text = str(msg).rstrip()
    if not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text):
        return text
    out = []
    for ch in text:
        if ch in _CTRL_ESCAPES:
            out.append(_CTRL_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append("\\x%02x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def add_log_entry(msg, level=None, tag=None):
    global _LOG_COUNTER
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    t_short = time.strftime("%H:%M:%S")
    msg_str = _one_line(msg)
    if not level:
        lower = msg_str.lower()
        if any(k in lower for k in _LOG_ERROR_HINTS):
            level = "ERROR"
        elif any(k in lower for k in _LOG_WARN_HINTS):
            level = "WARN"
        else:
            level = "INFO"
    if not tag:
        lower = msg_str.lower()
        for candidate, hints in _LOG_TAG_HINTS:
            if any(k in lower for k in hints):
                tag = candidate
                break
        else:
            tag = "system"
    with _LOG_LOCK:
        _LOG_COUNTER += 1
        entry = {
            "id": _LOG_COUNTER,
            "ts": ts,
            "time": t_short,
            "level": level,
            "tag": tag,
            "msg": msg_str,
        }
        LOG_BUFFER.append(entry)
    # 落库在锁外：append 只是入队，但没必要把持锁时间拉长到调用 queue.put。
    if _log_db_active():
        LOG_STORE.append(entry)
    return entry

#: 当前线程正在服务的请求 id。每个请求一个线程（ThreadingHTTPServer），
#: 所以在 dispatch 入口设一次，这条请求打出的所有日志行都会自动带上它 ——
#: 不必给几十个 log() 调用点各加一个参数，也不会漏掉以后新增的那些。
_REQ_ID = threading.local()


def new_request_id():
    """一条请求的短 id：8 位十六进制，够用又不至于把日志行挤长。"""
    return uuid.uuid4().hex[:8]


def set_request_id(value):
    _REQ_ID.value = value or ""


def current_request_id():
    return getattr(_REQ_ID, "value", "") or ""


def log(msg, level=None, tag=None, req=None):
    """写一条日志：stderr 与面板/落库是同一条记录。

    行首自动带上当前请求 id（见 ``new_request_id``）：同一条请求的重试、
    断流、失败各自是独立的三条日志，以前它们唯一的共同点是「模型名相同」，
    并发一上来就对不上号。
    """
    line = _one_line(msg)
    req = req or current_request_id()
    if req:
        line = "[%s] %s" % (req, line)
    sys.stderr.write("[codearts-hub] %s %s\n" % (time.strftime("%H:%M:%S"), line))
    sys.stderr.flush()
    add_log_entry(line, level=level, tag=tag)


def get_logs(limit=200, level="", tag="", search="", since_id=0):
    # 落库开启时以数据库为准：它是完整历史（受保留上限约束），而内存环形缓冲
    # 只留最新 2000 条，拿它回答会看不到刚过去的窗口。查询失败或超时就退回内存，
    # 面板宁可少看历史，也不能因为日志库出问题而整页空白。
    if _log_db_active():
        try:
            stored = LOG_STORE.query(limit=limit, level=level, tag=tag,
                                     search=search, since_id=since_id)
        except Exception:
            stored = None
        if stored is not None:
            return stored
    with _LOG_LOCK:
        items = list(LOG_BUFFER)
    if since_id > 0:
        items = [x for x in items if x["id"] > since_id]
    if level:
        items = [x for x in items if x["level"] == level.upper()]
    if tag:
        items = [x for x in items if x["tag"].lower() == tag.lower()]
    if search:
        s = search.lower()
        items = [x for x in items if s in x["msg"].lower() or s in x["tag"].lower()]
    total = len(items)
    if limit and limit > 0 and since_id == 0:
        items = items[-limit:]
    max_id = items[-1]["id"] if items else since_id
    return {"total": total, "logs": items, "max_id": max_id}

def clear_logs():
    with _LOG_LOCK:
        LOG_BUFFER.clear()
    if _log_db_active():
        try:
            LOG_STORE.clear()
        except Exception:
            pass


def apply_log_db_settings():
    """Read the panel's log-database settings into the live store.

    Called once at startup (after USAGE_DIR is settled) and again on every
    settings save, so flipping the switch or editing a cap takes effect at once
    without a restart. Also pulls the id counter up to whatever the database
    already holds, so ids stay monotonic across a restart and the panel's
    `since_id` incremental fetch keeps working.
    """
    global _LOG_COUNTER
    if LOG_STORE is None:
        return False
    LOG_STORE.configure(
        ca_settings.log_db_enabled(ACCOUNTS_DIR),
        max_rows=ca_settings.log_db_max_rows(ACCOUNTS_DIR),
        max_days=ca_settings.log_db_max_days(ACCOUNTS_DIR),
        max_bytes=ca_settings.log_db_max_bytes(ACCOUNTS_DIR),
    )
    if LOG_STORE.enabled:
        try:
            highest = LOG_STORE.max_id()
        except Exception:
            highest = 0
        with _LOG_LOCK:
            if highest > _LOG_COUNTER:
                _LOG_COUNTER = highest
    return LOG_STORE.enabled

# ---------------------------------------------------------------------------
# upstream helpers
# ---------------------------------------------------------------------------
#: Auxiliary models the API advertises but that are not usable for chat.
#: "lite" backs internal helpers (title generation, compaction) and upstream
#: rejects it with 11102; the codewise/completion entries are text-completion
#: or IDE-inline models, not chat models.
def catalog_meta(realm=None):
    """The provenance of the last list built for a realm, for the panel.

    {"source": "remote" | "endpoint" | "cache" | "legacy" | "bundled",
     "fetched_at": unix seconds when the gateway obtained the batch,
     "file_mtime": unix seconds of the desktop cache file's own write
                   (only for the config-file sources), else None}
    """
    r = realm or CURRENT_REALM
    with _lock:
        meta = _catalog_meta.get(r)
        return dict(meta) if meta else None


# ---------------------------------------------------------------------------
# 码道（华为云）模型目录与路由
# ---------------------------------------------------------------------------
#
# 码道账号与 WorkBuddy 账号池是两套独立的凭证体系，但**对外的 OpenAI 面应该
# 是同一份**：客户端只认 /v1/models 与 /v1/chat/completions，不该为码道模型
# 学一套新地址。所以这里把码道清单并进 /v1/models，并在聊天入口按模型名分流。
#
# 分流判定用 ca_codearts.CHAT_MODELS —— 那是**逐个真实推理验证过**的名单，
# 不是「服务端报了什么就信什么」（内置/限时福利两组都实测过，见 ca_codearts
# 里 chat_headers 的注释）。

#: 码道账号的**并发会话上限只有 3 个**（撞上就是 400 TM.00001041）。
#:
#: 旧值是 1（彻底串行）。那是错的：账号能给 3 个，网关自己只放 1 个，第二个
#: 请求就得**等前一个生成完**才算开始 —— 一条三千字的回答要几分钟，用户看到
#: 的就是「发出去没反应」。2026-10-22 实测：两个客户端并发，第二个卡 4 分钟。
#:
#: 现在默认 2：留一个名额给账号上的其它使用者（本机 CodeArts IDE、另一台机器），
#: 撞车时靠下面的排队超时 + 429 兜住，而不是死等。可用 CODEARTS_CONCURRENCY 调。
CODEARTS_CONCURRENCY = ca_env.number("CODEARTS_CONCURRENCY", 2,
                                     minimum=1, integer=True)

#: 拿不到并发名额时最多等多久（秒）。超时立刻回 429 而不是无限排队 ——
#: 排队中的请求没有任何反馈，客户端只能干等到自己超时（ZCode 4 分钟）。
CODEARTS_SLOT_WAIT = ca_env.number("CODEARTS_SLOT_WAIT", 20.0,
                                   minimum=0.0, zero_ok=True)

#: 撞上「并发会话已满」时的退避序列。它和 TPM 限流不是一回事：名额在别人手里，
#: 通常一秒级就会释放，用不着 5/12/25/40（合计 82 秒）那么久 —— 那 82 秒里
#: 客户端早自己重试了，反而叠出更多会话。
CODEARTS_BUSY_DELAYS = (2.0, 5.0, 8.0)

#: 一般瞬时限流（TPM 打满）的退避。额度按分钟恢复，等得久一点才有效。
CODEARTS_RETRY_DELAYS = (5.0, 12.0, 25.0, 40.0)

#: 真流式转发开关（默认开）。置 0 可退回「读完整条流再回放」的老行为。
CODEARTS_STREAM_PASSTHROUGH = (os.environ.get(
    "CODEARTS_STREAM_PASSTHROUGH") or "1").strip().lower() not in ("0", "false", "no")

#: 撞上「并发会话已满」后把这个号晾多久（秒）。晾着期间不再往它身上派活，
#: 有别的号就换号，没别的号就等它解冻 —— 比盲重试快得多。
CODEARTS_BUSY_COOLDOWN = ca_env.number("CODEARTS_BUSY_COOLDOWN", 5.0,
                                       minimum=0.0, zero_ok=True)

#: TPM 限流（ModelArts.811xx）的冷却。额度按分钟恢复，晾 20 秒是折中：
#: 既不会把号彻底歇掉，也能让同一波请求换到别的号去。
CODEARTS_TPM_COOLDOWN = ca_env.number("CODEARTS_TPM_COOLDOWN", 20.0,
                                      minimum=0.0, zero_ok=True)

#: 授权类错误（STS 失效、401/403）的冷却。这种错重试没用，得人工重新授权，
#: 先把它从池子里摘掉，别让后面的请求一遍遍撞。
CODEARTS_AUTH_COOLDOWN = ca_env.number("CODEARTS_AUTH_COOLDOWN", 300.0,
                                       minimum=0.0, zero_ok=True)

#: 上游把 chunked 流掐断后，在**一个字都还没给客户端**的前提下换号重开几次。
#: 只在没出内容时重开：那时客户端只收到一个空的 role 帧，整段重来完全无感；
#: 吐过内容之后再重开会把两段回答拼在一起，比断流更难排查。
CODEARTS_STREAM_RESTARTS = ca_env.number("CODEARTS_STREAM_RESTARTS", 1,
                                         minimum=0, integer=True, zero_ok=True)

#: 上面的重开还有个时间预算：断流发生在几十秒之后时，再开一条会话又是几十秒，
#: 客户端早自己重试了 —— 那才是把 3 个名额吃干净的原因。
CODEARTS_STREAM_RESTART_BUDGET = ca_env.number("CODEARTS_STREAM_RESTART_BUDGET", 90.0,
                                               minimum=1.0)

#: 建连重试的总预算（秒，只作用于流式请求）。
#:
#: 官方哲学（2026-10-24 对照官方内核日志重新校准）：上游抖动期间官方客户端
#: **从不把失败硬塞给用户** —— 429/5xx 按 2s 起步退避重试最多 10 次，排队
#: 最长 12h。网关下游是 ZCode（客户端超时 4 分钟），拿不到官方的无限耐心，
#: 但也不该 75s 就放弃：75s 只够试**一次** 0203（每次 ~60s），上游一抖用户
#: 就看到 504。210s ≈ 3 次完整尝试（60+2+60+5+60+8=195s），贴着客户端超时
#: 收口 —— 与官方一样「在耐心范围内持续重试」，而不是快速报错。
CODEARTS_OPEN_BUDGET = ca_env.number("CODEARTS_OPEN_BUDGET", 210.0, minimum=1.0)

#: 「再来一轮」的**成本估算**里，快速失败的那种算多久（秒）。
#:
#: 1041（并发会话满）与 429（TPM/请求数限流）都是上游立刻回的，实测毫秒级；
#: 按满窗口 60s 估的话，只要已经花了 15 秒之后就连它们都不敢再试了 ——
#: TPM 退避设计上是 5/12/25/40 四次，实际只能用前两次。这里给个保守的小数
#: （不写 0，是因为还要算一次池内排队 + 一次签名请求）。
CODEARTS_FAST_RETRY_COST = ca_env.number("CODEARTS_FAST_RETRY_COST", 2.0,
                                         minimum=0.0, zero_ok=True)

#: 非流式请求的重试总预算（秒）。
#:
#: 非流式没有「首帧」承诺，重试是纯收益 —— 但**不能没有上限**：一次 0203
#: 就是 60s，5/12/25/40 的退避加上 4 轮首字节窗口，最坏能到 4 分钟以上，
#: 已经超过 ZCode 自己的 4 分钟超时（10-22 实测单个请求 346s / 405s）。
#: 240 秒：比客户端超时留一点余量，又足够吃掉一次 60s 抖动 + 一次重试。
CODEARTS_TOTAL_BUDGET = ca_env.number("CODEARTS_TOTAL_BUDGET", 240.0, minimum=1.0)

#: 会话 busy 续期间隔（秒）。上游会话的空闲回收是分钟级，30s 一次足够；
#: 比请求本身更频繁没有意义，而且每次续期都是一次签名请求。
CODEARTS_SESSION_PING = ca_env.number("CODEARTS_SESSION_PING", 30.0,
                                      minimum=1.0)

#: 会话粘性的记忆时长（秒）。同一条对话的多轮落在同一个账号上，上游的
#: prompt cache 才可能命中（换号 = 换一台机器，前缀缓存全丢）。
#: 30 分钟：比一轮对话的实际间隔长，又不至于让绑定表一直涨。
CODEARTS_AFFINITY_TTL = ca_env.number("CODEARTS_AFFINITY_TTL", 1800.0,
                                      minimum=0.0, zero_ok=True)

#: 粘性表上限。超了按最久未用淘汰 —— 它只是「选号偏好」，丢了最多退化成轮询。
CODEARTS_AFFINITY_MAX = ca_env.number("CODEARTS_AFFINITY_MAX", 4096,
                                      minimum=1, integer=True)

#: 粘性落盘的文件名（放在账号目录下，和 settings.json 作伴）。
#: 为什么不每次请求都写：这张表只是「偏好」，丢最后几秒的绑定最多让一次请求
#: 换个号；每请求一次 fsync 是拿延迟换一个几乎无感的收益。
CODEARTS_AFFINITY_FILE = "codearts_affinity.json"
CODEARTS_AFFINITY_SAVE_EVERY = ca_env.number("CODEARTS_AFFINITY_SAVE_EVERY", 10.0,
                                             minimum=0.0, zero_ok=True)

#: 面板可调的码道参数（并发 / 续期 / 冷却），见 ca_settings.codearts_config。
#: 读一次缓存 5 秒：acquire、续期、惩罚都在热路径上，每请求读一遍 settings
#: 没必要；5 秒足够让「保存后下一个请求」生效。
_CODEARTS_TUNING = {"at": 0.0, "cfg": None}
CODEARTS_TUNING_TTL = 5.0


def codearts_tuning():
    now = time.time()
    cached = _CODEARTS_TUNING
    if cached["cfg"] is not None and now - cached["at"] < CODEARTS_TUNING_TTL:
        return cached["cfg"]
    try:
        cfg = ca_settings.codearts_config(ACCOUNTS_DIR)
    except Exception:
        cfg = dict(ca_settings.CODEARTS_DEFAULTS)
    cached["at"] = now
    cached["cfg"] = cfg
    return cfg


def _codearts_seconds(name, fallback):
    """取一个秒数型调参；坏值退回内置默认。"""
    try:
        value = int(codearts_tuning().get(name) or fallback)
    except Exception:
        return float(fallback)
    return float(max(1, value))


#: 上游每个账号的并发会话名额。实测 3 个，撞满回 TM.00001041。
#: 本地容量永远不超过它 —— 配到 4 只等于每次都有一路在撞限流。
CODEARTS_UPSTREAM_SLOTS = ca_env.number("CODEARTS_UPSTREAM_SLOTS", 3,
                                        minimum=1, integer=True)

# ---------------------------------------------------------------------------
# 模型级健康熔断 + 降级链（学习官方 smart-router / model-selector）。
#
# 官方两件套：①每次推理完成按 (provider, model) 记成败进断路器，连败即
# 翻转、冷却后半开放行；②选模按 agent 配置的 flagship/fallback 标签。
# 网关的对应物：record_usage/record_error 落账时顺手记成败；连败 ≥ 阈值且
# 在冷却窗内 → 该模型「熔断」，此时按面板的降级链换成第一个健康的模型。
# **链耗尽或未启用时照发原模型** —— 绝不硬拒（2026-10-24 的教训：把上游
# 抖动变成用户可见的错误是反官方哲学的）。
# ---------------------------------------------------------------------------
CODEARTS_MODEL_BREAKER_THRESHOLD = ca_env.number(
    "CODEARTS_MODEL_BREAKER_THRESHOLD", 3, minimum=1, integer=True)
CODEARTS_MODEL_BREAKER_COOLDOWN = ca_env.number(
    "CODEARTS_MODEL_BREAKER_COOLDOWN", 60.0, minimum=1.0)

_MODEL_HEALTH = {}          # resolved model -> {"fails": n, "last_fail": ts}
_MODEL_HEALTH_LOCK = threading.Lock()


def note_model_result(model, ok):
    """记一次模型成败（挂在 record_usage / record_error 上，全链路只有这两处）。"""
    key = ca_codearts.resolve_model(str(model or ""))
    if not key:
        return
    with _MODEL_HEALTH_LOCK:
        st = _MODEL_HEALTH.setdefault(key, {"fails": 0, "last_fail": 0.0})
        if ok:
            st["fails"] = 0
        else:
            st["fails"] += 1
            st["last_fail"] = time.time()


def _model_blocked(model):
    """该模型是否处于熔断窗内（连败到阈值且最后一次失败还在冷却期内）。

    冷却期一过自然放行（半开）：下一个请求照发，成败由 note_model_result
    决定是复位还是再记一笔 —— 不需要显式的状态迁移。
    """
    with _MODEL_HEALTH_LOCK:
        st = _MODEL_HEALTH.get(model)
    if not st:
        return False
    return (st["fails"] >= CODEARTS_MODEL_BREAKER_THRESHOLD
            and time.time() - st["last_fail"] < CODEARTS_MODEL_BREAKER_COOLDOWN)


def model_health(model):
    """健康度标签：ok / degraded（有败绩但未到阈值）/ down（熔断中）。"""
    key = ca_codearts.resolve_model(str(model or ""))
    with _MODEL_HEALTH_LOCK:
        st = _MODEL_HEALTH.get(key)
    if not st or st["fails"] <= 0:
        return "ok"
    if _model_blocked(key):
        return "down"
    return "degraded"


def _health_counts_failure(status, message, outcome):
    """这次失败算不算模型的健康失败。

    限流（429/TPM）、参数错、凭据错都与模型好坏无关 —— 记进去只会把
    「配额被打满」误报成「模型坏了」。只有 5xx / 上游中断 / 0203 算。
    """
    if outcome == "upstream_aborted":
        return True
    if isinstance(status, int) and status >= 500:
        return True
    text = str(message or "")
    return "APIG.0203" in text or "IncompleteRead" in text


def _apply_model_fallback(payload):
    """入口处按健康度换模型（就地改 payload["model"]，返回换后的模型名）。

    链来自面板设置 ``codearts.model_fallbacks``（默认 glm-5.3 →
    openpangu-2.0-flash → deepseek-v4.1-flash）；``model_fallback_enabled``
    关掉或链里没有健康候选时**照发原模型**。
    """
    requested = str((payload or {}).get("model") or "")
    resolved = ca_codearts.resolve_model(requested)
    if not resolved or not _model_blocked(resolved):
        return resolved
    try:
        tuning = codearts_tuning()
    except Exception:
        tuning = {}
    if not tuning.get("model_fallback_enabled", True):
        return resolved
    chain_raw = str(tuning.get("model_fallbacks") or "")
    for cand in chain_raw.split(","):
        cand = cand.strip()
        if not cand:
            continue
        cand_resolved = ca_codearts.resolve_model(cand)
        if not cand_resolved or cand_resolved == resolved:
            continue
        if not _model_blocked(cand_resolved):
            log("model fallback: %s is down (%d consecutive failures within "
                "%.0fs) -> serving with %s"
                % (resolved, CODEARTS_MODEL_BREAKER_THRESHOLD,
                   CODEARTS_MODEL_BREAKER_COOLDOWN, cand_resolved))
            payload["model"] = cand_resolved
            return cand_resolved
    log("model fallback: %s is down but no healthy candidate in the chain; "
        "serving with it anyway" % resolved)
    return resolved


def _codearts_stream_idle():
    """流式读的心跳间隔（秒）。

    优先级：面板的 ``stream_idle`` > 环境变量 ``CODEARTS_STREAM_IDLE`` >
    模块默认（15 s）。以前流式路径直接读 ``ca_codearts.STREAM_IDLE_TIMEOUT``，
    面板改了完全没反应 —— 实际静默上限永远是 15 × 40 = 600 秒。
    """
    try:
        value = codearts_tuning().get("stream_idle")
    except Exception:
        value = None
    try:
        if value:
            return max(1.0, float(value))
    except (TypeError, ValueError):
        pass
    return ca_codearts.STREAM_IDLE_TIMEOUT


def _codearts_stream_max_idle():
    """连续静默多少次算上游卡死；None 用模块默认。

    面板的 ``stream_max_idle`` 可以设 0（关掉看门狗），但 ``iter_sse`` 里还有
    一道物理硬上限，不会真的无限挂着（见 ca_codearts.IDLE_HARD_CEILING）。
    """
    try:
        value = codearts_tuning().get("stream_max_idle")
    except Exception:
        return None
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


def codearts_concurrency():
    """每账号并发容量：面板值优先，其次环境变量，最后内置默认（2）。

    ``ca_settings.codearts_config`` 已经做了「面板 > 环境变量 > 默认」的合并，
    这里只兜底 + 夹区间。上限是**上游名额数**（3），不是面板的 1~8：
    设到 4 以上必然撞 TM.00001041，那不叫并发，叫自我限流。
    """
    try:
        want = int(codearts_tuning().get("concurrency") or CODEARTS_CONCURRENCY)
    except Exception:
        want = CODEARTS_CONCURRENCY
    return max(1, min(CODEARTS_UPSTREAM_SLOTS, want))


class _ResizableSemaphore:
    """容量可调的信号量（面板改并发，下一条请求就生效，不用重启）。

    标准库 ``threading.Semaphore`` 的容量定了就改不了；换成新对象又有个坑：
    某个线程刚 ``acquire`` 完还没记账，换对象后它的 ``release`` 会打到新对象
    上，容量凭空多出来一格。这里自己拿 Condition 记「容量 / 空闲」两个数，
    acquire 与 release 永远打在同一个对象上，没有换对象的窗口。

    在跑数（``_used``）**单独记**，不用 ``capacity - free`` 反推。反推在
    缩容时是错的：容量 2、跑了 2 个 → 缩到 1 时 ``free`` 被压成 0，但真实
    在跑的仍是 2；此后任意一个结束都会让 ``release`` 看到 ``free < capacity``
    而把名额加回去（1），再扩容到 2 时 ``free`` 又按「在跑 0」算成 2 ——
    于是实际能跑到 3 个，正好打满上游的 3 个会话名额（2026-10-23 复现）。
    """

    def __init__(self, capacity):
        self._cond = threading.Condition()
        self._capacity = max(1, int(capacity))
        self._free = self._capacity
        #: 真实在跑的条数。只由 acquire/release 加减，retune 不碰它。
        self._used = 0

    def acquire(self, blocking=True, timeout=None):
        with self._cond:
            if not blocking:
                if self._used >= self._capacity:
                    return False
                self._used += 1
                self._free = max(0, self._capacity - self._used)
                return True
            if timeout is None:
                while self._used >= self._capacity:
                    self._cond.wait()
            else:
                deadline = time.monotonic() + timeout
                while self._used >= self._capacity:
                    remain = deadline - time.monotonic()
                    if remain <= 0:
                        return False
                    self._cond.wait(remain)
            self._used += 1
            self._free = max(0, self._capacity - self._used)
            return True

    def release(self):
        with self._cond:
            # 多还了就夹在 0 上：宁可少放一个，也别让 bug 悄悄放大并发
            if self._used > 0:
                self._used -= 1
            self._free = max(0, self._capacity - self._used)
            self._cond.notify()

    def retune(self, capacity):
        """在跑的请求不受影响，只改「还能再进几个」。

        缩容**不会**打断已经在跑的（它们本来就没法撤回），只是让它们结束
        之前不再放新人进来；扩容也不会因为「之前缩过」凭空多出一格 ——
        ``_used`` 是独立计数，不随容量变化。
        """
        with self._cond:
            capacity = max(1, min(CODEARTS_UPSTREAM_SLOTS, int(capacity)))
            self._capacity = capacity
            self._free = max(0, capacity - self._used)
            self._cond.notify_all()

    @property
    def capacity(self):
        with self._cond:
            return self._capacity


#: 用首条用户消息当会话指纹时要求的最短长度。太短（"hi"、"继续"）会撞车，
#: 撞了只是"两个无关对话被排到同一个号"，无害但没必要。
CODEARTS_AFFINITY_MIN_CHARS = 24


def codearts_session_key(headers, payload):
    """同一条对话的稳定标识，用来把多轮固定到同一个账号。

    三层，从最可信到最兜底：

      1. **显式会话键** —— 客户端真的发了 ``conversation_id`` /
         ``X-Conversation-Id`` / ``prompt_cache_key`` 就用它，零歧义；
      2. **会话头**（``X-Session-Id`` 之类）；
      3. **首条用户消息的指纹** —— Codex CLI / Claude Code 每一轮都会把完整
         历史重发一遍，而**第一条 user 消息在整个对话里不变**，正好当指纹。
         coding2api 的 affinity 也是这个思路（它还把 username 掺进键里防串）。

    都没有就返回 None：不猜。宁可退化成轮询，也不要靠一个不稳的东西
    把两条无关对话绑到同一个号上。
    """
    try:
        explicit = extract_session_key(headers or {}, payload)
    except Exception:
        explicit = None
    if explicit:
        return "k:" + explicit
    try:
        user = str(payload.get("user") or "").strip()
        if user:
            return "u:" + user
        messages = payload.get("messages") or []
        for message in messages:
            if not isinstance(message, dict):
                continue
            if message.get("role") != "user":
                continue
            content = message.get("content")
            if isinstance(content, list):
                content = "".join(
                    str(part.get("text") or "") for part in content
                    if isinstance(part, dict))
            text = str(content or "").strip()
            if len(text) < CODEARTS_AFFINITY_MIN_CHARS:
                return None
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            return "p:" + digest
    except Exception:
        return None
    return None


class _CodeartsAccountPool:
    """按**账号**分配并发名额，并在账号之间做负载与故障转移。

    上游的并发上限是账号级的 3 个会话。旧实现用一个全局信号量（默认 2）：
      · 总容量不随账号数增长 —— 3 个号仍然只能同时跑 2 条；
      · 轮转挑号完全不看谁在忙 —— 第 3 条可能压到已经满的号上，另一个号
        闲着，白撞 TM.00001041 再退避重试。
    所以这里每个账号一个信号量（容量 CODEARTS_CONCURRENCY，默认 2，给 IDE
    等其它使用者留 1 个），挑号时先看空闲、再看冷却。
    """

    def __init__(self, state_dir=None):
        self._lock = threading.Lock()
        self._state_dir = state_dir or ACCOUNTS_DIR
        self._semaphores = {}     # 账号 id -> Semaphore（每号独立容量）
        self._cool_until = {}     # 账号 id -> 冷却到期时间戳
        # (账号 id, 模型) -> 冷却到期时间戳。TPM 限流是**按模型**的：glm-5.3
        # 撞满不该把同一个号上的 deepseek 一起晾 20 秒（2026-10-22 补）。
        self._model_cool = {}
        self._inflight = {}       # 账号 id -> 正在跑的请求数（面板用）
        self._affinity = {}       # 会话键 -> (账号 id, 最后使用时间)，见 acquire
        self._affinity_loaded = False   # 落盘的粘性只读一次
        self._affinity_dirty = False    # 有改动还没写盘
        self._affinity_saved = 0.0      # 上次写盘的时间（节流用）
        self._cursor = 0

    @staticmethod
    def key_of(sess):
        account = sess.get("account") or {}
        return str(account.get("id") or account.get("label") or "default")

    def _sem(self, key):
        """取这个账号的信号量；面板改过并发就顺手调容量（空闲时也不丢号）。"""
        want = codearts_concurrency()
        with self._lock:
            sem = self._semaphores.get(key)
            if sem is None:
                sem = _ResizableSemaphore(want)
                self._semaphores[key] = sem
            else:
                sem.retune(want)
            return sem

    @staticmethod
    def _usable():
        usable = []
        for sess in ca_codearts.load_sessions(ACCOUNTS_DIR):
            _left, expired, renewable = _codearts_left(sess)
            if not expired or renewable:
                usable.append(sess)
        return usable

    @staticmethod
    def _usage_key(sess):
        """The key daily_usage_stats() files this account's rows under.

        record_usage() is called with the CodeArts account *label* (see
        _codearts_chat_result), not the id key_of() prefers; using the id here
        would read zero usage forever and silently disable every guard.
        """
        account = sess.get("account") or {}
        return str(account.get("label") or "")

    @staticmethod
    def _limits_for_request():
        """(limits, stats) for one acquire call, or (limits, None) fail-open.

        One settings read and at most one usage fold per request: the fold is
        incremental and TTL-cached, so this is a stat plus a cached dict unless
        the log actually grew. A read failure means "unknown", never "blocked".
        """
        limits = ca_settings.limit_values_many(
            ACCOUNTS_DIR,
            ("daily_token_limit", "daily_credit_limit",
             "model_daily_token_limit"))
        if not any((entry.get("global") or 0) > 0
                   for entry in limits.values()):
            return limits, None
        try:
            stats = daily_usage_stats()
        except Exception as exc:
            log("codearts daily usage unavailable: %s" % exc)
            stats = None
        return limits, stats

    @classmethod
    def _limit_blocked(cls, sess, model, limits, stats):
        """True when a daily guard parks this account (or just this model)."""
        if not stats:
            return False
        uid = cls._usage_key(sess)
        if not uid:
            return False
        token_limit = (limits.get("daily_token_limit") or {}).get("global") or 0
        if token_limit > 0 and stats["tokens"].get(uid, 0) >= token_limit:
            return True
        credit_limit = (limits.get("daily_credit_limit") or {}).get("global") or 0
        if credit_limit > 0 and stats["credits"].get(uid, 0) >= credit_limit:
            return True
        model_limit = (limits.get("model_daily_token_limit")
                       or {}).get("global") or 0
        if model_limit > 0 and model:
            used = (stats["models"].get(uid) or {}).get(model, 0)
            if used >= model_limit:
                return True
        return False

    def limits_blocked(self, model=None):
        """Whether sessions exist but every one is parked by a daily guard.

        Used to answer 429 (quota) instead of 503 (no account) when the pool
        looks empty only because of the panel's limits.
        """
        try:
            limits, stats = self._limits_for_request()
        except Exception:
            return False
        if not stats:
            return False
        sessions = self._usable()
        return bool(sessions) and all(
            self._limit_blocked(sess, model, limits, stats)
            for sess in sessions)

    def acquire(self, timeout=None, session_key=None, model=None):
        """要一个名额。返回 ``(session, key)``；拿不到时 ``(None, None)``。

        先试「不等待」的：谁有空位给谁。全都忙才在**第一个候选**上等一小会
        儿（最多 0.25s）然后重新评估 —— 这样别的号空出来的瞬间就能换过去，
        而不是死等某一个号。

        ``session_key`` 给了就带上**粘性**：这条对话上次落在哪个号，这次优先
        还给它（上游的 prompt cache 是按机器存的，换号等于前缀缓存全丢）。
        但粘性只是排序偏好 —— 那个号满了/在冷却时**立刻换号**，绝不为了一条
        偏好让用户多等。

        ``model`` 用来判按模型的日限额；日 token / 日积分是账号级的。限额
        每次请求只读一遍，读不出来按「未知」处理（fail-open），不误封。
        """
        timeout = CODEARTS_SLOT_WAIT if timeout is None else timeout
        deadline = time.time() + max(0.0, timeout)
        try:
            limits, stats = self._limits_for_request()
        except Exception as exc:
            log("codearts daily limits unavailable: %s" % exc)
            limits, stats = {}, None
        while True:
            sessions = [s for s in self._usable()
                        if not self._limit_blocked(s, model, limits, stats)]
            if not sessions:
                return None, None
            now = time.time()
            ready = [s for s in sessions
                     if self._cool_until.get(self.key_of(s), 0.0) <= now]
            if ready and model:
                # 模型级冷却：只在「还有别的号能跑这个模型」时才筛掉，
                # 全在冷却时保持原样（宁可撞一次限流，也别让请求排死）。
                model_key = str(model)
                fresh = [s for s in ready
                         if self._model_cool.get(
                             (self.key_of(s), model_key), 0.0) <= now]
                if fresh:
                    ready = fresh
            if ready:
                candidates = ready
            else:
                # 全在冷却。这里**不能**直接把最早解冻的那个拿来用：冷却的
                # 意思就是「现在用它只会再撞一次同样的错」—— 单账号部署里
                # 那就等于冷却完全没作用（以前就是这么写的，注释里说「别去
                # 撞刚被限流的号」，代码却直接撞）。
                # 正确做法是等到最早的那条解冻（但不超过本次 acquire 的
                # 截止时间），等不及就如实报「暂时没有可用号」。
                soonest = min(
                    self._cool_until.get(self.key_of(s), 0.0) for s in sessions)
                remaining = deadline - time.time()
                wait = soonest - now
                if wait > remaining:
                    # 这次等不到：交给调用方回 429 / 503（带 Retry-After）。
                    log("codearts all accounts cooling: model=%s need %.1fs, "
                        "budget %.1fs" % (model, wait, max(0.0, remaining)))
                    return None, None
                time.sleep(max(0.0, min(wait, remaining)))
                continue
            start = self._cursor % len(candidates)
            ordered = candidates[start:] + candidates[:start]
            self._cursor += 1
            # 粘住的号提到最前。它是**偏好**不是约束：下面仍然非阻塞地要槽位，
            # 拿不到就继续试后面的号。
            sticky = self._sticky(session_key, now)
            if sticky:
                ordered.sort(key=lambda s: 0 if self.key_of(s) == sticky else 1)
            for sess in ordered:
                key = self.key_of(sess)
                if self._sem(key).acquire(blocking=False):
                    return self._admit(sess, key), key
            remaining = deadline - time.time()
            if remaining <= 0:
                return None, None
            key = self.key_of(ordered[0])
            if self._sem(key).acquire(timeout=min(0.25, remaining)):
                return self._admit(ordered[0], key), key
            time.sleep(min(0.05, max(0.0, deadline - time.time())))

    def _state_path(self):
        return os.path.join(self._state_dir, CODEARTS_AFFINITY_FILE)

    def _load_affinity_locked(self, now):
        """第一次用到粘性时读一次盘。坏文件当没有 —— 绝不因此让请求失败。"""
        if self._affinity_loaded:
            return
        self._affinity_loaded = True
        try:
            with open(self._state_path(), encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        for key, item in raw.items():
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            acct, stamp = item
            try:
                stamp = float(stamp)
            except (TypeError, ValueError):
                continue
            if now - stamp <= CODEARTS_AFFINITY_TTL:
                self._affinity[str(key)] = (str(acct), stamp)

    def _save_affinity_locked(self, now, force=False):
        """把粘性表写盘（按 ``CODEARTS_AFFINITY_SAVE_EVERY`` 节流）。"""
        if not self._affinity_dirty:
            return
        if not force and now - self._affinity_saved < CODEARTS_AFFINITY_SAVE_EVERY:
            return
        self._affinity_dirty = False
        self._affinity_saved = now
        data = {key: [acct, stamp]
                for key, (acct, stamp) in self._affinity.items()}
        path = self._state_path()
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
            os.replace(tmp, path)          # 原子替换：半个文件永远读不到
        except OSError as exc:
            log("codearts affinity save failed: %s" % exc)

    def _sticky(self, session_key, now=None):
        """这条对话绑在哪个号上；没绑、已过期都返回 None。"""
        if not session_key:
            return None
        now = time.time() if now is None else now
        with self._lock:
            self._load_affinity_locked(now)
            item = self._affinity.get(session_key)
            if not item:
                return None
            key, stamp = item
            if now - stamp > CODEARTS_AFFINITY_TTL:
                self._affinity.pop(session_key, None)
                return None
            return key

    def remember(self, session_key, key, now=None):
        """把这条对话绑定到刚服务它的号上（只记偏好，不影响可用性判定）。"""
        if not session_key or not key:
            return
        now = time.time() if now is None else now
        with self._lock:
            self._load_affinity_locked(now)
            self._affinity[session_key] = (key, now)
            self._affinity_dirty = True
            if len(self._affinity) > CODEARTS_AFFINITY_MAX:
                # 超限按最久没碰过的淘汰。它是纯偏好，丢了只会退化成轮询。
                dead = sorted(self._affinity.items(),
                              key=lambda kv: kv[1][1])[:len(self._affinity) // 8 + 1]
                for name, _item in dead:
                    self._affinity.pop(name, None)
            self._save_affinity_locked(now)

    def _admit(self, sess, key):
        """已经拿到槽位：记在跑数、顺手把 STS 续上。"""
        with self._lock:
            self._inflight[key] = self._inflight.get(key, 0) + 1
        try:
            return _ensure_fresh(sess)
        except BaseException:
            self.release(key)
            raise

    def release(self, key):
        with self._lock:
            if self._inflight.get(key):
                self._inflight[key] -= 1
        try:
            self._sem(key).release()
        except ValueError:          # 多还了：忽略，别把请求炸掉
            pass

    def penalize(self, key, seconds, model=None):
        """把这个号晾一会儿（冷却期内挑号会跳过它）。

        ``model`` 给了就只冷却「这个号跑这个模型」——TPM 限流是按模型的，
        账号级冷却会连带把同一账号上的其它模型一起停掉。并发会话满（1041）
        与凭据失效才是账号级的，调用方不传 model。
        """
        with self._lock:
            until = time.time() + max(0.0, seconds)
            if model:
                mk = (key, str(model))
                if until > self._model_cool.get(mk, 0.0):
                    self._model_cool[mk] = until
                return
            if until > self._cool_until.get(key, 0.0):
                self._cool_until[key] = until

    def cooling_for(self, key, model=None):
        """这个号（可选：这个模型）还要晾多少秒；0 表示现在就能用。

        只读观察口：重试路径实际走 ``soonest_ready()``（按整套退避预算判断
        等不等）；测试与诊断用它直接读冷却状态。
        """
        now = time.time()
        with self._lock:
            left = self._cool_until.get(key, 0.0) - now
            if model:
                left = max(left, self._model_cool.get((key, str(model)), 0.0) - now)
            return max(0.0, left)

    def soonest_ready(self, model=None):
        """所有账号里最早解冻还要多少秒（没有账号时 0）。

        模型级冷却与账号级冷却都算：只要有一项还在冷却，这个号就用不了。
        以前只看 ``(key, model)`` 那一张表，于是「账号级冷却（1041 / 401）」
        完全看不到 —— 调用方据此判成「没在冷却」，然后回一条说「容量满」的
        429，把真实原因（还在晾着）藏掉了。
        """
        now = time.time()
        sessions = self._usable()
        if not sessions:
            return 0.0
        with self._lock:
            waits = []
            for sess in sessions:
                key = self.key_of(sess)
                # 每个号都算「账号级与模型级里更晚解冻的那一项」：只要有一项
                # 还在冷却，这个号就用不了。必须逐号取 max、再在号之间取
                # min —— 以前直接对所有时间戳取 min，过期项的负值会把「还有
                # 5 秒才解冻」压成负数，于是被当成「没在冷却」。
                per_account = [self._cool_until.get(key, 0.0)]
                if model:
                    per_account.append(
                        self._model_cool.get((key, str(model)), 0.0))
                waits.append(max(per_account) - now)
            return max(0.0, min(waits) if waits else 0.0)

    def clear_cooldown(self, key=None, model=None):
        """把冷却表清掉（``key`` 为空时清全部）。

        凭据失效（401/403）的 300 秒冷却必须能被「重新登录」清掉：用户在面板
        里重新授权之后，那个号明明已经能用了，冷却表却还在拦它 —— 表现就是
        「刚登录还是 429」。码道每次登录都会写一份新的会话文件，所以登录成功
        时按账号 id 清一次就够。
        """
        with self._lock:
            if key is None:
                self._cool_until.clear()
                self._model_cool.clear()
                return
            if model is None:
                self._cool_until.pop(key, None)
                for mk in [k for k in self._model_cool if k[0] == key]:
                    self._model_cool.pop(mk, None)
                return
            self._model_cool.pop((key, str(model)), None)

    def snapshot(self):
        """每号「在跑几条 / 容量几格 / 还剩几秒冷却」，给面板与排障用。"""
        now = time.time()
        # 容量要在锁外读（可能触发一次 settings 读盘）；取号时 _sem 也会按
        # 同一个值 retune，所以这里读到的是「下一条请求能用几格」。
        want = codearts_concurrency()
        with self._lock:
            # 过期项顺手清掉，别让长期运行的表无限长（每个模型一条）。
            for mk in [k for k, until in self._model_cool.items() if until <= now]:
                self._model_cool.pop(mk, None)
            keys = set(self._semaphores) | set(self._inflight) | set(self._cool_until)
            out = {}
            for key in sorted(keys):
                cooling = {str(model): round(until - now, 1)
                           for (acct, model), until in self._model_cool.items()
                           if acct == key and until > now}
                sem = self._semaphores.get(key)
                out[key] = {
                    "in_flight": self._inflight.get(key, 0),
                    "capacity": sem.capacity if sem is not None else want,
                    "cooling_s": round(max(0.0,
                                           self._cool_until.get(key, 0.0) - now), 1),
                    "model_cooling_s": cooling,
                }
            return out


_CODEARTS_POOL = _CodeartsAccountPool()


def _codearts_welcome_claim_sync(account_id):
    """补签的主体（同步）：找到该账号的会话，把当天积分签上。"""
    if not account_id:
        return
    try:
        for session in ca_codearts.load_sessions(ACCOUNTS_DIR):
            acct = session.get("account") or {}
            if acct.get("id") != account_id:
                continue
            label = acct.get("label") or account_id
            try:
                res = ca_codearts.welfare_claim_daily(
                    session.get("accessKey"), session.get("secretKey"),
                    session.get("securitytoken"))
                msg = ("已签到 +%s 积分" % res.get("amount")) \
                    if not res.get("already") \
                    else ("今日已签到（%s 积分）" % (res.get("amount") or "?"))
                log("welcome    : [%s] %s" % (label, msg))
                ca_activity.record(account_id, label, "cn",
                                   ca_activity.TASK_CHECKIN,
                                   "login", True, msg, usage_dir=USAGE_DIR)
            except Exception as exc:              # noqa: BLE001 —— 补签失败不碍事
                log("welcome    : [%s] 签到失败: %s" % (label, exc),
                    level="WARN")
                ca_activity.record(account_id, label, "cn",
                                   ca_activity.TASK_CHECKIN,
                                   "login", False, str(exc)[:120],
                                   usage_dir=USAGE_DIR)
            return
    except Exception as exc:                      # noqa: BLE001
        log("welcome claim failed for %s: %s" % (account_id, exc),
            level="WARN")


def _codearts_welcome_claim(account_id):
    """新账号入池时顺手把当天的积分签上（异步，不拖慢登录响应）。

    签到调度器每天只在 00:05 跑一次，之后新加的账号要等到次日才会被自动
    签到（2026-10-25 实测：05:36 加入的号当天空窗，全靠手动补）。失败不
    影响登录结果——积分明天照样有。主体在 _welcome_claim_sync，测试同步打它。
    """
    threading.Thread(
        target=_codearts_welcome_claim_sync,
        args=(account_id,), name="codearts-welcome-claim", daemon=True).start()


def codearts_clear_cooldown_for(label_or_id):
    """按昵称或账号 id 清掉某个号的冷却（重新登录 / 手动续期后调用）。

    昵称与 id 都可能给到（登录成功时回的是 label），所以两个都试：把匹配的
    那一个键清掉，顺带清它的模型级冷却 —— 换了新凭据，之前的 429/401 结论
    都不再成立。
    """
    value = str(label_or_id or "").strip()
    if not value:
        return
    _CODEARTS_POOL.clear_cooldown(value)
    for session in ca_codearts.load_sessions(ACCOUNTS_DIR):
        account = session.get("account") or {}
        if value not in (str(account.get("label") or ""),
                         str(account.get("id") or "")):
            continue
        _CODEARTS_POOL.clear_cooldown(str(account.get("id") or ""))
        _CODEARTS_POOL.clear_cooldown(str(account.get("label") or ""))


#: 我们自己造过、还没注销的上游会话（user-session-id）落盘一份。
#:
#: 为什么非落盘不可：idle 注销写在 ``finally`` 里，它只挡得住**异常**，挡不住
#: ``systemctl restart`` / OOM / 断电 —— 进程一死，那几条 busy 就永远挂在上游，
#: 直到它自己按超时回收。账号只有 3 个名额，一次部署就能全占掉，之后一律
#: ``TM.00001041 并发会话数已达上限(3个)``，而我们的退避是等「别人释放」，
#: 等的是永远不会来的东西（2026-10-23 15:00–15:03 连着重启五次，那一小时的
#: 1041 全出自这里）。
#:
#: 文件本身很小（稳态下最多 = 账号数 × 并发数 条），和 ``codearts_affinity``
#: 一样放在 accounts/ 下（已被 ``accounts/*.json`` 忽略，不会进仓库）。
CODEARTS_SESSIONS_FILE = "codearts_sessions.json"
_SESSION_REGISTRY_LOCK = threading.Lock()
#: 没注销成功的条目最多留这么久：超过就认为上游早已按超时回收，别再拿它去
#: 打扰上游（也免得文件随失败累积无限长）。
CODEARTS_SESSION_TTL = 3600.0
#: 文件长度上限。正常远到不了；只是防「idle 一直失败 + 长期不重启」把它撑大。
CODEARTS_SESSION_MAX = 64


def _sessions_path():
    """每次现算：测试会改 ``ACCOUNTS_DIR``，模块级常量会被钉死在旧路径上。"""
    return os.path.join(ACCOUNTS_DIR, CODEARTS_SESSIONS_FILE)


#: 进程内的登记表副本。**心跳路径只碰内存**，落盘由改写立刻完成、由
#: ``_sessions_flush`` 按需执行。
#:
#: 以前每次 busy 续期都要「整文件读 → 改一条 → 整文件写」：一条跑两小时的
#: 流按 30 秒续期就是 240 次全量读写，而这张表在稳态下有 账号数 × 并发数
#: 条 —— 路由器上那是实打实的 flash 写入与延迟，全压在一次心跳上（心跳本身
#: 只有 2 秒预算）。现在内存里改一条，写盘沿用同一套原子替换。
_SESSION_REGISTRY = {"data": None}


def _sessions_sane(data):
    """只留形状对了的条目；坏条目丢掉而不是让整个表读成空。

    文件是磁盘上的东西：手工编辑、旧版本写入、写到一半断电，都可能留一条
    ``"abc": "oops"``（字符串）或 ``at: "not a number"``。以前的读取侧
    只检查「顶层是不是 dict」，于是那种条目会在 reap 里
    ``float(item.get("at"))`` 直接抛 —— 清理线程整个死掉，**剩下的会话
    一条都不补发**，名额继续挂着，正是这个登记表要防的事。
    """
    if not isinstance(data, dict):
        return {}
    out = {}
    for session_id, item in data.items():
        if not isinstance(session_id, str) or not session_id:
            continue
        if not isinstance(item, dict):
            continue
        try:
            at = float(item.get("at") or 0)
        except (TypeError, ValueError):
            at = 0.0
        acct = item.get("acct")
        uid = item.get("uid")
        out[session_id] = {"acct": acct if isinstance(acct, str) else "",
                           # uid 是重启补发 idle 时取凭据的键。洗掉它等于让
                           # 整条链路退回按 label 猜号 —— 那正是要修的问题。
                           "uid": uid if isinstance(uid, str) else "",
                           "at": at}
    return out


def _sessions_read():
    """读登记表（并填进内存副本）；坏文件/不存在都当空表。

    这是记账，不是前置条件 —— 任何读失败都不该影响请求。
    """
    try:
        with open(_sessions_path(), encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    data = _sessions_sane(raw)
    _SESSION_REGISTRY["data"] = data
    return dict(data)


def _sessions_loaded():
    """当前进程的登记表副本；还没读过就先读一次。调用方必须持锁。"""
    data = _SESSION_REGISTRY.get("data")
    if data is None:
        return _sessions_read()
    return data


def _sessions_write(data):
    """原子写（临时文件 + replace）：半截 JSON 会让启动时的清理读出空表。"""
    data = _sessions_sane(data)
    _SESSION_REGISTRY["data"] = data
    path = _sessions_path()
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError as exc:
        # 写不进去只影响「重启后的清理」，不影响这条请求本身，所以不抛。
        log("codearts session registry write failed: %r" % (exc,))


def _sessions_trim(data):
    """超长就砍掉最老的，返回 (data, 是否改过)。调用方必须持锁。"""
    if len(data) <= CODEARTS_SESSION_MAX:
        return data, False
    # 留最近的：老的更可能已经被上游回收了。
    keep = sorted(data.items(), key=lambda kv: kv[1].get("at") or 0)
    return dict(keep[-CODEARTS_SESSION_MAX:]), True


def track_codearts_session(session_id, account_label, account_key=None):
    """记下一条刚 busy 登记成功的会话。

    ``account_key`` 是账号 id（``_CodeartsAccountPool.key_of``），不是昵称：
    两个账号可以叫同一个名字，按 label 索引会在重启补发时拿到**另一个号**
    的凭据 —— 那条 idle 必然 401，还会把一对合法凭据打上「失效」的嫌疑。
    label 仍然存着，只用于日志与面板展示。
    """
    if not session_id:
        return
    with _SESSION_REGISTRY_LOCK:
        data = dict(_sessions_loaded())
        data[session_id] = {"acct": account_label or "",
                            "uid": account_key or "",
                            "at": round(time.time(), 1)}
        data, _trimmed = _sessions_trim(data)
        _sessions_write(data)


def untrack_codearts_session(session_id):
    """idle 成功注销一条，把它从登记表里去掉。"""
    if not session_id:
        return
    with _SESSION_REGISTRY_LOCK:
        data = dict(_sessions_loaded())
        if data.pop(session_id, None) is not None:
            _sessions_write(data)


#: busy 心跳的超时（秒）。它挡在**请求发出去之前**，所以必须小：2026-10-23
#: 15:14 有一个请求因为心跳超时白等了 6 秒才拿到 200。
#:
#: 为什么不干脆去掉：上游的并发闸只认 busy/idle，不让它知道「我们开始了」，
#: 3 个名额会被隐式会话占满。但「登记慢」不该拖住请求 —— 2 秒是正常 RTT
#: 的十倍，超了就是这次心跳不成了（下面还会把 id 记进登记表，重启补发）。
CODEARTS_BUSY_TIMEOUT = ca_env.number("CODEARTS_BUSY_TIMEOUT", 2.0, minimum=0.5)


def codearts_session_busy(cred, account_label, timeout=None, account_key=None):
    """``heartbeat busy`` + 记账，返回 ``(session_id, ok, detail)``。

    记账在**成功或超时**时都做：超时的那条心跳上游可能已经收到了（只是
    响应没回来），把 id 记进登记表，重启时补一次 idle 是幂等的 —— 不记的话
    这条会话就永远挂在上面占名额（15:14 那条正是这么漏的）。

    只有**明确被拒**（400 / 401 之类，上游根本不认这个 id）才不记：那种 id
    在重启后 idle 只会换来 404，白跑一趟。

    ``account_key`` 传账号 id：重启补发按它取凭据（label 可能重名）。
    """
    if timeout is None:
        timeout = CODEARTS_BUSY_TIMEOUT
    session_id = ca_codearts.new_session_id()
    ok, detail = ca_codearts.heartbeat(*(cred + (session_id, "busy")),
                                       timeout=timeout)
    if ok:
        track_codearts_session(session_id, account_label, account_key)
    elif not str(detail).startswith("HTTP 4"):
        # 超时 / 连接中断 / 未确认：上游可能已经开了这条会话。
        track_codearts_session(session_id, account_label, account_key)
    return session_id, ok, detail


def codearts_session_idle(cred, session_id, timeout=6):
    """``heartbeat idle`` + 销账。失败**保留**登记：下次启动还能补一次。"""
    ok, detail = ca_codearts.heartbeat(*(cred + (session_id, "idle")),
                                       timeout=timeout)
    if ok:
        untrack_codearts_session(session_id)
    return ok, detail


def reap_codearts_sessions():
    """启动后补发 idle：把上一次进程没来得及注销的会话还回去。

    三条设计取舍：
      · **best-effort**：凭据可能已经换过、会话可能早被回收，失败只记日志，
        绝不让启动失败；
      · **成功后销账、失败留 1 小时**：上游对不存在的会话 idle 是幂等的，
        重复补发无害；但真的失败（比如 STS 过期）留一会儿还能再试；
      · 后台线程跑，不拖启动：每条最坏 6 秒超时，攒几条就能感觉到慢。

    凭据按**账号 id** 索引，不按 label：两个账号可以叫同一个名字（同一个华为
    云 IAM 用户在不同 region、手工改过的昵称），按 label 建字典会让后一个
    覆盖前一个 —— 补发 idle 时拿着 A 的凭据去注销 B 的会话，那条必然失败，
    然后被当成「这个号有问题」。老登记条目没写 uid 时按 label 兜底（那时
    也只能这样），但只在该 label 唯一时才认。
    """
    with _SESSION_REGISTRY_LOCK:
        data = _sessions_read()
    if not data:
        return
    now = time.time()
    try:
        by_uid = {}
        by_label = {}
        dup_labels = set()
        for sess in ca_codearts.load_sessions(ACCOUNTS_DIR):
            account = sess.get("account") or {}
            uid = str(account.get("id") or "")
            label = account.get("label")
            cred = (sess.get("accessKey"), sess.get("secretKey"),
                    sess.get("securitytoken"))
            if uid:
                by_uid[uid] = cred
            if label:
                if label in by_label:
                    dup_labels.add(label)        # 重名：这个兜底键不可信
                by_label[label] = cred
    except Exception as exc:                     # noqa: BLE001
        log("codearts session reap: cannot load accounts: %r" % (exc,))
        return
    for label in dup_labels:
        by_label.pop(label, None)

    released = stale = 0
    left = {}
    for session_id, item in data.items():
        # _sessions_read 已经洗过形状，这里仍然按「可能缺字段」取值：
        # 这是一条后台线程，宁可少补一条也不许整轮崩掉。
        item = item if isinstance(item, dict) else {}
        age = now - float(item.get("at") or 0)
        cred = by_uid.get(str(item.get("uid") or "")) or \
            by_label.get(item.get("acct"))
        if not cred or not cred[0]:
            # 账号可能只是暂时读不出来（凭据在续期、面板刚删）。留到超龄为止：
            # 下次启动还能再试一次，但不会为一个已经不存在的账号永久保账。
            if age < CODEARTS_SESSION_TTL:
                left[session_id] = item
            else:
                stale += 1
            continue
        try:
            ok, _detail = ca_codearts.heartbeat(
                *(cred + (session_id, "idle")), timeout=6)
        except Exception as exc:                 # noqa: BLE001
            # 单条心跳炸了不该终止整轮：剩下的会话还在占名额，那才是要修的。
            log("codearts session reap: idle %s failed: %r" % (session_id, exc))
            ok = False
        if ok:
            released += 1
        elif age < CODEARTS_SESSION_TTL:
            left[session_id] = item
        else:
            stale += 1
    # 收尾要**合并**而不是覆盖：清理期间可能已经有新请求登记了新会话，直接
    # 写 left 会把它们抹掉 —— 那正好是下一次重启要泄漏的那批。
    with _SESSION_REGISTRY_LOCK:
        current = _sessions_loaded()
        current = dict(current)
        for session_id in data:
            if session_id in left:
                current[session_id] = left[session_id]
            else:
                current.pop(session_id, None)     # 已注销 / 超龄丢弃
        _sessions_write(current)
    log("codearts session reap: %d released, %d left (accounts=%d)"
        % (released, len(left) + stale, len(by_uid) or len(by_label)))


class _CodeartsLease:
    """一次码道上游连接的持有凭证。

    为什么不直接返回 resp：**并发名额和连接是同一条命** —— 忘了关连接，
    上游会话就挂到它自己超时；忘了还名额，后面所有请求都排队。把两件事绑在
    一个对象上，调用方只需要在 finally 里 close() 一次。

    从 2026-10-22 起还多带一条**上游会话**：上游的并发闸不认「请求结束」，
    只认 ``chat-session/heartbeat`` 的 busy/idle（见 ca_codearts.heartbeat）。
    所以 close() 除了关连接、还本地名额，还要 idle 注销 —— 三件事缺一，名额
    都会在不同的地方泄漏。
    """

    def __init__(self, resp, account_label, started_at, account_key,
                 session_id=None, session_cred=None, max_idle=None,
                 idle_timeout=None):
        self.resp = resp
        self.account_label = account_label
        self.started_at = started_at
        self.account_key = account_key
        self.session_id = session_id
        self._session_cred = session_cred
        #: 流式读的心跳间隔（秒）。None 用模块默认。**面板设的就是这个**：
        #: 以前这里写死读 ca_codearts.STREAM_IDLE_TIMEOUT，面板改了不生效。
        self.idle_timeout = idle_timeout
        #: 连续静默多少次算上游卡死。None 用模块默认。
        #: 0 表示「关掉看门狗」，但 iter_sse 仍有一道物理硬上限
        #: （IDLE_HARD_CEILING），不会真的无限挂。
        self.max_idle = max_idle
        self._last_ping = time.time()
        self._closed = False
        # release_slot() 的幂等标记：close() 与显式调用的路径都可能走到它。
        self._slot_lock = threading.Lock()
        self._slot_released = False
        # 续期走独立线程，不挂在读循环上（理由见 _ping_loop）。
        self._ping_lock = threading.Lock()
        self._ping_stop = threading.Event()
        self._ping_thread = None
        if self.session_id and self._session_cred:
            self._ping_thread = threading.Thread(
                target=self._ping_loop, name="codearts-session-ping",
                daemon=True)
            self._ping_thread.start()

    def _ping_loop(self):
        """独立定时续期 busy，与「有没有收到字节」无关。

        以前续期挂在读循环上：每收一行试一次、按 session_ping 节流。两个毛病：

        1. 模型思考期间上游可能长时间不吐字节（只靠 KEEPALIVE 哨兵兜着），
           哨兵拿不到 socket 时续期就彻底停了 —— 上游到点回收会话，表现就是
           ``IncompleteRead(0 bytes read)``（2026-10-23 上午 11 次断流）。
        2. 带签名的 HTTP PUT 塞在收帧路径上，一次慢心跳就让读停住，反过来把
           上游的写缓冲顶满。

        官方客户端的做法就是 busy 之后起 interval(30000) 独立续期，见
        docs/codearts-projects-study.md 第二节。
        """
        while not self._ping_stop.wait(5.0):
            try:
                self.keepalive()
            except Exception as exc:          # noqa: BLE001
                # 静默吞掉会让「续期线程挂了」表现成「上游无缘无故断流」，
                # 每次失败都留一行（正常路径一行都没有）。
                log("codearts session ping loop error: %r" % (exc,))

    def keepalive(self):
        """流式期间按需续期 busy（默认 30s 一次）。返回是否真的发了一次。"""
        if not self.session_id or not self._session_cred or self._closed:
            return False
        now = time.time()
        interval = _codearts_seconds("session_ping", CODEARTS_SESSION_PING)
        if (now - self._last_ping) < interval:
            return False
        # 锁只包住一次心跳：close() 要等它落地才能发 idle，否则可能
        # 「idle 之后又被 busy 续上」，留下一条占着名额的死会话。
        with self._ping_lock:
            if self._closed:
                return False
            self._last_ping = time.time()
            ok, detail = ca_codearts.heartbeat(
                *(self._session_cred + (self.session_id, "busy")))
            if ok:
                # 顺手把登记表里的时间戳刷新：一条跑了两小时的流如果崩在
                # 第 90 分钟，启动清理不能因为「at 太老」就跳过它。
                track_codearts_session(self.session_id, self.account_label,
                                       self.account_key)
        if not ok:
            # 续期失败**不释放名额**：一次网络抖动不等于对话结束，急着 idle
            # 会把还活着的对话踢掉。收尾时照常 idle。
            log("codearts session renew failed: %s" % detail)
        return True

    def lines(self, abort_check=None, stats=None, idle_timeout=None):
        """逐行吐出上游 SSE（str）。续期在 _ping_loop 里，与读无关。

        上游静默时会 yield 一次 ``ca_codearts.KEEPALIVE`` —— 调用方**必须**
        判断哨兵，把它翻成给客户端的一条 SSE 注释（首帧前不要发，那时还没
        承诺 200）。见 ca_codearts.iter_sse。

        ``idle_timeout`` / ``max_idle`` 为空时退回模块默认。面板能调的就是
        这两个数，以前这里写死读模块常量，面板的「静默超时」改了不生效。
        """
        return ca_codearts.iter_sse(
            self.resp, abort_check, stats=stats,
            idle_timeout=(self.idle_timeout if idle_timeout is None
                          else idle_timeout),
            max_idle=self.max_idle)

    def byte_lines(self, abort_check=None, stats=None):
        """逐行吐出（bytes）—— Responses / Messages 的事件翻译器吃这种。

        哨兵原样透传，由调用方决定怎么翻译成协议里的事件（Responses 是
        ``response.in_progress``，Messages 是 ``ping``，Chat 是注释行）。
        """
        for line in self.lines(abort_check, stats):
            if line is ca_codearts.KEEPALIVE:
                yield line
            else:
                yield line.encode("utf-8")

    def close(self):
        self.close_upstream()
        self.release_slot()

    def close_upstream(self):
        """关上游连接 + 停续期线程。**不**发 idle、**不**还本地名额。

        单独拆出来是为了给收尾留出顺序：客户端要看到 ``[DONE]`` 才算这条流
        结束，而 idle 是一次最长 6 秒的同步 HTTP。以前 ``finally: close()``
        把 idle 排在 ``[DONE]`` 之前，上游一抖动客户端就要多等几十秒才看到
        结束标记（三段收尾各 6 秒）。现在先关连接（上游立刻回收会话），
        再去写 ``[DONE]``，最后才 idle + 还名额。
        """
        with self._ping_lock:
            if self._closed:
                return
            # 先占住锁：等在途的那次 busy 落地，然后再也不会有新的 busy。
            self._closed = True
        self._ping_stop.set()
        try:
            self.resp.close()      # 关上游连接 = 上游立刻回收这条会话
        except Exception:
            pass

    def release_slot(self):
        """idle 注销 + 还本地名额（幂等，close() 之后重复调用无害）。

        **先 idle、再还本地名额**。反过来会把「本地已经放行一个新人」和
        「上游还没收到 idle」重叠起来：新请求立刻向上游开会话，正好撞上
        那条还没注销的旧会话，于是白白吃一个 TM.00001041。聚合路径一直是
        这个顺序，流式这边原来是反的。
        """
        with self._slot_lock:
            if self._slot_released:
                return
            self._slot_released = True
        if self.session_id and self._session_cred:
            ok, detail = codearts_session_idle(
                self._session_cred, self.session_id)
            if not ok:
                log("codearts session idle failed: %s" % detail)
        _CODEARTS_POOL.release(self.account_key)


class _SettingsError(Exception):
    """``/settings/save`` 的校验失败：只承载「该回什么」，不写任何东西。

    以前 ``_handle_settings_save`` 是「边校验边写」—— ``api_keys`` 落盘之后，
    ``codearts`` 才发现区间不合法并回 400。面板显示保存失败，磁盘上却是
    一半生效（2026-10-23）。把失败装成异常，就只剩一个写入点。
    """

    def __init__(self, status, message, err_type="invalid_request_error"):
        super().__init__(message)
        self.status = int(status)
        self.message = str(message)
        self.err_type = err_type


class _DeferredHTTPError(Exception):
    """``fail`` 的「只决定、不写」版本：把该回的错误装成异常。

    为什么需要它：``_codearts_open_lease`` 在失败时会**自己**写 HTTP 错误
    （``fail(...)`` → ``_error`` → ``_json``）。第一次建连时这是对的 —— 头还
    没发，客户端该收到一个干净的状态码。但 chat 流式会在「上游断流、一个字
    都没吐」时**重开**一条：那时 200 和 SSE 头可能早就发出去了（上游先给了
    一个空 delta 帧，随后才断），再写一个完整 HTTP 响应就等于在一条 SSE 流
    里塞进「HTTP/1.1 503 …{json}」—— 客户端把状态行当 SSE 数据，整条流报废，
    而它本来还能收到一个错误帧（2026-10-23）。

    现在失败时抛这个，由调用方按「有没有发过头」二选一：发过头就写本协议的
    错误帧，没发过就写状态码。
    """

    def __init__(self, status, message, err_type="server_error",
                 retry_after=None, anthropic=False):
        super().__init__(message)
        self.status = int(status)
        self.message = str(message)
        self.err_type = err_type
        self.retry_after = retry_after
        self.anthropic = anthropic


# ---------------------------------------------------------------------------
# history-snip（soft 一档）：上下文压力的**投影式**裁剪。
#
# 官方 ContextMod 管线的完整顺序是 tool_budget → history_prune(soft/hard) →
# micro_compact → context_collapse，这里只实现 soft：压力到阈值时，把保护窗
# 之外的**大工具结果**替换成「头尾保留 + 官方一字不差的占位符」。本地（客户
# 端）历史不动 —— 网关本来就没有历史，投影即「只影响本次发上游的消息」。
# 它的直接收益：长会话里几十万字符的 read 结果不再反复占输入，触发面上游
# 的静默/排队/限流概率都随之下降。
# ---------------------------------------------------------------------------

#: soft 档触发压力 = 估算输入 token / 有效输入预算。官方默认 0.4，但对
#: glm-5.3（1M 窗口）那是 41 万 token 才触发 —— 真实会话的输入分布是
#: p50=30k / p90=91k / max=103k（2026-10-23~24 线上 159 次），0.4 的阈值
#: 永远够不着，坏窗口里 10 万 token 的请求照样整段被切。降到 0.1（glm-5.3
#: ≈10 万 token）从 p90 开始裁：只裁保护窗外的大工具结果，正文与最近 12
#: 个 user turn 不动，客户端几乎无感。
CODEARTS_PRUNE_SOFT_PCT = ca_env.number("CODEARTS_HISTORY_SOFT_TRIGGER_PCT",
                                        0.1, minimum=0.01)
#: soft 档保护窗：最近 N 个 user turn 的工具结果一律不裁。官方默认 12。
CODEARTS_PRUNE_PROTECTED_TURNS = ca_env.number(
    "CODEARTS_HISTORY_PROTECTED_TURNS", 12, minimum=0, integer=True)

#: 官方常量：结果 ≤4000 字符不动；裁剪保头尾各 1500；图片/pdf part 按 2000
#: token 计数且从不裁。
PRUNE_SOFT_KEEP_BOUND = 4000
PRUNE_SOFT_HEAD = 1500
PRUNE_SOFT_TAIL = 1500
PRUNE_IMAGE_TOKENS = 2000
#: 占位符与官方一字不差（官方按前缀 ``[Old tool result `` 识别这类替换）。
PRUNE_SOFT_PLACEHOLDER = ("\n[Old tool result truncated: %d characters "
                          "omitted. Original content remains in session "
                          "transcript]\n")

#: 可裁工具（官方 G3），比较用小写；写类（官方 w3 + compress.protectedTools）
#: 永不裁；其余工具按官方默认 not_pruneable —— 宁可少裁也不裁错。
_PRUNEABLE_TOOLS = {"read", "grep", "glob"}
_PRUNE_PROTECTED_TOOLS = {"edit", "write", "apply_patch", "multiedit",
                          "question", "skill", "task", "todowrite",
                          "todoread"}
_BASH_READONLY_RE = re.compile(
    r"^\s*(?:ls|find|rg|grep|cat|Get-Content|Select-String)\b", re.I)
_BASH_META_RE = re.compile(r"[;&|`]|\$\(|&&|\|\|")

#: 输出上限官方口径：inferhub 系一律 min(目录值, 32000)。
PRUNE_OUTPUT_TOKEN_MAX = 32000
#: 官方常量：预留输出（reservedOutput = min(24000, maxOut)）。
PRUNE_RESERVED_OUTPUT = 24000


def _prune_est_tokens(text):
    """官方估算器：``Math.round(len/4)``（中文记 1、emoji 记 2，无特殊处理）。"""
    return max(0, (len(text or "") + 2) // 4)


def _prune_message_tokens(messages):
    """整条 messages 的输入 token 估算（官方口径）。

    assistant 的 tool_calls 参数计入（官方把回放的 input 计入但从不裁它）；
    工具 schema 不计 —— 它不在 messages 里。
    """
    total = 0
    for m in messages if isinstance(messages, list) else []:
        if not isinstance(m, dict):
            continue
        for call in m.get("tool_calls") or []:
            fn = (call or {}).get("function") or {}
            total += _prune_est_tokens(
                json.dumps(fn.get("arguments") or "", ensure_ascii=False))
            total += _prune_est_tokens(fn.get("name"))
        content = m.get("content")
        if isinstance(content, str):
            total += _prune_est_tokens(content)
        elif isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                if str(part.get("type") or "") in ("image_url", "input_image",
                                                   "image"):
                    total += PRUNE_IMAGE_TOKENS
                else:
                    total += _prune_est_tokens(part.get("text"))
    return total


def _prune_prunable(name, arguments):
    """这个工具的结果能不能裁（官方 U3：保护名单 → 可裁名单 → bash 只读）。"""
    low = str(name or "").strip().lower()
    if low in _PRUNE_PROTECTED_TOOLS:
        return False
    if low in _PRUNEABLE_TOOLS:
        return True
    if low in ("bash", "shell"):
        try:
            args = (json.loads(arguments)
                    if isinstance(arguments, str) else arguments) or {}
        except Exception:
            return False
        command = str((args or {}).get("command") or "")
        return bool(_BASH_READONLY_RE.match(command)
                    and not _BASH_META_RE.search(command))
    return False


def _prune_soft_truncate(text):
    """官方 soft 截断：≤4000 不动；否则头尾各 1500 + 占位符。"""
    if len(text) <= PRUNE_SOFT_KEEP_BOUND:
        return text
    omitted = len(text) - PRUNE_SOFT_HEAD - PRUNE_SOFT_TAIL
    return (text[:PRUNE_SOFT_HEAD]
            + PRUNE_SOFT_PLACEHOLDER % omitted
            + text[-PRUNE_SOFT_TAIL:])


def prune_history_for_upstream(messages, model, max_tokens, source=""):
    """soft 档投影裁剪；压力不到阈值时**原样返回入参对象**（零开销路径）。

    ``max_tokens`` 只用于对齐官方日志口径（maxOut）；真正的预算是
    ``context_window - min(24000, maxOut)``。
    """
    if not isinstance(messages, list) or len(messages) < 2:
        return messages
    resolved = ca_codearts.resolve_model(str(model or ""))
    limits = ca_codearts.BUILTIN_MODEL_LIMITS.get(resolved) or (0, 0)
    context_window = limits[0] or 200000
    max_out = min(ca_codearts.MODEL_OUTPUT_CAPS.get(resolved)
                  or limits[1] or PRUNE_OUTPUT_TOKEN_MAX,
                  PRUNE_OUTPUT_TOKEN_MAX)
    reserved = min(PRUNE_RESERVED_OUTPUT, max_out)
    budget = max(1, context_window - reserved)
    estimated = _prune_message_tokens(messages)
    pressure = estimated / float(budget)
    if pressure < CODEARTS_PRUNE_SOFT_PCT:
        return messages

    total_turns = sum(1 for m in messages
                      if isinstance(m, dict) and m.get("role") == "user")
    prunable_last = total_turns - CODEARTS_PRUNE_PROTECTED_TURNS
    if prunable_last <= 0:
        log("history_prune.evaluate%s: model=%s stage=none (all %d user "
            "turns inside the %d-turn protection window) pressure=%.4f"
            % ((" [%s]" % source) if source else "", resolved, total_turns,
               CODEARTS_PRUNE_PROTECTED_TURNS, pressure))
        return messages

    # tool_call_id → (工具名, 参数串)：OpenAI 形状里 tool 消息只有 id，
    # 工具名要回头找发它的那条 assistant。
    name_by_id = {}
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "assistant":
            for call in m.get("tool_calls") or []:
                call = call or {}
                if call.get("id"):
                    fn = call.get("function") or {}
                    name_by_id[call["id"]] = (fn.get("name") or "",
                                              fn.get("arguments") or "")

    turn = 0
    changed = 0
    out = []
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "user":
            turn += 1
        new_m = m
        if (isinstance(m, dict) and m.get("role") == "tool"
                and turn <= prunable_last):
            name, arguments = name_by_id.get(m.get("tool_call_id"), ("", ""))
            if _prune_prunable(name, arguments):
                content = m.get("content")
                if isinstance(content, str):
                    trimmed = _prune_soft_truncate(content)
                    if trimmed != content:
                        new_m = dict(m, content=trimmed)
                        changed += 1
                elif isinstance(content, list):
                    new_parts = []
                    hit = False
                    for part in content:
                        if (isinstance(part, dict)
                                and isinstance(part.get("text"), str)):
                            trimmed = _prune_soft_truncate(part["text"])
                            if trimmed != part["text"]:
                                hit = True
                                new_parts.append(dict(part, text=trimmed))
                                continue
                        new_parts.append(part)
                    if hit:
                        new_m = dict(m, content=new_parts)
                        changed += 1
        out.append(new_m)

    log("history_prune.evaluate%s: model=%s contextWindow=%d maxOut=%d "
        "reservedOutput=%d estimatedInputTokens=%d effectiveInputBudget=%d "
        "pressure=%.4f softTriggerPct=%.2f protectedTurns=%d "
        "prunableTurns<=%d tool_results_truncated=%d"
        % ((" [%s]" % source) if source else "", resolved, context_window,
           max_out, reserved, estimated, budget, pressure,
           CODEARTS_PRUNE_SOFT_PCT, CODEARTS_PRUNE_PROTECTED_TURNS,
           prunable_last, changed))
    return out if changed else messages


def _codearts_max_tokens(payload):
    """请求里的输出上限；缺省取模型的目录值，坏值/负数一律按缺省。

    三个毛病一起修（2026-10-23）：

    1. **缺省值写死 4096**，而 Messages / Responses 两个入口用的是模型目录
       里的真实上限（glm-5.3 是 65536）。同一个模型、同一句提问，从 Chat 进来
       只能出 4096 token，从 Messages 进来能出 65536 —— 思考模型的推理和正文
       共用这个额度，长思考一上来就被截断，而截断（见
       ``_chat_finish_reason``）以前还报成 ``stop``，客户端完全看不出来。
    2. **负数原样透传**：``max_tokens: -1`` 会被当成合法的「上限」，上游对
       这种值回 001001005.400（一句「参数非法」，看不出是哪个参数）。现在
       按缺省处理 —— 客户端发一个明显无效的值，意图就是「没指定」。
    3. 非数字仍然按缺省（老行为）。
    """
    model = str(payload.get("model") or "")
    resolved = ca_codearts.resolve_model(model)
    limit = (ca_codearts.BUILTIN_MODEL_LIMITS.get(resolved)
             or (None, None))[1]
    # 目录里没有输出上限（kimi-k3 的输入窗口是 0，输出有值）时退回 4096：
    # 不拿别的模型的数字顶替，也不无限放大。
    default = int(limit) if limit else 4096
    value = (payload.get("max_tokens")
             or payload.get("max_completion_tokens"))
    if value is None:
        value = default
    else:
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = default
        else:
            if value <= 0:
                value = default
    # 官方口径钳制（ca_codearts.MODEL_OUTPUT_CAPS）：glm-5.3 官方每轮都发
    # 32000，我们以前按能力值 65536 顶满 —— 拉长上游排队，0203 的一部分。
    capped = ca_codearts.cap_output_tokens(resolved, value)
    if capped != value:
        log("clamping %s max_tokens from %d to %d (official request shape)"
            % (resolved, value, capped))
    return capped


def _codearts_extra(payload, cred=None):
    """思考参数 + 采样参数合成一份 extra（上游认的那些，见 ca_codearts）。

    两件事分开算、合一发：`thinking` / `reasoning_effort` 决定思考预算，
    `temperature` / `top_p` / `stop` / `seed` / 两个 penalty 决定采样。以前只
    合了前者，后者全丢 —— 见 ca_codearts.sampling_extra_from 的注释。

    ``stop_dropped`` 是**内部标记**，不能发给上游：``sampling_extra_from``
    用它告诉我们「超过 4 条的停止串被裁了几条」，这里记一行日志再摘掉。
    以前静默裁掉，客户端以为 6 条全生效（2026-10-23）。

    ``cred``：账号凭据 (ak, sk, st)。给全了才查官方档位表（带 1h 缓存，见
    ``ca_codearts.refresh_thinking_strengths``），把客户端的 effort 钳进白名
    单 —— glm-5.3 的白名单是空的，effort=max 深思考 60s 静默就是断流根源。
    没有凭据（形状日志等只读用途）时白名单按未知处理，维持转发。
    """
    effort_allowed = None
    if cred:
        try:
            effort_allowed = ca_codearts.refresh_thinking_strengths(
                cred[0], cred[1], cred[2],
                ca_codearts.resolve_model(str(payload.get("model") or "")))
        except Exception:              # noqa: BLE001 —— 档位表失败不拦请求
            effort_allowed = None
        # 模型真值（input/output 上限）顺路刷一次（TTL 1h，写回
        # BUILTIN_MODEL_LIMITS；失败保留旧值）—— 上游上新模型不用等手表。
        try:
            ca_codearts.refresh_model_limits(cred[0], cred[1], cred[2])
        except Exception:              # noqa: BLE001 —— 刷新失败不拦请求
            pass
    merged = {}
    for part in (ca_codearts.thinking_extra_from(payload,
                                                 effort_allowed=effort_allowed),
                 ca_codearts.sampling_extra_from(payload)):
        if part:
            merged.update(part)
    # 官方请求体顶层带 user_prompt（当前用户原话，2026-10-24 kernel 日志
    # 实证）。镜像官方形状；找不到用户正文（纯 tool_result 回合）就不带。
    prompt_text = ca_codearts.last_user_prompt_text(payload.get("messages"))
    if prompt_text:
        merged["user_prompt"] = prompt_text
    dropped = merged.pop("stop_dropped", 0)
    if dropped:
        log("stop_sequences capped: kept first 4, dropped %d (upstream accepts "
            "4 at most)" % dropped, level="INFO")
    return merged or None


def _codearts_response_format_error(payload):
    """``response_format`` 的拒绝文案；允许（或没给）时返回 None。

    上游根本不实现这个字段 —— 实测连 ``{"type": "bogus"}`` 都回 200，说明它
    被当未知键忽略。我们以前也静默丢掉，于是客户端以为 JSON 模式生效了，拿到
    散文后再自己解析失败，报错位置离真正原因十万八千里。

    ``"text"`` 放行（那就是默认行为，没必要拒绝）。要强制 schema 就用
    tools / function calling —— 那条路上游是真支持的。
    """
    fmt = (payload or {}).get("response_format")
    if not isinstance(fmt, dict):
        return None
    kind = str(fmt.get("type") or "").strip().lower()
    if kind in ("", "text"):
        return None
    return ("response_format.type=%r is not supported: the codearts upstream "
            "ignores this field (verified 2026-10-22 - even an invalid type "
            "returns 200), so structured output cannot be guaranteed. Remove "
            "the field and parse the text yourself, or force a schema through "
            "tools/function calling." % kind)


def _codearts_choice_count_error(payload):
    """``n>1`` 的拒绝文案；不拒绝就返回 None。

    上游只给一条 choice（``n=2`` 实测回帧内 001001005）。以前我们既不转发也不
    报错，客户端按 n=2 解析却只拿到一条 —— 形状对不上，比直接报错更难查。
    """
    try:
        n = int((payload or {}).get("n") or 1)
    except (TypeError, ValueError):
        n = 1
    if n <= 1:
        return None
    return ("n=%d is not supported: the codearts upstream returns exactly one "
            "choice per request. Send n=1 (or omit it) and repeat the call if "
            "you really need independent samples." % n)


_CODEARTS_CATALOG = {"at": 0.0, "models": [], "errors": {}}
_CODEARTS_CATALOG_TTL = 300.0
def codearts_catalog(force=False):
    """码道模型目录（内存缓存 5 分钟）。没有账号时返回空，不抛。"""
    now = time.time()
    if not force and (now - _CODEARTS_CATALOG["at"]) < _CODEARTS_CATALOG_TTL:
        return _CODEARTS_CATALOG
    sessions = ca_codearts.load_sessions(ACCOUNTS_DIR)
    # 「可用」= STS 未过期，**或虽然过期但还能续期**。以前只留前者，导致服务
    # 闲置两小时后 /v1/models 里的码道模型整体消失、看板「刷新榜单」也只会
    # 回「没有可用码道账号」—— 明明账号还在、refresh_token 也还有效。
    usable = []
    for candidate in sessions:
        _, expired, renewable = _codearts_left(candidate)
        if not expired or renewable:
            usable.append(candidate)
    if not usable:
        # 把「为什么空」写进 errors：面板要靠它告诉用户是没账号还是 STS 过期，
        # 而不是只显示一片空白。
        reason = ("no codearts account" if not sessions
                  else "all codearts sessions have expired STS")
        _CODEARTS_CATALOG.update({"at": now, "models": [],
                                  "errors": {"sessions": reason}})
        return _CODEARTS_CATALOG
    # 过期但可续期的会话现续；一个账号续失败就试下一个，全部失败才算空。
    sess = None
    for candidate in usable:
        candidate = _ensure_fresh(candidate)
        if not _codearts_left(candidate)[1]:
            sess = candidate
            break
    if sess is None:
        _CODEARTS_CATALOG.update({
            "at": now, "models": [],
            "errors": {"sessions": "codearts STS expired and renewal failed"}})
        return _CODEARTS_CATALOG
    try:
        cat = ca_codearts.model_catalog(
            sess.get("accessKey"), sess.get("secretKey"),
            sess.get("securitytoken"))
        models, errors = cat.get("models") or [], cat.get("errors") or {}
    except Exception as exc:
        models, errors = [], {"catalog": str(exc)}
    # 只暴露实测可用的那些：服务端报了但打不通的模型进清单只会误导客户端。
    models = [m for m in models if m.get("id") in ca_codearts.CHAT_MODELS
              and m.get("routable", True)]
    _CODEARTS_CATALOG.update({"at": now, "models": models, "errors": errors})
    return _CODEARTS_CATALOG


#: 模型别名表文件名（放在 accounts/ 下，与 settings.json 同级）。
#:
#: 为什么需要：Claude Code 默认发 `claude-sonnet-4-5-20250929`、Codex CLI 发
#: `gpt-5-codex`，这些名字我们一个都不服务 —— 不改客户端配置就是 404。别名让
#: 「换网关不换配置」成立，而不是逼用户去改 ANTHROPIC_MODEL / `-m`。
#:
#: **默认空**，刻意不内置任何猜测：写错一个别名比没有别名更糟（请求会静默
#: 打到别的模型上，用户看到的是「回答不对」而不是「模型不存在」）。
MODEL_ALIASES_FILE = "model_aliases.json"

#: mtime 缓存的别名表。改完文件下一个请求就生效，不用重启进程。
_MODEL_ALIASES = {"mtime": -2.0, "map": {}}


def model_aliases():
    """读别名表：``{"客户端写的名字": "码道模型名"}``。读不出来就当没有。"""
    path = os.path.join(ACCOUNTS_DIR, MODEL_ALIASES_FILE)
    try:
        stamp = os.stat(path).st_mtime
    except OSError:
        _MODEL_ALIASES.update({"mtime": -1.0, "map": {}})
        return {}
    if stamp == _MODEL_ALIASES["mtime"]:
        return _MODEL_ALIASES["map"]
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception as exc:
        # 只记一次（mtime 没变就不会重复进来），别让坏文件刷屏。
        _MODEL_ALIASES.update({"mtime": stamp, "map": {}})
        log("model aliases unreadable (%s): %s" % (path, exc))
        return {}
    mapping = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            name = str(key or "").strip()
            target = value.strip() if isinstance(value, str) else ""
            if name and target:
                mapping[name.lower()] = target
    _MODEL_ALIASES.update({"mtime": stamp, "map": mapping})
    return mapping


def alias_target(model_id):
    """这个别名指向哪个模型（没有就返回空串）。大小写无关。"""
    name = str(model_id or "").strip().lower()
    if not name:
        return ""
    return model_aliases().get(name, "")


def collapse_duplicate_v1(path):
    """``/v1/v1/messages`` → ``/v1/messages``（重复的 ``/v1`` 前缀折掉一层）。

    为什么会有人这么配：OpenAI SDK 的 ``base_url`` 约定**含** ``/v1``，Anthropic
    SDK 约定**不含**。用户把同一个网关地址分别贴进两个客户端，必有一个多写
    一层，得到的却是 ``404 not found`` —— 看起来像「网关不支持这个端点」，
    实际只是路径拼重了。2026-10-22 的日志里 ``POST /v1/v1/messages`` 出现 24 次，
    用户显然卡在这里。

    只折 ``/v1/v1/...`` 这一种形态，且是循环折：贴三次也不会漏。
    """
    text = str(path or "")
    while text.startswith("/v1/v1/"):
        text = "/v1/" + text[len("/v1/v1/"):]
    return text


def _chat_finish_reason(upstream, has_tool_calls=False):
    """非流式渲染用的 finish_reason：透传上游的，别把截断说成说完了。

    三点：
      · 上游说 ``length``（撞 max_tokens）就必须原样传给客户端 —— 以前一律
        写 ``stop``，客户端以为回答完整，截断的工具参数当成完整 JSON 去解析，
        拿到的是坏 JSON 还不报错；
      · 有工具调用时上游可能给 ``stop``（有的实现只在最后一个调用帧上带
        ``tool_calls``），这时按 ``tool_calls`` 报 —— 客户端据此决定要不要执行，
        报 stop 它就当这轮结束了；
      · 上游什么都没说（``""``/None）时退回 ``stop``，保持老行为。
    """
    reason = str(upstream or "").strip().lower()
    if has_tool_calls and reason in ("", "stop"):
        return "tool_calls"
    if reason in ("stop", "length", "tool_calls", "content_filter", "function_call"):
        return reason
    return "stop"


def _codearts_request_shape(payload, messages, max_tokens):
    """把请求形状压成一行，供失败时打日志。

    `InferHub.001001005.400 The request param is invalid` 是码道最常见也最没
    信息量的失败（2026-10-22 的日志里 21 次，全部 model=glm-5.3）—— 上游不说
    是哪个参数错了，只说「无效」。而它可能来自 max_tokens 越界、上下文过长、
    图片塞给了非多模态模型、tools 形状不对…… 不看这些数字根本没法区分。
    所以失败时把形状一起打出来，下一次就不用猜了。

    只统计，不记录任何正文（日志里不该出现用户内容）。
    """
    chars = 0
    images = 0
    parts = 0
    acall = 0
    for message in messages or []:
        if not isinstance(message, dict):
            continue
        # assistant 的 tool_calls 参数不在 content 里：一次 write_file 可以带
        # 上百 KB 文件内容，只数 content 会把请求看成「只有 30K 字符」。
        for call in message.get("tool_calls") or []:
            try:
                acall += len(json.dumps((call or {}).get("function") or {},
                                        ensure_ascii=False))
            except Exception:
                pass
        content = message.get("content")
        if isinstance(content, str):
            chars += len(content)
            continue
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            parts += 1
            kind = str(part.get("type") or "")
            if kind in ("image_url", "input_image", "image"):
                images += 1
            text = part.get("text")
            if isinstance(text, str):
                chars += len(text)
    # 工具的 JSON 字节数单独算：55 个 MCP 工具的 schema 可以轻松上百 KB
    # （约等于几万 token），只看 messages 的字符数会把它当成「请求很小」。
    # 顶层的「额外键」与 thinking 细节：ZCode 会带 stream_options /
    # metadata / parallel_tool_calls 之类，也可能给一个很大的
    # budget_tokens —— 只看 thinking=yes 分不出是哪一项把上游顶死的。
    extra_keys = ""
    think = ""
    _extra = None
    if isinstance(payload, dict):
        extra_keys = ",".join(sorted(
            k for k in payload if k not in ("messages", "tools", "model")))
        # 档位白名单只读缓存/种子（不发网络请求），让 `think=` 反映**实际
        # 发给上游**的参数 —— 白名单把 effort 丢掉时，日志若还写 effort=max
        # 会把排查引到沟里。
        _allowed = ca_codearts.thinking_strengths_for(
            ca_codearts.resolve_model(str(payload.get("model") or "")))
        _extra = ca_codearts.thinking_extra_from(payload,
                                                 effort_allowed=_allowed)
        thinking = (_extra or {}).get("thinking")
        if isinstance(thinking, dict):
            think = str(thinking.get("type") or "")[:8]
            if thinking.get("budget_tokens") is not None:
                think += "/%s" % thinking.get("budget_tokens")
        effort = payload.get("reasoning_effort") or payload.get("reasoningEffort")
        if effort:
            effort = str(effort).strip().lower()
            if _allowed is not None and effort not in _allowed:
                think += "/effort=%s(dropped: not in model whitelist)" % str(effort)[:8]
            else:
                think += "/effort=%s" % str(effort)[:8]
    tools = payload.get("tools") if isinstance(payload, dict) else None
    tchars = 0
    ttypes = {}
    if isinstance(tools, list):
        try:
            tchars = len(json.dumps(tools, ensure_ascii=False))
        except Exception:
            tchars = 0
        for t in tools:
            if isinstance(t, dict):
                key = str(t.get("type") or "?")
                ttypes[key] = ttypes.get(key, 0) + 1
    tchoice = ""
    if isinstance(payload, dict):
        choice = payload.get("tool_choice")
        if isinstance(choice, str):
            tchoice = choice[:16]
        elif isinstance(choice, dict):
            tchoice = str(choice.get("type") or "obj")[:16]
    return ("max_tokens=%s msgs=%d parts=%d chars=%d tchars=%d acall=%d "
            "images=%d tools=%d ttypes=%s tchoice=%s stream=%s thinking=%s "
            "think=%s keys=%s"
            % (max_tokens, len(messages or []), parts, chars, tchars, acall,
               images,
               len(tools) if isinstance(tools, list) else 0,
               ",".join("%s:%d" % kv for kv in sorted(ttypes.items())) or "-",
               tchoice or "-",
               bool((payload or {}).get("stream")) if isinstance(payload, dict) else False,
               "yes" if _extra else "no",
               think or "-", extra_keys or "-"))


#: 失败请求快照的保留上限（份数）与最老年龄。
#:
#: 以前只靠「5 分钟内最多一份」限速，而**数量本身没有上限**：长时间运行的
#: 部署一天能攒几十份（每份的主题是同一批工具 schema，几十 KB 到几百 KB），
#: 从来没有人删。现在落新的一份时顺手把超量的、超龄的清掉 —— 淘汰是
#: 「让下一份能落下来」的一部分，不需要另起清理线程。
CODEARTS_DUMP_MAX = ca_env.number("CODEARTS_DUMP_MAX", 20,
                                  minimum=1, integer=True)
CODEARTS_DUMP_MAX_AGE = ca_env.number("CODEARTS_DUMP_MAX_AGE", 7 * 86400.0,
                                      minimum=60.0)


def _dump_prefix():
    return "failed-req-"


def _prune_failed_dumps(folder, keep_path=None, now=None):
    """只留最新的 ``CODEARTS_DUMP_MAX`` 份，且不超过 ``CODEARTS_DUMP_MAX_AGE``。

    返回删掉的份数。``keep_path`` 是刚写下的那份，按年龄淘汰时不删它 ——
    否则把上限调得比一份还小的时候，刚落盘的文件会被自己删掉。
    """
    now = time.time() if now is None else now
    try:
        names = [n for n in os.listdir(folder) if n.startswith(_dump_prefix())]
    except OSError:
        return 0
    entries = []
    for name in names:
        path = os.path.join(folder, name)
        try:
            entries.append((os.path.getmtime(path), path))
        except OSError:
            continue
    entries.sort(reverse=True)              # 新的在前
    removed = 0
    for index, (mtime, path) in enumerate(entries):
        too_many = index >= CODEARTS_DUMP_MAX
        too_old = (now - mtime) > CODEARTS_DUMP_MAX_AGE and path != keep_path
        if not (too_many or too_old):
            continue
        try:
            os.unlink(path)
            removed += 1
        except OSError:
            continue
    return removed


def dump_failed_request(payload, messages, max_tokens):
    """把失败请求的**工具定义**落盘，供离线复现（不含任何消息正文）。

    只靠 shape 的数字复现不了 0203：92KB 的工具 schema 里可能有 $ref、
    anyOf、超长 enum，体积相同、结构不同，后端表现完全不同。这里只存
    tools / tool_choice / thinking —— 都是客户端配置，不是用户内容。

    开关是 ``WB_DUMP_FAILED_TOOLS``，默认关闭；5 分钟内最多留一份，避免
    客户端反复重试时把盘刷满。数量与年龄另有上限（``_prune_failed_dumps``），
    否则长期运行的部署会把它攒成一份没人管的日志。
    """
    if not os.environ.get("WB_DUMP_FAILED_TOOLS"):
        return
    if not isinstance(payload, dict):
        return
    try:
        folder = os.path.dirname(USAGE_LOG) or "."
        now = time.time()
        for name in os.listdir(folder):
            if name.startswith(_dump_prefix()):
                try:
                    if now - os.path.getmtime(os.path.join(folder, name)) < 300:
                        return
                except OSError:
                    continue
        path = os.path.join(folder, "failed-req-%d.json" % int(now))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({
                "model": payload.get("model"),
                "shape": _codearts_request_shape(payload, messages, max_tokens),
                "tool_choice": payload.get("tool_choice"),
                "thinking": (ca_codearts.thinking_extra_from(payload) or {}).get("thinking"),
                "max_tokens": max_tokens,
                "tools": payload.get("tools"),
            }, fh, ensure_ascii=False)
        removed = _prune_failed_dumps(folder, keep_path=path, now=now)
        log("codearts failed request dumped: %s%s"
            % (path, (" (pruned %d old)" % removed) if removed else ""))
    except Exception as exc:                 # noqa: BLE001
        log("codearts failed request dump skipped: %r" % (exc,))


def canonicalize_model(payload):
    """把请求体里的 ``model`` 换成上游真名（就地改，返回同一个 dict）。

    三个协议入口都要过一遍，原因见 ``ca_codearts.resolve_model``：客户端的
    小写写法和上游真名对不上时，**报错和模型名毫无关系**（503 没有可用账号 /
    001001005 参数错 / 002002009 模型未注册），排查成本极高。

    先查别名表再走真名归一：别名是用户显式配的映射，优先级高于「大小写改写」。
    别名指向的名字本身也过一遍归一 —— 用户在别名表里写小写 ``glm-5.2`` 时
    不该因此绕过 max_tokens 夹紧。

    认不出来的名字原样留着 —— 是不是码道模型由码道清单决定（``codearts_catalog``），
    不存在「本地改名」这回事。
    """
    if not isinstance(payload, dict):
        return payload
    given = payload.get("model")
    real = alias_target(given) or ca_codearts.resolve_model(given)
    real = ca_codearts.resolve_model(real) if real else real
    if real != given:
        payload["model"] = real
    return payload


def is_codearts_model(model_id):
    """这个模型名是不是码道的（**大小写无关**）。

    上游模型 id 的大小写是混的（``GLM-5.2`` / ``glm-5.3`` / ``Qwen3-VL-235B``），
    客户端却习惯一律小写。精确比较会让 ``glm-5.2`` 判成「不是码道模型」，请求
    掉进 WorkBuddy 池，在只配了码道账号的部署里回一个
    ``503 no usable account`` —— 报错和模型名毫无关系，用户根本猜不到原因。
    见 ca_codearts.resolve_model。
    """
    return ca_codearts.resolve_model(model_id) in ca_codearts.CHAT_MODELS


def codearts_deployed():
    """这个部署是否真的配了码道账号（会话文件存在且能读出来）。

    判据和 /v1/models 里那句「有没有码道账号」完全一致：都看会话存不存在，
    不看目录取没取到模型 —— 上游抖动时目录会空，但账号还在。
    """
    try:
        return bool(ca_codearts.load_sessions(ACCOUNTS_DIR))
    except Exception:
        return False


def unserved_model_message(model_id):
    available = [m for m in ca_codearts.CHAT_MODELS] if codearts_deployed() else []
    hint = ""
    if codearts_deployed():
        # 常见情况是客户端自带一套模型名（Claude Code / Codex CLI 都是硬编码的），
        # 用户不知道可以在网关侧做映射。把「怎么办」写进报错，比让他猜好。
        hint = (" If the client insists on its own name (claude-sonnet-4-5-*, "
                "gpt-5-codex, ...), map it in accounts/%s." % MODEL_ALIASES_FILE)
    return ("model '%s' is not served by this gateway. Available: %s%s"
            % (model_id, ", ".join(available) or "(none - no account configured)",
               hint))


#: STS 剩这么多秒时就开始续期。码道的 STS 只有约 2 小时寿命，
#: 不自动续的话服务会每隔两小时静默 503 一次（实测踩到过）。
CODEARTS_REFRESH_MARGIN = ca_codearts.REFRESH_MARGIN_SECONDS


def _codearts_left(sess):
    """返回 (剩余秒, 是否已过期, 是否可续期)。"""
    try:
        su = ca_codearts.summarize(sess)
    except Exception:
        return None, True, False
    return (su.get("sts_remaining_seconds"), bool(su.get("sts_expired")),
            bool(su.get("renewable")))


def _ensure_fresh(sess):
    """STS 快到期（或已过期）就先续一次，别等请求打到上游才 503。

    串行化与「锁内重读」都在 ca_codearts.refresh_session 里完成，这里只管
    打日志和兜底：续期失败时把旧会话原样交回，让调用方拿到上游的真实错误。
    """
    left = _codearts_left(sess)[0]
    try:
        renewed = ca_codearts.ensure_fresh_session(
            ACCOUNTS_DIR, sess, CODEARTS_REFRESH_MARGIN)
    except Exception as exc:      # noqa: BLE001
        log("codearts: STS renew failed for %s: %s"
            % ((sess.get("account") or {}).get("label"), exc), level="WARN")
        return sess
    if renewed is not sess:
        log("codearts: renewed STS for %s (was %ss left)"
            % ((sess.get("account") or {}).get("label"), left))
    return renewed


def codearts_model_meta(m):
    """把 ca_codearts 归一后的模型转成 model_entry 期望的 meta 形状。

    这一步不能省：model_entry 的契约里 ``contextWindow`` 是**带
    supportedLengths 的 dict**，而 ca_codearts 归一出来的是数字。直接把它自己
    的输出喂进去会 AttributeError: 'int' object has no attribute 'get' ——
    第一次接清单就栽在这上面，而且异常被外层 try 吞成了「清单里没有码道模型」，
    表现成「功能没生效」，不报错也看不出原因。
    """
    ctx = int(m.get("contextWindow") or m.get("maxInputTokens") or 0)
    meta = {
        "name": m.get("name") or m.get("id"),
        "descriptionZh": m.get("description") or "",
        "supportsImages": bool(m.get("supportsImages")),
        "supportsToolCall": bool(m.get("supportsToolCall")),
        "supportsReasoning": bool(m.get("supportsReasoning")),
        "vendor": "codearts",
    }
    if ctx:
        meta["contextWindow"] = {"supportedLengths": [ctx]}
        meta["maxInputTokens"] = ctx
    out = int(m.get("maxOutputTokens") or 0)
    if out:
        meta["maxOutputTokens"] = out
    # ---- 倍率 / 计费 ----
    # model_entry 的 ``credits`` 是**字符串**（WorkBuddy 那批给的是 "0.79"），
    # 面板会自己在后面拼一个 "x"。码道这边原始字段里 ratio_display 已经带
    # 单位（"0.7x"），直接把 dict 塞进去会渲染成 "[object Object]" —— 2026-10-21
    # 就是这样在榜单上漏了一个坏值，所以这里统一裁成纯数字。
    tier = m.get("creditTier") or {}
    display = str(m.get("creditRatio") or tier.get("ratio_display") or "").strip()
    display = display.rstrip("xX").strip()
    if display:
        meta["credits"] = display
    pricing = m.get("creditPricing")
    if pricing:
        meta["creditPricing"] = pricing
    # ---- 缺省采样参数 ----
    # 上游 AgentCenter 的真实默认值（ca_codearts.BUILTIN_MODEL_SAMPLING）。
    # model_entry 会原样带到 /v1/models，面板的「默认采样参数」列读的就是它。
    for key in ("temperature", "top_p"):
        if m.get(key) is not None:
            meta[key] = m[key]
    # ---- 官方选模真值 + 健康度（2026-10-24 学习 model-selector）----
    truth = ca_codearts.model_truth_meta(m.get("id"))
    if truth.get("tags"):
        meta["tags"] = truth["tags"]
    if truth.get("scenario"):
        meta["scenario"] = truth["scenario"]
    try:
        meta["health"] = model_health(m.get("id"))
    except Exception:
        pass
    # ---- 思考档位 ----
    # 逆向后确认：strengths 里的字符串直接就是请求里的 reasoning_effort
    # （客户端 mB() 拼成 {reasoningEffort: 值}）。上游**不接受关闭思考**，
    # thinking.type=disabled 会回 81001，所以 canDisableThinking 恒为 false。
    strengths = m.get("thinkingStrengths") or []
    if strengths:
        meta["reasoning"] = {
            "supportedEfforts": list(strengths),
            "defaultEffort": m.get("thinkingDefault") or strengths[0],
            "canDisableThinking": False,
        }
    return meta


def codearts_model_entry(m):
    """码道模型 → /v1/models 条目。形状跟 WorkBuddy 那批一致，厂商标明 codearts。"""
    entry = model_entry(m["id"], codearts_model_meta(m))
    entry["owned_by"] = "codearts"
    entry["group"] = m.get("group") or ""
    if m.get("creditRatio"):
        entry["credit_ratio"] = m["creditRatio"]
    # 计费规则原样带出：光有倍率算不出花多少积分，调用方需要三个单价与 ratio。
    pricing = m.get("creditPricing")
    if pricing:
        entry["credit_pricing"] = pricing
    return entry


class _CodeartsRateLimit(Exception):
    """给 ``_rate_limited`` 用的最小载体（码道路径没有现成的异常对象）。"""

    def __init__(self, message, wait=10):
        Exception.__init__(self, message)
        self.message = message
        self.wait = max(1, int(wait))
        self.detail = ""


class _BufferedSSELines:
    """把已经收完的 SSE 文本伪装成字节行流。

    码道只支持「一次请求读完整条流」，而 Responses 的事件翻译器吃的是
    可迭代的行流。桥接层拿到的既然已经是完整文本，就按行重放给它，
    这样流式/非流式两条路径共用同一套事件生成逻辑。
    """

    def __init__(self, text):
        self._lines = (text or "").encode("utf-8").splitlines(keepends=True)

    def __iter__(self):
        return iter(self._lines)

    def close(self):
        pass


def model_entry(mid, meta):
    """Build a rich /v1/models entry from the desktop app catalog metadata.
    The OpenAI spec only names id/object/created/owned_by, so capability data is
    convention-driven. Several shapes are emitted at once so that different
    clients (OpenRouter-style, LobeChat-style, plain-flag readers) all find
    what they look for.
    """
    meta = meta or {}
    item = {
        "id": mid,
        "object": "model",
        "created": int(time.time()),
        "owned_by": "codearts",
    }
    name = meta.get("name")
    if name:
        item["name"] = name
    desc = meta.get("descriptionEn") or meta.get("descriptionZh")
    if desc:
        item["description"] = desc
    # ---- modality / capability ----
    # disabledMultimodal explicitly turns image input off; absent means allowed.
    vision = bool(meta.get("supportsImages")) and not meta.get("disabledMultimodal")
    if mid == "glm-5.3-flash":
        # 强制修正：上游元数据虽宣告支持多模态，但后端实际未接入视觉通道（见 issue #315）
        vision = False
        item["vision_note"] = "上游宣告多模态但实际通道不支持读图，已修正为纯文本" 
    tools = bool(meta.get("supportsToolCall"))
    thinks = bool(meta.get("supportsReasoning"))
    inputs = ["text"] + (["image"] if vision else [])
    # Capability flags under every spelling the common clients look for.
    # /v1/models has no standard for this, so each convention is emitted at
    # once rather than guessing which one a given client reads:
    #   capabilities.vision      generic
    #   supports_vision/images   LobeChat-style flat flags
    #   vision                   Cherry Studio / NextChat style
    #   abilities.vision         LobeChat
    #   multimodal               misc
    #   *_modalities             OpenRouter
    item["capabilities"] = {
        "vision": vision,
        "tool_calls": tools,
        "reasoning": thinks,
    }
    item["supports_vision"] = vision
    item["supports_images"] = vision
    item["supports_tool_calls"] = tools
    item["supports_reasoning"] = thinks
    item["vision"] = vision
    item["multimodal"] = vision
    item["abilities"] = {
        "vision": vision,
        "functionCall": tools,
        "function_call": tools,
        "reasoning": thinks,
    }
    item["input_modalities"] = inputs
    item["output_modalities"] = ["text"]
    item["modalities"] = {"input": inputs, "output": ["text"]}
    # OpenRouter-shaped block, read by several multi-provider clients.
    item["architecture"] = {
        "input_modalities": inputs,
        "output_modalities": ["text"],
        "modality": "+".join(inputs) + "->text",
    }
    # ---- limits ----
    # Four-level lookup: remote > built-in knowledge table > local model.json
    # cache > models.dev (asynchronously warmed; never blocks). context_length
    # always has a value (1M when unknown - a high estimate is safer than a
    # low one); max_output_tokens is omitted when unknown.
    ctx_value, out_value, _limit_source = ca_modelsdev.lookup(
        mid, meta.get("maxInputTokens"), meta.get("maxOutputTokens"),
        directory=ACCOUNTS_DIR)
    item["context_length"] = ctx_value
    item["max_input_tokens"] = ctx_value
    # 这个数字从哪来的：remote / table / cache / default。面板要靠它区分
    # 「上游真的说了」和「谁都不知道，按 1M 兜底」—— 后者不能当事实展示。
    item["context_source"] = _limit_source.get("context")
    if out_value:
        item["max_output_tokens"] = out_value
        item["max_completion_tokens"] = out_value
    # Annotate the measured upstream clamp (from output_probes.json) without
    # overriding the model's spec value; the panel shows "钳制 N×" beside it.
    clamp = ca_probes.clamp_for(ACCOUNTS_DIR, mid)
    if clamp:
        item["output_clamp"] = clamp
        item["max_output_tokens_clamped"] = clamp
    ctx = (meta.get("contextWindow") or {}).get("supportedLengths")
    if ctx:
        item["context_windows"] = ctx
    # ---- reasoning controls ----
    reasoning = meta.get("reasoning") or {}
    efforts = reasoning.get("supportedEfforts")
    if efforts:
        item["reasoning_efforts"] = efforts
    if reasoning.get("effort"):
        item["reasoning_fixed_effort"] = reasoning["effort"]
    if reasoning.get("defaultEffort"):
        item["reasoning_default_effort"] = reasoning["defaultEffort"]
    if reasoning.get("canDisableThinking") is not None:
        item["reasoning_can_disable"] = reasoning["canDisableThinking"]
    if meta.get("onlyReasoning") is not None:
        item["always_reasoning"] = bool(meta.get("onlyReasoning"))
    # ---- misc ----
    if meta.get("credits"):
        item["credits"] = meta["credits"]
    # 健康度与官方选模标签（health 由 model_health 提供，tags/scenario 来自
    # agent-center 的 custom_config.tags —— 官方 flagship/fallback 选模真值）。
    if meta.get("health"):
        item["health"] = meta["health"]
    if meta.get("tags"):
        item["tags"] = meta["tags"]
    if meta.get("scenario"):
        item["scenario"] = meta["scenario"]
    if meta.get("vendor"):
        item["vendor"] = meta["vendor"]
    if meta.get("temperature") is not None:
        item["temperature"] = meta["temperature"]
    if meta.get("top_p") is not None:
        item["top_p"] = meta["top_p"]
    if meta.get("isDefault"):
        item["is_default"] = True
    tags = [t for t in (meta.get("tags") or []) if isinstance(t, str) and not t.startswith("badge:")]
    if tags:
        item["tags"] = tags
    return item
# ---------------------------------------------------------------------------
# Fingerprint Sanitization (immunizes against Codex / Claude Code WAF patterns)
# ---------------------------------------------------------------------------
SANITIZE_FEATURES = (
    "x-anthropic-billing-header",
    "cc_entrypoint=",
    "You are Claude Code",
    "Main branch (",
    "You are a coding agent running in the Codex CLI",
    "github.com/anthropics/",
    "11128",
)
SANITIZE_REWRITES = (
    ("You are Claude Code, Anthropic's official CLI for Claude",
     "You are Claude Code, Anthropic's official CLI tool for Claude"),
    ("Main branch (you will usually use this for PRs)",
     "Default branch (you will usually use this for PRs)"),
    ("You are a coding agent running in the Codex CLI, a terminal-based coding assistant.",
     "You are a coding agent running in the Codex CLI tool, a terminal-based coding assistant."),
    ("To give feedback, users should report the issue at https://github.com/anthropics/claude-code/issues",
     "To provide feedback, users should report the issue at https://github.com/anthropics/claude-code/issues"),
    ("11128", "11-128"),
)
SANITIZE_HDR_RE = re.compile(r"(?i)x-anthropic-billing-header:[^;\r\n]*;?\s*")
SANITIZE_BARE_HDR_RE = re.compile(r"(?i)x-anthropic-billing-header")
SANITIZE_KV_RE = re.compile(r"(?i)\bcc_[a-z0-9_]+=[^;\r\n]*;?\s*")
# WorkBuddy upstream returns 11128 ("Illegal API invocation from an unapproved
# channel") when this exact OmO identity fingerprint appears as a contiguous
# substring in a system message. A/B tests show the match is case-insensitive,
# survives surrounding prefix/suffix text, and stops matching when the phrase
# structure is changed. Rewrite only this confirmed fingerprint, leaving the
# agent identity and behaviour intact while dropping the framework attribution.
SANITIZE_OMO_JUNIOR_RE = re.compile(
    r"Sisyphus-Junior - Focused executor from OhMyOpenCode", re.IGNORECASE
)
# 指纹判定的字面量快路径（见 has_fingerprint）：原先对每段文本跑两个 (?i) 正则，
# 4KB 输入实测 319µs，其中正则 137+188µs、几个 `in` 只占 9µs；64KB 文本要
# 6.2ms，而 sanitize_messages 会给每个文本段都过一遍——build_upstream_body
# (168KB) 的耗时约 95% 都耗在这里（13.60ms -> 2.14ms）。
# 两个模式都是纯字面量，换成小写副本上的 `in` 之后是纯 C 速度的单遍扫描。
#
# 等价性：re.IGNORECASE 的 Unicode 语义与 str.lower() 只有三处差异（CPython
# 3.13 全码点实测，其余所有带大小写的码点两法完全一致）：
#   'İ'(U+0130) 与 'ı'(U+0131) 能匹配字面量 i，'ſ'(U+017F) 能匹配 s，
# 而这三个字符的 lower() 并不落到 i/s。所以先把它们按 SANITIZE_REI_FOLD
# 归一化成基字母、再小写，副本上的 `in` 与 (?i) search 完全等价（多字符模式
# 同样成立；全码点替换 + 定向用例 + 随机串对拍零差异，见 tests/_test_hotpath_savings.py）。
SANITIZE_REI_FOLD = str.maketrans({0x130: "i", 0x131: "i", 0x17F: "s"})
# 两个小写字面量直接从正则派生，保证与正则永远同源：手抄第二份迟早漂移，
# 派生出来的值不存在这个问题。pattern 里的 (?i) 是内联旗标，剥掉后就是
# 字面量本体。
SANITIZE_BARE_HDR_LOWER = SANITIZE_BARE_HDR_RE.pattern
if SANITIZE_BARE_HDR_LOWER.startswith("(?i)"):
    SANITIZE_BARE_HDR_LOWER = SANITIZE_BARE_HDR_LOWER[4:]
SANITIZE_OMO_JUNIOR_LOWER = SANITIZE_OMO_JUNIOR_RE.pattern.lower()
def has_fingerprint(text):
    if not isinstance(text, str) or not text:
        return False
    for f in SANITIZE_FEATURES:
        if f in text:
            return True
    # 三个特例字符几乎从不出现：先做三次 C 速度探测，命中才走归一化副本，
    # 常规文本只付一次 lower()。
    if "\u0130" in text or "\u0131" in text or "\u017f" in text:
        low = text.translate(SANITIZE_REI_FOLD).lower()
    else:
        low = text.lower()
    return SANITIZE_BARE_HDR_LOWER in low or SANITIZE_OMO_JUNIOR_LOWER in low
def sanitize_text(text):
    if not isinstance(text, str) or not text:
        return text
    if not has_fingerprint(text):
        return text
    # Keep the rewrite deliberately narrow: do not globally remove
    # "OhMyOpenCode" or "Sisyphus-Junior", because either token alone is
    # accepted by the upstream. Only the confirmed contiguous fingerprint is
    # neutralized.
    text = SANITIZE_OMO_JUNIOR_RE.sub("Sisyphus-Junior - Focused executor", text)
    for old, new in SANITIZE_REWRITES:
        text = text.replace(old, new)
    text = SANITIZE_HDR_RE.sub("", text)
    if "cc_" in text:
        prev = ""
        while prev != text:
            prev = text
            text = SANITIZE_KV_RE.sub("", text)
    text = SANITIZE_BARE_HDR_RE.sub("x-anthropic-billing-hdr", text)
    return text.strip()
def sanitize_content(content):
    if isinstance(content, str):
        return sanitize_text(content)
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                p = dict(part)
                p["text"] = sanitize_text(p["text"])
                out.append(p)
            else:
                out.append(part)
        return out
    return content
def sanitize_tool_calls(tool_calls):
    if not isinstance(tool_calls, list):
        return tool_calls
    out = []
    for tc in tool_calls:
        if isinstance(tc, dict):
            item = dict(tc)
            fn = item.get("function")
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                fn = dict(fn)
                fn["arguments"] = sanitize_text(fn["arguments"])
                item["function"] = fn
            out.append(item)
        else:
            out.append(tc)
    return out
def sanitize_messages(messages):
    out = []
    for m in messages or []:
        if isinstance(m, dict):
            item = dict(m)
            if "content" in item:
                item["content"] = sanitize_content(item["content"])
            if isinstance(item.get("reasoning_content"), str):
                item["reasoning_content"] = sanitize_text(item["reasoning_content"])
            if "tool_calls" in item:
                item["tool_calls"] = sanitize_tool_calls(item["tool_calls"])
            out.append(item)
        else:
            out.append(m)
    return out


# ---------------------------------------------------------------------------
# Tool-call pairing repair
# ---------------------------------------------------------------------------
def _empty_content(value):
    """True when an assistant message carries no content at all.

    None / "" / [] all mean "no content": clients disagree on which empty
    shape they emit, and a batch split into adjacent assistant messages must
    merge for either shape (a missed [] was the original 11148 case).
    """
    if value is None:
        return True
    if isinstance(value, str):
        return value == ""
    if isinstance(value, list):
        return len(value) == 0
    return False


def _merge_reasoning_content(dst, src):
    """Fold src's reasoning_content into dst, newline-joined when both exist."""
    rc = src.get("reasoning_content")
    if not isinstance(rc, str) or not rc:
        return
    prev = dst.get("reasoning_content")
    if isinstance(prev, str) and prev:
        dst["reasoning_content"] = prev + "\n" + rc
    else:
        dst["reasoning_content"] = rc


def merge_adjacent_tool_calls(messages):
    """Merge back-to-back assistant tool_calls messages into one.

    Some OpenAI-compatible agent clients replay a parallel batch as several
    adjacent assistant messages, each carrying one tool_call. DeepSeek-family
    upstreams answer 400 / code 11148 (tool_call_sequence_broken) for that
    shape and retire the conversation, because every retry replays the same
    history and switching accounts cannot help. Merging the declarations
    restores the shape the upstream accepts.

    Conditions are strict, so no semantics are invented:
      - the messages must be adjacent;
      - the trailing message must have empty content (None/""/[]);
      - the leading message must already be an assistant with tool_calls.

    A second form folds a plain assistant's string content into a preceding
    tool_calls assistant that has no content of its own (the same split batch
    replayed in the other order). reasoning_content is preserved either way,
    because DeepSeek multi-turn thinking requires it back.
    """
    if not isinstance(messages, list) or len(messages) < 2:
        return messages, False
    out = []
    changed = False
    for m in messages:
        if not isinstance(m, dict):
            out.append(m)
            continue
        if m.get("role") == "assistant" and out:
            prev = out[-1] if isinstance(out[-1], dict) else None
            if prev is not None and prev.get("role") == "assistant":
                tcs = m.get("tool_calls")
                prev_calls = prev.get("tool_calls")
                # Form 1: this message declares tool calls and has no content.
                if (isinstance(tcs, list) and tcs
                        and _empty_content(m.get("content"))
                        and isinstance(prev_calls, list) and prev_calls):
                    prev["tool_calls"] = prev_calls + tcs
                    _merge_reasoning_content(prev, m)
                    changed = True
                    continue
                # Form 2: plain string content folds into a preceding
                # content-less tool_calls assistant.
                if ("tool_calls" not in m
                        and isinstance(m.get("content"), str) and m["content"]
                        and isinstance(prev_calls, list) and prev_calls
                        and _empty_content(prev.get("content"))):
                    prev["content"] = m["content"]
                    _merge_reasoning_content(prev, m)
                    changed = True
                    continue
        out.append(m)
    if not changed:
        return messages, False
    return out, True


def repack_tool_result_blocks(messages):
    """Keep a tool_calls batch and its results adjacent.

    The upstream requires the role:"tool" results to follow the assistant
    message that requested them with nothing in between. Codex's
    image_resize_notice, for one, arrives as a developer message right after a
    tool output; with parallel calls it lands between two results, the pairing
    reads as broken and the upstream rejects the whole request (code 11148),
    retiring the conversation. This only reorders: same results, same relative
    order, the intruders moved behind the batch.
    """
    if not isinstance(messages, list) or len(messages) < 3:
        return messages, False
    out = []
    changed = False
    i = 0
    while i < len(messages):
        m = messages[i]
        if not isinstance(m, dict) or m.get("role") != "assistant":
            out.append(m)
            i += 1
            continue
        calls = m.get("tool_calls")
        if not isinstance(calls, list) or not calls:
            out.append(m)
            i += 1
            continue
        want = set()
        for tc in calls:
            if isinstance(tc, dict):
                tid = tc.get("id")
                if isinstance(tid, str) and tid:
                    want.add(tid)
        out.append(m)
        i += 1
        results = []
        between = []
        saw_non_tool = False
        while i < len(messages):
            mm = messages[i]
            if not isinstance(mm, dict):
                break
            role = mm.get("role")
            if role == "tool":
                tid = mm.get("tool_call_id")
                if not (isinstance(tid, str) and tid in want):
                    break
                results.append(mm)
                if saw_non_tool:
                    changed = True
                i += 1
                continue
            if not results:
                break
            # A following assistant.tool_calls opens the next batch: it must go
            # back to the outer loop, or its own results never get repacked.
            if role == "assistant" and isinstance(mm.get("tool_calls"), list) \
                    and mm["tool_calls"]:
                break
            between.append(mm)
            saw_non_tool = True
            i += 1
        out.extend(results)
        out.extend(between)
    if not changed:
        return messages, False
    return out, True


def cleanup_orphan_tool_calls(messages):
    """Drop tool calls that have no result, and results that have no call.

    A failed tool call (bad arguments, timeout, unknown tool) leaves the client
    with an assistant tool_calls entry it can never answer: the result message
    is never written, yet the entry rides along with the history on every later
    turn and the upstream rejects each one (code 11148), so a single failed
    call can retire a whole conversation. Both sides are trimmed against the
    same set of ids, so no half-pairing can survive the repair.
    """
    if not isinstance(messages, list) or not messages:
        return messages, False
    call_ids = set()
    result_ids = set()
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role == "tool":
            tid = m.get("tool_call_id")
            if isinstance(tid, str) and tid:
                result_ids.add(tid)
        elif role == "assistant":
            calls = m.get("tool_calls")
            if isinstance(calls, list):
                for tc in calls:
                    if isinstance(tc, dict):
                        tid = tc.get("id")
                        if isinstance(tid, str) and tid:
                            call_ids.add(tid)
    if not call_ids and not result_ids:
        return messages, False
    keep = call_ids & result_ids
    changed = False
    for m in messages:
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        calls = m.get("tool_calls")
        if not isinstance(calls, list) or not calls:
            continue
        kept = [tc for tc in calls
                if isinstance(tc, dict) and isinstance(tc.get("id"), str)
                and tc["id"] in keep]
        if len(kept) == len(calls):
            continue
        changed = True
        if kept:
            m["tool_calls"] = kept
        else:
            m.pop("tool_calls", None)
    out = []
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "tool":
            tid = m.get("tool_call_id")
            if not (isinstance(tid, str) and tid in keep):
                changed = True
                continue
        out.append(m)
    if not changed:
        return messages, False
    return out, True


# ---------------------------------------------------------------------------
# DeepSeek Multi-turn Consistency: reasoning_content backfill
# ---------------------------------------------------------------------------
# Upstream (code 11155 "the reasoning content from the previous turn must be
# passed back in thinking mode") requires every assistant message to carry a
# `reasoning_content` string while thinking is on. Two halves gate the fix,
# mirroring the official client's ReasoningContentBackfillRule:
#   - thinkingEnabled: deepseek + thinking enabled -> always backfill, even
#     when a third-party client dropped reasoning entirely (this was the bug:
#     only the hasTrace half existed, so zero-trace histories were forwarded
#     untouched and rejected).
#   - hasTrace: any existing reasoning trace -> backfill regardless of the
#     thinking flag.
# Upstream also validates len(reasoning) > 0, so an empty placeholder is not
# enough on its own: `reasoning` is mirrored with a non-empty value.
def backfill_reasoning_content(messages, model, thinking_enabled=None):
    if not model or not str(model).lower().startswith("deepseek"):
        return messages
    if thinking_enabled is None:
        thinking_enabled = False
    has_trace = False
    for m in messages:
        if not isinstance(m, dict):
            continue
        reasoning = m.get("reasoning")
        if isinstance(reasoning, str) and reasoning:
            has_trace = True
            break
        if "reasoning_content" in m:
            has_trace = True
            break
    if not thinking_enabled and not has_trace:
        return messages
    out = []
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "assistant":
            item = dict(m)
            rc = item.get("reasoning_content")
            if not isinstance(rc, str):
                # Non-string (null/number/absent) counts as missing, matching
                # the official `typeof !== "string"` check.
                legacy = item.get("reasoning")
                rc = legacy if isinstance(legacy, str) else ""
                item["reasoning_content"] = rc
            # Mirror onto `reasoning` with a non-empty value: upstream rejects
            # an empty/absent reasoning, while a whitespace placeholder passes
            # its length check and carries no model-visible semantics.
            existing = item.get("reasoning")
            if not (isinstance(existing, str) and existing):
                item["reasoning"] = rc if rc else " "
            out.append(item)
        else:
            out.append(m)
    return out
# ---------------------------------------------------------------------------
# Tool & Tool Choice Normalization (avoids code 11101 on object tool_choice)
# ---------------------------------------------------------------------------
def normalize_tool_choice(obj):
    if "tool_choice" not in obj:
        return
    tc = obj["tool_choice"]
    if isinstance(tc, str):
        val = tc.strip().lower()
        if val == "none":
            # 这里曾经把 tools/functions 一起删掉，那正是 Agent 死循环的成因：
            # 工具声明没了，模型拿不到函数签名、又没有结构化工具通道，却仍被要求
            # 完成任务，于是把调用降级成 DSML / 伪 JSON 文本塞进 content
            # （tool_calls 为空、finish_reason=stop）。客户端解析不到调用只能再
            # 追问一轮，模型又重复一遍 "I'll do it"，上下文每轮 +2 条消息、token
            # 线性膨胀，直到撑爆窗口或用户手动断开。
            #
            # tool_choice="none" 的语义是「本轮不许调用工具」，这层意思由
            # tool_choice 字段本身表达就够了，不需要抹掉能力声明。
            # 上游把 tool_choice 声明为 string（发对象会 11101），所以保持字符串
            # 原样透传，同时保留 tools。
            #
            # 取舍：实测本上游并不真正遵守 tool_choice="none"（保留 tools 后它
            # 仍返回 tool_calls）。但对比两条路 —— 删 tools 会让模型输出不可解析
            # 的文本、Agent 原地空转；留 tools 则走正常 tool_calls 通道，客户端能
            # 正常执行与回填 —— 后者明显更好。确实需要禁止调用时，客户端不传
            # tools 即可。
            obj["tool_choice"] = "none"
        return
    if isinstance(tc, dict):
        typ = (tc.get("type") or "").strip().lower()
        if typ == "none":
            # 同上：保留 tools 声明。上游只认字符串，对象形式必须降级成
            # "none"，否则 11101。
            obj["tool_choice"] = "none"
        elif typ in ("auto", "required"):
            obj["tool_choice"] = typ
        elif typ == "function":
            name = (tc.get("function") or {}).get("name") or tc.get("name") or ""
            obj["tool_choice"] = name.strip() or "auto"
        else:
            obj.pop("tool_choice", None)
    else:
        obj.pop("tool_choice", None)
def normalize_tools(obj):
    tools = obj.get("tools")
    if not tools or not isinstance(tools, list):
        return
    norm = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        # Wrap top-level name tool definition into Chat Completions function schema
        if "name" in t and "function" not in t and t.get("type") == "function":
            fn = {
                "name": t.get("name") or "",
                "description": t.get("description") or "",
                "parameters": t.get("parameters") or {},
            }
            if "strict" in t:
                fn["strict"] = t["strict"]
            norm.append({"type": "function", "function": fn})
        else:
            norm.append(t)
    obj["tools"] = norm
# ---------------------------------------------------------------------------
# Stop Sequence Normalization (avoids code 11101 on a string stop)
# ---------------------------------------------------------------------------
def normalize_stop(obj):
    # OpenAI 把 stop 声明成 string | array，客户端传单个字符串完全合法；本上游的
    # Go 端却把该字段定死为 []string，收到字符串直接 400：
    #   Unmarshal chat params failed with error: json: cannot unmarshal string
    #   into Go struct field Request.stop of type []string   (code 11101)
    # 实测（deepseek-v4.1-flash，同一条 prompt，同一个上游账号）：
    #   "stop": "END"     -> 400 / code 11101
    #   "stop": ["END"]   -> 200
    # 归一化成数组后语义完全等价：OpenAI 里单字符串就是单元素数组，模型侧看到的
    # 停止序列一模一样。空字符串 / 空数组 / null / 非法类型一律删字段——它们的实际
    # 含义都是「没有停止序列」，而空值本身在上游同样会被判参数不合法。
    if "stop" not in obj:
        return
    val = obj["stop"]
    if isinstance(val, str):
        val = [val] if val else []
    elif isinstance(val, (list, tuple)):
        val = [s for s in val if isinstance(s, str) and s]
    else:
        val = []
    if val:
        obj["stop"] = val
    else:
        obj.pop("stop", None)
def translate_max_completion_tokens(obj):
    alias = obj.pop("max_completion_tokens", None)
    if alias is None:
        return
    if "max_tokens" in obj:
        return
    try:
        val = int(alias)
        if val > 0:
            obj["max_tokens"] = val
    except (TypeError, ValueError):
        pass
# ---------------------------------------------------------------------------
# 模型封锁表
#
# 背景：客户端除了使用者的对话，还会自己发背景请求（记忆整理、自动复核等）。
# 这些请求不经过模型选单，而是直接使用目录上的模型 ID，因此可能在使用者
# 没有实际操作时，用付费模型消耗额度。
#
# 对策（选用）：把要拒绝的模型填进 ALLOWED_MODELS / BANNED_SUBSTRING /
#               EXTRA_BANNED；命中的请求在本机直接回 400，完全不碰上游。
#               预设全部为空 = 不封锁任何模型，行为与原版相同。
#
# 调整方式：
#   要放行某个模型 -> 加进 ALLOWED_MODELS 或 ALLOWED_PREFIXES
#   要连非 gpt 的模型一起挡 -> 加进 EXTRA_BANNED
# ---------------------------------------------------------------------------

# 允许放行的模型（你要用的）
ALLOWED_MODELS = {
    # 预设不封锁任何模型；填入模型 id 即可只放行这些
}

# 允许前缀：涵盖 -high / -preview / [1M] 等变体
ALLOWED_PREFIXES = ()

# 封锁字串：模型名里含这个就拒绝
BANNED_SUBSTRING = ""

# 额外封锁的内部模型（不在 gpt- 前缀内，但也会烧点）
EXTRA_BANNED = set()


def is_model_banned(model):
    """True 表示这个模型名不该被送去上游。

    规则：ALLOWED_MODELS / ALLOWED_PREFIXES 命中就放行；其余只要命中
    BANNED_SUBSTRING 或 EXTRA_BANNED 就拒绝，没命中则照常送往上游。
    三个设定预设都是空的，所以预设不封锁任何模型。
    """
    if not model:
        return False
    m = str(model).strip().lower()
    # 白名单优先（含 -high / -preview / [1M] 这类变体）
    if m in ALLOWED_MODELS:
        return False
    if any(m.startswith(a) for a in ALLOWED_PREFIXES):
        return False
    # 命中封锁字串就拒绝
    if BANNED_SUBSTRING and BANNED_SUBSTRING in m:
        return True
    # 其他已知会烧点的内部模型
    if m in EXTRA_BANNED:
        return True
    return False


# ---------------------------------------------------------------------------
# 背景请求拦截
#
# Codex App 除了使用者的对话，还会自己发背景请求（记忆整理、环境建议、自动复核…）。
# 这些请求不经过模型选单，所以单靠模型白名单挡不住 —— 它们可能直接用目录上
# 的付费模型（例如 gpt-6-astra 这类），在使用者没有实际操作时照样消耗额度。
#
# Codex 会在 client_metadata 里带 x-codex-turn-metadata，内容像：
#   {"request_kind":"memory","thread_source":"memory_consolidation",
#    "turn_trigger":"memory_consolidation"}
# 这里就靠这个标记判断：命中背景关键字 -> 本地直接拒绝，不碰上游、不扣点。
# ---------------------------------------------------------------------------

# 要不要拦截背景请求（False = 全部放行，维持原行为）
BLOCK_BACKGROUND_REQUESTS = False

# 命中任一关键字就视为背景请求（不分大小写、子字串比对）
BACKGROUND_TRIGGER_KEYWORDS = (
    "memory_consolidation",
    "memory-write",
    "memory_write",
    "memorywriting",
    "ambient",
    "suggestion",
    "auto_review",
    "auto-review",
    "autoreview",
    "title",
    "compaction",
    "compact",
    "summariz",
)


# Thread sources that belong to a job the client started on its own. A
# compaction request carries one of these when the client triggered it, and the
# user's own thread when the operator pressed "compact the context" - so the
# source has to be read before the keyword list, where "compaction" matches
# both and would otherwise refuse the button.
BACKGROUND_THREAD_SOURCES = (
    "memory_consolidation",
    "memory",
    "ambient",
    "suggestion",
    "auto_review",
    "autoreview",
    "title",
)


def turn_metadata_fields(payload):
    """Flatten the request_kind / turn_trigger / thread_source hints we get.

    Codex sends them either as plain client_metadata keys or as a JSON string
    under a metadata key of its own, so both shapes are read. Returns {} when
    the payload carries none of them.
    """
    if not isinstance(payload, dict):
        return {}
    meta = payload.get("client_metadata")
    if not isinstance(meta, dict):
        return {}

    # 收集所有可能的来源/触发栏位
    fields = {}
    for key, value in meta.items():
        if isinstance(value, str) and value.strip().startswith("{"):
            try:
                inner = json.loads(value)
            except Exception:
                inner = None
            if isinstance(inner, dict):
                for k in ("request_kind", "turn_trigger", "thread_source", "kind", "trigger", "source"):
                    if k in inner:
                        fields[k] = inner[k]
        if key in ("request_kind", "turn_trigger", "thread_source"):
            fields[key] = value
    return fields


def is_compaction_request(payload):
    """True for the operator's own "compact the context" request.

    request_kind=compaction carries the same word as the background keyword, but
    this request is one the user asked for: the client sends it on the user's
    thread, while a compaction the client started by itself names the job that
    started it. Refusing this one takes the context-compaction button away.
    """
    fields = turn_metadata_fields(payload)
    kind = str(fields.get("request_kind") or "").strip().lower()
    if "compact" not in kind:
        return False
    source = str(fields.get("thread_source") or "").strip().lower()
    return source not in BACKGROUND_THREAD_SOURCES


def background_request_reason(payload):
    """若这是 Codex 自己发的背景请求，回传说明字串；否则回传 ""。

    只看 client_metadata，不碰讯息内容。
    """
    fields = turn_metadata_fields(payload)
    if not fields:
        return ""

    if is_compaction_request(payload):
        return ""

    blob = " ".join(str(v) for v in fields.values()).lower()
    for kw in BACKGROUND_TRIGGER_KEYWORDS:
        if kw in blob:
            return "%s=%s" % (
                ",".join(sorted(fields.keys())),
                ",".join(str(fields[k]) for k in sorted(fields)),
            )
    return ""


def background_request_message(reason):
    return ("這是客戶端自己發的背景請求（%s），本機代理已擋下，"
            "避免在沒有實際操作時消耗上游額度。"
            "要放行請把 ca_proxy.py 的 BLOCK_BACKGROUND_REQUESTS 改成 False。"
            % reason)


def banned_model_message(model):
    allowed = "、".join(sorted(ALLOWED_MODELS))
    return ("模型 %s 已被本機代理封鎖（依 ALLOWED_MODELS / BANNED_SUBSTRING 設定）。"
            "目前允許：%s。要放行請編輯 ca_proxy.py 的 ALLOWED_MODELS。"
            % (model, allowed))


def key_model_message(entry, model):
    """Explain a per-key model restriction the same way the global ban does."""
    name = (entry or {}).get("name") or "未命名"
    allowed = "、".join((entry or {}).get("models") or []) or "-"
    asked = str(model or "").strip() or "(未指定模型)"
    return ("API Key「%s」的模型限制不允許 %s。該 Key 目前允許：%s。"
            "請在看板「設置」頁修改這個 Key 的模型限制，或改用允許該模型的 Key。"
            % (name, asked, allowed))


# Process-memory degradation window: content-blocked passthrough/append
# traffic switches to the minimal neutral prompt until the next 00:00 CST
# (panel degrade.go). Restarts clear it, which is fine - the next rejection
# re-triggers it.
PROMPT_DEGRADE = ca_prompt.DegradeGate()


def prompt_mode_config():
    """Prompt mode settings, fail-open to passthrough on any read error."""
    try:
        cfg = ca_settings.prompt_config(ACCOUNTS_DIR)
    except Exception:
        cfg = None
    if not isinstance(cfg, dict):
        cfg = {"mode": "passthrough", "file": ""}
    return cfg


def apply_prompt_mode(messages):
    """Apply the configured prompt mode to one request's messages.

    passthrough is the legacy behaviour (client system prompts ride through);
    custom/append are opt-in. While the degrade window is active, passthrough
    and append switch to the minimal neutral prompt; custom never degrades.
    An unreadable prompt file fails open to passthrough rather than blocking.
    """
    cfg = prompt_mode_config()
    mode = cfg.get("mode") or "passthrough"
    degraded = PROMPT_DEGRADE.active()
    if mode in ("custom", "append"):
        try:
            text = ca_prompt.load_prompt(mode, cfg.get("file"))
        except Exception:
            text = ""
        if text:
            return ca_prompt.apply_mode(messages, mode, text, degraded=degraded)
        return messages
    if degraded:
        return ca_prompt.apply_mode(messages, mode, "", degraded=True)
    return messages


def repair_messages_for_upstream(messages, model=""):
    """送出前把消息历史修成上游能吃的形状（**码道路径也走这里**）。

    2026-10-23：这一整套修复（`merge_adjacent_tool_calls` /
    `repack_tool_result_blocks` / `cleanup_orphan_tool_calls` /
    `backfill_reasoning_content`）**只挂在 `build_upstream_body()` 上，而它
    在码道路径上没有调用点** —— 五条码道入口各自只做了一句
    ``ca_protocol.normalize_roles``。于是：

      · 孤立的 tool_call / tool_result（客户端历史里断掉的一轮）直接送给
        上游 → 400 / 11148 tool_call_sequence_broken，整条对话从此报废；
      · 并行批次被拆成相邻多条 assistant → 同样 11148；
      · deepseek 思考模式下缺 reasoning_content → 上游拒收。

    对应的测试套件当时只调用这些函数本身（测的是死代码），所以全绿也保护
    不了生产路径。现在它们有了唯一的入口函数，五条码道入口都从这儿过。

    顺序有讲究：先合并被拆开的声明，再重排 tool_result，最后清孤立的成对项
    —— 反过来的话，repack 看到的还是残缺批次。
    """
    out = list(messages or [])
    out, _merged = merge_adjacent_tool_calls(out)
    out, _repacked = repack_tool_result_blocks(out)
    out, _cleaned = cleanup_orphan_tool_calls(out)
    if model:
        out = backfill_reasoning_content(out, model,
                                        thinking_enabled=_thinking_enabled(model,
                                                                          {}))
    return out


def _thinking_enabled(model, payload):
    """这条请求对上游要不要「思考」。两个入口（build_upstream_body 与码道路径）
    必须同一口径，所以抽出来。"""
    model = str(model or "")
    thinking = (payload or {}).get("thinking")
    thinking_type = ""
    if isinstance(thinking, dict):
        thinking_type = str(thinking.get("type") or "").strip().lower()
    effort = ((payload or {}).get("reasoning_effort")
              or (payload or {}).get("reasoningEffort"))
    if not model.lower().startswith("deepseek"):
        return False
    if thinking_type == "enabled":
        return True
    return thinking_type != "disabled" and str(effort or "").strip().lower() != "none"


def build_upstream_body(payload):
    model = payload.get("model") or ""
    # Resolve the effective thinking state before the backfill below: while
    # thinking is on, the upstream requires reasoning_content on every
    # assistant message, whether or not the client kept a reasoning trace.
    thinking_enabled = _thinking_enabled(model, payload)
    messages = ca_protocol.normalize_roles(payload.get("messages") or [])
    # Prompt mode runs before sanitize/backfill so the gateway prompt is the
    # one the upstream sees, with the client's fingerprint-y system text gone.
    messages = apply_prompt_mode(messages)
    messages = sanitize_messages(messages)
    messages = backfill_reasoning_content(
        messages, model, thinking_enabled=thinking_enabled
    )
    if not messages or (messages[0].get("role") != "system"):
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
    body = dict(payload)
    # Private request markers ride along on the chat body for the Responses
    # path (the namespace map, the local-web-tools flag). They are not part of
    # the upstream protocol, so drop them here rather than trusting the
    # upstream to ignore unknown keys.
    for _marker in [k for k in body if str(k).startswith("_")]:
        body.pop(_marker, None)
    # dict(payload) 会把原始模型名一起带过去，所以别名要在这里覆盖回去
    body["model"] = model
    body["messages"] = messages
    # Repair tool-call pairing before the body leaves: a call whose result never
    # came back, results split from their batch by an interleaved message, or a
    # parallel batch split into adjacent assistant messages makes the upstream
    # reject every later turn of that conversation. Order matters: merge the
    # split declarations first, so repack sees one complete batch.
    repaired, _merged = merge_adjacent_tool_calls(body["messages"])
    repaired, _repacked = repack_tool_result_blocks(repaired)
    repaired, _cleaned = cleanup_orphan_tool_calls(repaired)
    body["messages"] = repaired
    translate_max_completion_tokens(body)
    # Upstream GPT-family models enforce a minimum max_output_tokens >= 16;
    # smaller values (e.g. max_tokens=1 from probes) fail with 400 integer_below_min_value (#364, #252).
    if "max_tokens" in body and str(model).lower().startswith("gpt-"):
        try:
            mt = int(body["max_tokens"])
            if mt < 16:
                log("clamping %s max_tokens from %d to 16 for upstream requirements" % (model, mt))
                body["max_tokens"] = 16
        except (TypeError, ValueError):
            pass
    normalize_tool_choice(body)
    normalize_tools(body)
    normalize_stop(body)
    if "max_tokens" not in body:
        default_max = model_default_max_output_tokens(model)
        if default_max:
            body["max_tokens"] = default_max
    # Thinking injection for DeepSeek models.
    #
    # thinking.type=enabled on its own does not switch the reasoning trace on:
    # the upstream still answers without one unless an effort level rides along.
    # Measured against the live upstream on deepseek-v4.1-flash, same prompt:
    #   enabled + no effort   -> reasoning_tokens 0,  reasoning_content len 0
    #   reasoning_effort=high -> reasoning_tokens 37, reasoning_content len 117
    # The client's own choice always wins; an effort level is only filled in
    # when it left the field out, and never for a request that opted out.
    if str(model).lower().startswith("deepseek"):
        thinking = body.get("thinking")
        opted_out = isinstance(thinking, dict) and \
            str(thinking.get("type") or "").strip().lower() == "disabled"
        effort = body.get("reasoning_effort") or body.get("reasoningEffort")
        if not opted_out and str(effort or "").strip().lower() != "none":
            if "thinking" not in body:
                body["thinking"] = {"type": "enabled"}
            if not effort:
                body["reasoning_effort"] = model_default_effort(model) or "high"
    body["stream"] = True
    if "stream_options" not in body:
        body["stream_options"] = {"include_usage": True}
    return body


def model_catalog_meta(model):
    """The catalog metadata dict for a model, or {}.

    Read from the same merged catalog that /v1/models advertises.
    Deliberately side-effect free: it reads the already-populated model cache
    and the shipped static tables only. Calling fetch_models() here would let a
    cold cache trigger an upstream discovery round-trip from inside request
    handling, turning one chat call into a network fetch.
    """
    if not model:
        return {}
    try:
        realm = detect_model_realm(model) or CURRENT_REALM
        entries = (_models_cache.get(realm) or {}).get("data")
        if not entries:
            table = getattr(ca_catalog, "STATIC_CN_MODELS", None) or ca_catalog.STATIC_MODELS
            entries = [(m.get("id"), m) for m in table if isinstance(m, dict)]
        m_lower = str(model).strip().lower()
        for mid, meta in entries:
            if str(mid).strip().lower() == m_lower:
                return meta or {}
    except Exception as exc:
        log("catalog meta lookup failed for '%s': %s" % (model, exc))
    return {}


def model_reasoning_meta(model):
    """The catalog's reasoning block for a model, or {}."""
    return model_catalog_meta(model).get("reasoning") or {}


def model_default_max_output_tokens(model):
    """The max output tokens the catalog declares for a model, or None."""
    val = model_catalog_meta(model).get("maxOutputTokens")
    if val is not None:
        try:
            val = int(val)
            if val > 0:
                return val
        except (TypeError, ValueError):
            pass
    return None


def model_default_effort(model):
    """The effort the catalog applies when the client asks for none, or None."""
    effort = model_reasoning_meta(model).get("defaultEffort")
    return effort.strip() if isinstance(effort, str) and effort.strip() else None


def gateway_hint(status, message):
    """A gateway-side note that sits beside the raw upstream message.

    The hint never replaces the upstream wording (clients keep parsing the
    same envelope); it only explains what the gateway could classify, so a
    user staring at "400 Bad Request" learns whether the fix is a smaller
    context, a different model, a re-login or simply waiting. An empty string
    means "nothing to add" - no hint is invented for unknown failures.

    Covers the shapes the hub can classify from the upstream body/status:
    11133 model_param_invalid, 11135 invalid_image_data, rate limits, content
    review, exhausted credits, dead sessions, missing models, prompt-length
    rejections, WAF blocks and the local no-usable-account case.
    """
    text = str(message or "")
    lower = text.lower()
    if status == 413 and "payload too large" in lower:
        return ("single request body exceeds the gateway cap "
                "(WB_MAX_PAYLOAD_BYTES, default 16MB); raise it and restart codearts-hub")
    if status == 503 and "concurrent chat limit" in lower:
        return "gateway is busy at its concurrency limit; retry shortly"
    if ("11133" in lower or "model_param_invalid" in lower
            or "invalid request parameters" in lower):
        return ("request parameters were rejected by the model provider; "
                "check message format and model capabilities")
    if ("11135" in lower or "invalid_image_data" in lower
            or "replace the image" in lower):
        return ("image data rejected by upstream; use a real/valid image, "
                "may need a new conversation")
    if "no usable account" in lower or "no healthy account" in lower:
        return "no healthy account available in pool; check /status or retry later"
    if "本机网络不可用" in text or "local network unavailable" in lower:
        return ("this machine has no working network (DNS/route failed); accounts were "
                "not penalised - check the host's network or proxy")
    if ("context length" in lower or "context_length" in lower
            or "prompt too long" in lower or "too many tokens" in lower
            or "maximum context" in lower):
        return ("request context exceeds the model's limit; reduce "
                "history/message size")
    if status == 429 or "rate limit" in lower or "frequency limit" in lower:
        return "rate limited by upstream; retry after reset"
    if status == 402 or ("insufficient" in lower and "credit" in lower):
        return ("account credits exhausted at upstream; waiting for daily "
                "check-in to restore")
    if "session" in lower and ("not found" in lower or "expired" in lower):
        return ("account session expired at upstream; the account is disabled "
                "until re-login")
    if "content" in lower and ("reject" in lower or "policy" in lower):
        return ("request content was rejected by content policy; adjust the "
                "prompt and retry")
    if ("no such model" in lower or "model not found" in lower
            or "unsupported model" in lower):
        return ("upstream has no such model on this backend; switch model or "
                "retry on another account")
    if status == 403 and "waf" in lower:
        return "upstream WAF blocked the gateway; retry after the block window"
    return ""


#: 出口级退避在单次请求里最多睡这么久（见 ca_egress）：退避阶梯可以到十几秒，
#: 但把一个客户端请求按住十几秒是不可接受的，所以只睡这个上限；共享计数器仍然
#: 让并发请求一起变慢（这才是「一次短暂的全局退避」）。
EGRESS_SLEEP_MAX = 5.0


def upstream_timeouts():
    """(header, idle) seconds for the chat upstream socket.

    header covers connect/TLS/first byte; idle bounds each mid-stream
    read, so active data keeps the connection alive while a silent
    stream fails out and releases its in-flight lease. There is no
    total-duration cap, matching the panel project's semantics.
    """
    try:
        cfg = ca_settings.upstream_config(ACCOUNTS_DIR)
    except Exception:
        cfg = None
    header = 120.0
    idle = 300.0
    if isinstance(cfg, dict):
        try:
            header = float(cfg.get("header_timeout_seconds") or header)
        except (TypeError, ValueError):
            pass
        try:
            idle = float(cfg.get("idle_timeout_seconds") or idle)
        except (TypeError, ValueError):
            pass
    return max(1.0, header), max(1.0, idle)
def extract_session_key(headers, payload):
    key = (
        headers.get("X-Conversation-Id") or
        headers.get("Conversation-Id") or
        headers.get("X-Session-Id") or
        headers.get("Session-Id") or
        payload.get("conversation_id") or
        payload.get("session_id") or
        (payload.get("metadata") or {}).get("conversation_id")
    )
    if key:
        return str(key).strip()
    return None
# ---------------------------------------------------------------------------
# Responses API (/v1/responses) <-> Chat Completions translation
# ---------------------------------------------------------------------------
#
# Kelivo and other clients can speak OpenAI's newer Responses API. The upstream
# gateway only speaks Chat Completions, so those requests are translated down,
# and the reply is translated back up into Responses objects / SSE events.
def local_ip_addresses():
    """Every non-loopback IPv4 address this machine answers on."""
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found and not ip.startswith("127."):
                found.append(ip)
    except Exception:
        pass
    if not found:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))
            found.append(probe.getsockname()[0])
            probe.close()
        except Exception:
            pass
    return found
def _flatten_content(content):
    """Flatten Responses-style content into text, or OpenAI vision parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)
    texts, parts = [], []
    for piece in content:
        if isinstance(piece, str):
            texts.append(piece)
            parts.append({"type": "text", "text": piece})
            continue
        if not isinstance(piece, dict):
            continue
        ptype = piece.get("type") or ""
        if ptype in ("input_text", "output_text", "text", "summary_text"):
            t = piece.get("text") or ""
            texts.append(t)
            parts.append({"type": "text", "text": t})
        elif ptype in ("input_image", "image_url", "image") or "image_url" in piece:
            url = piece.get("image_url") or piece.get("url")
            if isinstance(url, dict):
                url = url.get("url")
            if not url and piece.get("data"):
                mime = piece.get("mimeType") or piece.get("mime_type") or "image/png"
                url = f"data:{mime};base64," + piece["data"]
            if url:
                parts.append({"type": "image_url", "image_url": {"url": url}})
    if any(p.get("type") == "image_url" for p in parts):
        return parts          # multimodal: keep structured parts
    return chr(10).join(t for t in texts if t)


# ---------------------------------------------------------------------------
# Responses API "custom" (freeform) tools
#
# Some clients - most notably Codex 0.15x - declare their file-editing tool as a
# *custom* (freeform) tool rather than a JSON-schema function:
#
#     {"type": "custom", "name": "apply_patch", "format": {...grammar...}}
#
# and expect the model to answer with a custom_tool_call item carrying the raw
# payload in "input", then feed the result back as custom_tool_call_output.
#
# The upstream chat endpoint has no notion of custom tools, so we downgrade them
# to ordinary function tools with a single "input" string parameter on the way
# out, and re-inflate them to custom_tool_call on the way back. Without this the
# tool is silently ignored: the model emits the payload as ordinary prose and the
# client never sees a tool call (measured: 52 text deltas, 0 tool items).
# ---------------------------------------------------------------------------

CUSTOM_TOOL_HINT = (
    "This is a freeform tool. Put the COMPLETE raw payload into the single "
    "'input' string parameter, verbatim. Do not wrap it in JSON, do not wrap "
    "it in markdown code fences, do not add commentary."
)


# ---------------------------------------------------------------------------
# namespace 工具：只做「展开 + 还原」，没有「直接拒绝」这条分支
#
# 早先试过回一个格式明确的 400 逼 app 退回 flat function 清单（Command Code
# proxy.mjs 的 CC_REJECT_NAMESPACE_TOOLS 实验里记过这招，Agent Router 也是靠
# 拒绝这类请求才正常的）。现在正解是网关自己摊平：出程把 namespace 里的函数
# 展开成普通 function 工具，回程再按 (name, namespace) 还原成客户端的执行器。
# 那条 400 分支和它的开关一起删了——留着只会让人以为打开它还有用。
# ---------------------------------------------------------------------------


def _is_custom_tool(tool):
    return isinstance(tool, dict) and str(tool.get("type") or "").lower() == "custom"


def custom_tool_names(tools, _depth=0):
    """Names of tools declared as freeform/custom in a Responses request.

    递归进 namespace：新版 Codex Desktop 把自由格式工具嵌在 functions 命名
    空间里（exec 的 type 就是 "custom"）。漏掉它的后果不是「少一个名字」，
    而是回程被判成 function_call，客户端按 (name, namespace, kind) 三元组匹
    配不到执行器，调用不执行、不返回，模型只能无限重试。namespace 只是客户
    端给工具分组的方式，不是停止查找的理由。
    """
    names = set()
    if _depth > NAMESPACE_MAX_DEPTH:
        return names
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        if _is_custom_tool(t) and t.get("name"):
            names.add(str(t["name"]))
        elif str(t.get("type") or "").lower() == "namespace":
            subs = t.get("tools")
            if not isinstance(subs, list):
                subs = t.get("children")
            if not isinstance(subs, list):
                subs = t.get("functions")
            names |= custom_tool_names(subs, _depth + 1)
    return names


def _downgrade_custom_tool(tool):
    """Rewrite a Responses custom tool into a Chat function tool."""
    desc = tool.get("description") or ""
    fmt = tool.get("format") or {}
    extra = ""
    if isinstance(fmt, dict) and fmt.get("definition"):
        extra = chr(10) + chr(10) + "Grammar:" + chr(10) + str(fmt["definition"])
    return {
        "type": "function",
        "name": tool.get("name") or "",
        "description": (desc + chr(10) + chr(10) + CUSTOM_TOOL_HINT + extra).strip(),
        "parameters": {
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": "Complete raw payload for this tool, verbatim.",
                }
            },
            "required": ["input"],
        },
    }


# ---------------------------------------------------------------------------
# namespace 工具：展开 + 还原
#
# 新版 Codex App 把 MCP／外挂工具用 namespace 形式送出：
#   {"type":"namespace","name":"codex_app","tools":[{name:"list_threads",...}]}
#
# 上游 Chat Completions 只认 flat function，看不懂 namespace。
# 但 App 回程是用 (name, namespace) 两个栏位找执行器 ——
# 只给 flat name，App 一律回 "unsupported call"（实测 js / list_threads 全灭）。
#
# 三件事：
#   1. Expand   送上游前把 namespace 展开成 flat function，记住 name -> namespace
#   2. Normalise 模型回传的 name 可能是 js / ns__js / ns::js，都要能解析
#   3. Restore   回程的 function_call / custom_tool_call 补上 namespace 栏位
#
# 参考：某开源 CodeBuddy/WorkBuddy 反向代理项目的 tool-namespaces 说明
# ---------------------------------------------------------------------------

NAMESPACE_MAX_DEPTH = 4


def expand_namespace_tools(tools, _depth=0):
    """把 namespace 展开成 flat function 清单，其余工具原样保留。

      * 子工具可能在 tools / children / functions 任一栏位
      * namespace 子工具常常没有 type 栏位，展开时补成上游认得的 flat function
      * custom / web_search 等非 function 项目原样留下，交给既有管线处理
      * 同名工具：**同一个 namespace 内**去重；**不同 namespace 之间**不许互相
        顶掉（见下）
      * 回传 (flat_tools, name_to_namespace)

    **跨 namespace 重名不再丢弃**（2026-10-23）。以前用一个全局 ``seen`` 集合
    按裸名去重：Codex 同时接两个 MCP server、各自都有一个 ``search`` 时，第二个
    server 的 ``search`` 直接消失 —— 模型完全看不到它，而客户端那边它明明是
    可用的。现在撞名时把后来的那个**加上 namespace 前缀**送出（``server_b__search``），
    并且这个平名已经登记在 mapping 里，回程 ``resolve_namespaced_name`` 会把它
    解析回 ``(search, server_b)``。顶层的裸名仍按既有优先级赢（同名顶层工具优先），
    这是 test_namespace_tools 钉住的既有语义。
    """
    flat = []
    mapping = {}
    seen = set()
    #: 每个裸名属于哪个 namespace（顶层工具记为 ""）。
    owner = {}
    max_depth = max(0, int(_depth) + NAMESPACE_MAX_DEPTH)

    def _emit(flat_name, fn, ns_name):
        flat_fn = {
            "type": "function",
            "name": flat_name,
            "description": fn.get("description") or "",
            "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
        }
        if "strict" in fn:
            flat_fn["strict"] = fn["strict"]
        flat.append(flat_fn)
        mapping[flat_name] = ns_name
        seen.add(flat_name)

    def collect(entry, depth, ns_name):
        if not isinstance(entry, dict) or depth > max_depth:
            return
        etype = str(entry.get("type") or "").lower()
        if etype == "namespace":
            subs = entry.get("tools")
            if not isinstance(subs, list):
                subs = entry.get("children")
            if not isinstance(subs, list):
                subs = entry.get("functions")
            if not isinstance(subs, list):
                subs = []
            child_ns = str(entry.get("name") or ns_name or "")
            for sub in subs:
                collect(sub, depth + 1, child_ns)
            return
        if ns_name and etype in ("", "function"):
            fn = entry.get("function") if isinstance(entry.get("function"), dict) else None
            if fn is None:
                fn = {
                    "name": entry.get("name"),
                    "description": entry.get("description") or "",
                    "parameters": entry.get("parameters") or entry.get("input_schema")
                                  or {"type": "object", "properties": {}},
                }
            name = str(fn.get("name") or "").strip()
            if not name:
                return
            if name not in seen:
                owner[name] = ns_name
                _emit(name, fn, ns_name)
                return
            if owner.get(name) == ns_name:
                return                      # 同一个 server 内的真重复
            # 撞名：换成 ns__name。若那个平名也被占了（两个 server 同名，
            # 且已经有别的东西用了这个前缀名），才真的放弃。
            qualified = "%s%s%s" % (ns_name, ca_protocol.NS_SEP, name)
            if qualified in seen:
                return
            owner.setdefault(qualified, ns_name)
            _emit(qualified, fn, ns_name)
            return
        fn = entry.get("function") if isinstance(entry.get("function"), dict) else {}
        name = str(entry.get("name") or fn.get("name") or "").strip()
        if name:
            if name in seen:
                return
            seen.add(name)
            owner.setdefault(name, "")
            if ns_name:
                mapping[name] = ns_name
        flat.append(entry)

    for entry in tools or []:
        collect(entry, 0, "")
    return flat, mapping


def additional_tools_from_input(payload):
    """从 input 数组里收集 additional_tools 条目的 tools。

    新版 Codex Desktop 0.162+ 把工具放在 input 内的
    {"type": "additional_tools", "tools": [...]} 条目里，顶层 tools 是空的。
    出站（responses_to_chat）与回程（custom_tool_names / request_meta.tools）
    的取值都必须走这里，否则两边看到的是不同的工具清单。
    """
    collected = []
    for item in payload.get("input") or []:
        if isinstance(item, dict) and item.get("type") == "additional_tools":
            sub_tools = item.get("tools")
            if isinstance(sub_tools, list):
                collected.extend(sub_tools)
    return collected


def _tools_for_chat(tools):
    """Downgrade custom tools; leave everything else untouched.

    注意：**这两个上游要的工具形状不一样**，别在这里做统一归一。
    WorkBuddy 收的是 Responses 那种扁平声明（{"type":"function","name":…}），
    原样透传就对了，`_test_custom_tools.py` 也按这个契约锁着。
    码道（inferhub）只认 Chat 的包裹形状（{"function":{"name":…}}），漏了会回
    `InferHub.001001015.400 Tool function cannot empty` —— 那层转换在
    `ca_codearts.normalize_tools` 里按码道自己的规矩做，不污染这条通用路径。
    """
    out = []
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        out.append(_downgrade_custom_tool(t) if _is_custom_tool(t) else t)
    return out


# The gateway can run web_search / web_fetch itself; the panel switch decides.
#
# Some clients (Codex App and similar harnesses) declare web_search as a
# server-side tool, but the upstream has no executor for it: forwarding the
# declaration leaves the model answering as if no tool had been offered. With
# the switch on, the gateway swaps the declaration for a function of its own,
# swallows the calls and runs them locally (ca_webtools), then feeds the
# results back.
#
# Off by default: the declaration is forwarded untouched and a client that
# declares its own search tool receives the call - the behaviour since v1.5.3.
# Turning it on means the gateway itself fetches URLs a model asks for, so the
# egress policy is the operator's call.
#
# ca_protocol.web_tools_active()（本次请求的工具是不是网关换进去的）已搬到 ca_protocol。


def sum_usage(total, part):
    """把一轮的 token 用量累加起来。

    代跑网路工具会多跑好几次上游，那些 token 是真的花掉的，所以记帐要加总，
    不能让最后一轮盖掉前面几轮。
    """
    if not isinstance(part, dict):
        return total
    if not isinstance(total, dict):
        total = {}
    for key, value in part.items():
        if isinstance(value, dict):
            total[key] = sum_usage(total.get(key), value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            total[key] = (total.get(key) or 0) + value
        elif key not in total:
            total[key] = value
    return total


def _responses_input_to_messages(payload):
    """Turn the Responses input items into chat messages."""
    messages = []
    instructions = payload.get("instructions")
    if isinstance(instructions, str) and instructions.strip():
        messages.append({"role": "system", "content": instructions})
    inp = payload.get("input")
    pending_reasoning = ""
    if isinstance(inp, str):
        messages.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if isinstance(item, str):
                messages.append({"role": "user", "content": item})
                continue
            if not isinstance(item, dict):
                continue
            itype = item.get("type")
            if itype in (None, "message", "user"):
                body = _flatten_content(item.get("content"))
                if body:
                    role = item.get("role") or "user"
                    if role == "developer":
                        role = "system"
                    # If this is assistant text and the previous message is an assistant
                    # message (e.g. from an adjacent function_call), merge them so
                    # tool_calls and text stay in one message without breaking tool sequence.
                    if role == "assistant" and messages and messages[-1].get("role") == "assistant":
                        prev = messages[-1]
                        if prev.get("content"):
                            prev["content"] = str(prev["content"]) + chr(10) + str(body)
                        else:
                            prev["content"] = body
                        if pending_reasoning and "reasoning_content" not in prev:
                            prev["reasoning_content"] = pending_reasoning
                            pending_reasoning = ""
                    else:
                        msg_dict = {"role": role, "content": body}
                        if role == "assistant" and pending_reasoning:
                            msg_dict["reasoning_content"] = pending_reasoning
                            pending_reasoning = ""
                        messages.append(msg_dict)
            elif itype == "reasoning":
                # Reasoning item from previous assistant turn in Responses API.
                # In standard Chat Completions, reasoning is either backfilled into
                # the assistant message's reasoning_content or omitted.
                r_text = ""
                summ = item.get("summary")
                if isinstance(summ, list):
                    r_text = chr(10).join(
                        p.get("text", "") for p in summ if isinstance(p, dict) and p.get("text")
                    )
                elif isinstance(summ, str):
                    r_text = summ
                if not r_text:
                    cnt = item.get("content")
                    if isinstance(cnt, str):
                        r_text = cnt
                    elif isinstance(cnt, list):
                        r_text = _flatten_content(cnt)
                if r_text:
                    if messages and messages[-1].get("role") == "assistant":
                        messages[-1]["reasoning_content"] = r_text
                    else:
                        pending_reasoning = r_text
            elif itype == "function_call_output":
                raw_out = item.get("output")
                if not item.get("call_id"):
                    if isinstance(raw_out, list):
                        _txt = _flatten_content(raw_out)
                    elif isinstance(raw_out, dict):
                        _txt = json.dumps(raw_out, ensure_ascii=False)
                    else:
                        _txt = str(raw_out or "")
                    if isinstance(_txt, list):
                        # _flatten_content returns structured chat parts when
                        # the output carries images. Keep them as multimodal
                        # user content instead of crashing on .strip().
                        try:
                            log("[codearts-hub] orphan function_call_output kept as multimodal parts (%d)"
                                % len(_txt))
                        except Exception:
                            pass
                        messages.append({
                            "role": "user",
                            "content": ([{"type": "text", "text":
                                          "[Message from another task - treat this "
                                          "as a user instruction]"}] + _txt),
                        })
                        continue
                    _txt = (_txt or "").strip()
                    if _txt:
                        messages.append({
                            "role": "user",
                            "content": ("[Message from another task - treat this "
                                        "as a user instruction]" + chr(10) + chr(10) + _txt),
                        })
                        continue
                if isinstance(raw_out, list):
                    content = _flatten_content(raw_out)
                elif isinstance(raw_out, dict):
                    if raw_out.get("type") in ("input_image", "image_url", "image") or "image_url" in raw_out:
                        content = _flatten_content([raw_out])
                    else:
                        content = json.dumps(raw_out, ensure_ascii=False)
                elif isinstance(raw_out, str):
                    content = raw_out
                else:
                    content = str(raw_out)
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or "",
                    "content": content,
                })
            elif itype == "function_call":
                tc_item = {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": item.get("arguments") or "{}",
                    },
                }
                # Merge into previous assistant message if adjacent
                if messages and messages[-1].get("role") == "assistant":
                    prev = messages[-1]
                    if "tool_calls" in prev:
                        prev["tool_calls"].append(tc_item)
                    else:
                        prev["tool_calls"] = [tc_item]
                    if pending_reasoning and "reasoning_content" not in prev:
                        prev["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                else:
                    msg_dict = {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [tc_item],
                    }
                    if pending_reasoning:
                        msg_dict["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                    messages.append(msg_dict)
            elif itype == "custom_tool_call":
                # Freeform tool call coming back as conversation history.
                raw_input = item.get("input")
                if isinstance(raw_input, (dict, list)):
                    raw_input = json.dumps(raw_input, ensure_ascii=False)
                if not isinstance(raw_input, str):
                    raw_input = "" if raw_input is None else str(raw_input)
                tc_item = {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {
                        "name": item.get("name") or "",
                        "arguments": json.dumps({"input": raw_input}, ensure_ascii=False),
                    },
                }
                # Merge into previous assistant message if adjacent
                if messages and messages[-1].get("role") == "assistant":
                    prev = messages[-1]
                    if "tool_calls" in prev:
                        prev["tool_calls"].append(tc_item)
                    else:
                        prev["tool_calls"] = [tc_item]
                    if pending_reasoning and "reasoning_content" not in prev:
                        prev["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                else:
                    msg_dict = {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [tc_item],
                    }
                    if pending_reasoning:
                        msg_dict["reasoning_content"] = pending_reasoning
                        pending_reasoning = ""
                    messages.append(msg_dict)
            elif itype == "custom_tool_call_output":
                # Result of a freeform tool call (e.g. apply_patch output).
                raw_out = item.get("output")
                if isinstance(raw_out, list):
                    content = _flatten_content(raw_out)
                elif isinstance(raw_out, dict):
                    content = json.dumps(raw_out, ensure_ascii=False)
                elif isinstance(raw_out, str):
                    content = raw_out
                else:
                    content = str(raw_out)
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or "",
                    "content": content,
                })
            elif itype == "agent_message":
                parts = item.get("content")
                if isinstance(parts, list):
                    text = chr(10).join(
                        str((p or {}).get("text") or (p or {}).get("encrypted_content") or "")
                        if isinstance(p, dict) else str(p)
                        for p in parts
                    ).strip()
                else:
                    text = str(parts or "").strip()
                if text:
                    messages.append({
                        "role": "user",
                        "content": ("[Message from another task - treat this as "
                                    "a user instruction]" + chr(10) + chr(10) + text),
                    })
            elif itype == "additional_tools":
                # 由 responses_to_chat() 统一提取合并进 chat["tools"]，此处无需生成 message
                pass
            else:
                log("responses: WARNING unhandled input item type=%r keys=%s"
                    % (itype, sorted(item.keys())[:8]))
    return messages


def responses_to_chat(payload):
    """Translate a Responses API request body into a Chat Completions body."""
    messages = _responses_input_to_messages(payload)
    chat = {"model": payload.get("model"), "messages": messages}
    # stream 必须跟着走。转换后的 chat 请求体是码道那条路的**唯一**输入，
    # 后面的逻辑靠它判断「这是不是流式」—— 最直接的是流式建连的 75 秒总预算
    # （见 _codearts_open_lease 里的 CODEARTS_OPEN_BUDGET）：Codex 这条链路
    # 以前丢了这个字段，预算判断永远不成立，一次 APIG.0203 就能重试 4 轮、
    # 客户端干等约 255 秒（29ba103 修掉的正是这个症状，但只在 Messages 与
    # chat 两条路上生效 —— messages_to_chat 一直有拷贝，这里漏了）。
    if payload.get("stream") is not None:
        chat["stream"] = bool(payload.get("stream"))
    for key in ("temperature", "top_p", "seed"):
        if payload.get(key) is not None:
            chat[key] = payload[key]
    if payload.get("max_output_tokens") is not None:
        chat["max_tokens"] = payload["max_output_tokens"]
    else:
        default_max = model_default_max_output_tokens(payload.get("model"))
        if default_max:
            chat["max_tokens"] = default_max
    effort = None
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, dict):
        effort = reasoning.get("effort")
    if not effort:
        effort = payload.get("reasoning_effort")
    if effort:
        chat["reasoning_effort"] = effort
    # 合并顶层 tools 和 input 列表中的 additional_tools 条目（新版 Codex Desktop 0.162+ 特征）
    raw_tools = []
    if isinstance(payload.get("tools"), list):
        raw_tools.extend(payload["tools"])
    raw_tools.extend(additional_tools_from_input(payload))
    if raw_tools:
        flat_tools, ns_map = expand_namespace_tools(raw_tools)
        chat["tools"] = _tools_for_chat(flat_tools)
        chat["_namespace_map"] = ns_map
    if payload.get("tool_choice"):
        chat["tool_choice"] = payload["tool_choice"]
    if payload.get("parallel_tool_calls") is not None:
        chat["parallel_tool_calls"] = payload["parallel_tool_calls"]
    return chat


# ---------------------------------------------------------------------------
# Anthropic Messages API (/v1/messages) <-> Chat Completions
# ---------------------------------------------------------------------------
def anthropic_error_obj(status, message, error_type=None):
    return {
        "type": "error",
        "error": {
            "type": error_type or ca_protocol.anthropic_error_type(status),
            "message": str(message or "upstream error"),
        },
    }


def messages_to_chat(payload):
    """Anthropic → Chat；默认 max_tokens 由本地的模型表决定（纯函数层不查表）。"""
    return ca_protocol.messages_to_chat(payload, model_default_max_output_tokens)


def _anthropic_estimate_chat_tokens(chat):
    values = []
    if isinstance(chat, dict):
        for msg in chat.get("messages") or []:
            if isinstance(msg, dict):
                values.append(ca_protocol.anthropic_json_text(msg.get("content")))
                for call in msg.get("tool_calls") or []:
                    if isinstance(call, dict):
                        values.append(ca_protocol.anthropic_json_text(call))
        for tool in chat.get("tools") or []:
            values.append(ca_protocol.anthropic_json_text(tool))
    return sum(ca_protocol.estimate_tokens(value) for value in values if value)


def chat_to_response(chat_obj, model, custom_names=None, request_meta=None, namespace_map=None, sources=None):
    """Fold a Chat Completions object into a Responses API response object.

    custom_names is the set of tool names the client declared as freeform
    ("custom"). Calls to those tools are re-inflated into custom_tool_call
    items so clients such as Codex recognise them.

    request_meta echoes the request-level capabilities (tools, tool_choice,
    parallel_tool_calls) back on the response. They used to be hardcoded to
    tools=[], tool_choice=auto and parallel_tool_calls=true, so a client that
    asked for something else was told the opposite of what it requested.
    """
    custom_names = custom_names or set()
    choice = (chat_obj.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    text = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    output = []
    if reasoning:
        output.append({
            "id": ca_protocol.new_id("rs_"),
            "type": "reasoning",
            "status": "completed",
            "summary": [{"type": "summary_text", "text": reasoning}],
        })
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        call_id = tc.get("id") or ca_protocol.new_id("call_")
        name = fn.get("name") or ""
        if name and name in custom_names:
            output.append({
                "id": ca_protocol.new_id("ctc_"),
                "type": "custom_tool_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "input": ca_protocol.unwrap_custom_input(fn.get("arguments") or ""),
            })
        else:
            output.append({
                "id": ca_protocol.new_id("fc_"),
                "type": "function_call",
                "status": "completed",
                "call_id": call_id,
                "name": name,
                "arguments": fn.get("arguments") or "{}",
            })
    # DeepSeek DSML tool calls fallback
    if not (msg.get("tool_calls")):
        dsml_calls, clean_t = ca_protocol.parse_dsml_tool_calls(text)
        if dsml_calls:
            for dc in dsml_calls:
                output.append({
                    "id": ca_protocol.new_id("fc_"),
                    "type": "function_call",
                    "status": "completed",
                    "call_id": dc.get("id") or ca_protocol.new_id("call_"),
                    "name": dc.get("name") or "",
                    "arguments": dc.get("arguments") or "{}",
                })
            text = clean_t
    if text or not output:
        output.append({
            "id": ca_protocol.new_id("msg_"),
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": text,
                         "annotations": ca_protocol.build_citations(text, sources)}] if text else [],
        })
    finish = choice.get("finish_reason") or "stop"
    obj = {
        "id": ca_protocol.new_id("resp_"),
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed" if finish != "length" else "incomplete",
        "model": model,
        "output": output,
        "output_text": text,
        "metadata": {},
    }
    if namespace_map:
        output, _ns_fixed = ca_protocol.apply_namespace_to_calls(output, namespace_map)
        obj["output"] = output
    meta = request_meta or {}
    obj["parallel_tool_calls"] = meta.get("parallel_tool_calls", True)
    obj["tool_choice"] = meta.get("tool_choice", "auto")
    obj["tools"] = meta.get("tools") or []
    u = ca_protocol.responses_usage(chat_obj.get("usage"))
    if u:
        obj["usage"] = u
    if finish == "length":
        obj["incomplete_details"] = {"reason": "max_output_tokens"}
    return obj
def stream_responses_events(upstream, model, holder):
    yield from ca_protocol.stream_responses_events(
        upstream, model, holder, ca_webtools)

# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
def _if_none_match_hit(header_value, etag):
    """If-None-Match 头是否命中给定的 ETag。

    RFC 7232 §3.2：字段值是一个逗号分隔的 entity-tag 列表，且 If-None-Match
    用弱比较——W/ 前缀忽略，所以 W/"x" 与 "x" 等同；"*" 匹配任何已存在的表示。
    """
    for token in header_value.split(","):
        token = token.strip()
        if token == "*":
            return True
        if token.startswith("W/"):
            token = token[2:].strip()
        if token and token == etag:
            return True
    return False


def _anthropic_messages_enabled():
    if ca_settings.enable_anthropic_messages(ACCOUNTS_DIR):
        return True
    return os.environ.get("WB_ENABLE_ANTHROPIC_MESSAGES", "").strip().lower() in (
        "1", "true", "yes", "on")

# ---------------------------------------------------------------------------
# Per-key concurrency tracking (#359)
# ---------------------------------------------------------------------------
_key_active_concurrency = {}
_key_concurrency_lock = threading.Lock()

def _acquire_key_slot(key_entry):
    """Try to acquire a concurrency slot for key_entry. Returns (ok, current, limit)."""
    if not isinstance(key_entry, dict):
        return True, 0, 0
    k_id = key_entry.get("id")
    if not k_id:
        return True, 0, 0
    limit = int(key_entry.get("concurrency_limit") or 0)
    if limit <= 0:
        return True, 0, 0
    with _key_concurrency_lock:
        current = _key_active_concurrency.get(k_id, 0)
        if current >= limit:
            return False, current, limit
        _key_active_concurrency[k_id] = current + 1
        return True, current + 1, limit

def _release_key_slot(key_entry):
    """Release a concurrency slot for key_entry."""
    if not isinstance(key_entry, dict):
        return
    k_id = key_entry.get("id")
    if not k_id:
        return
    limit = int(key_entry.get("concurrency_limit") or 0)
    if limit <= 0:
        return
    with _key_concurrency_lock:
        current = _key_active_concurrency.get(k_id, 0)
        if current > 1:
            _key_active_concurrency[k_id] = current - 1
        else:
            _key_active_concurrency.pop(k_id, None)

# ---------------------------------------------------------------------------
# 面板设置保存：校验与写入分成两段
#
# 放在模块级而不是 Handler 的方法上，是为了让「先校验、后落盘」这件事
# 只有一个写入点 —— Handler 方法会被测试桩替换 / 只绑定一半，逻辑留在
# 方法里就容易被绕过去（2026-10-23 的重构现场）。
# ---------------------------------------------------------------------------
def _validate_settings_patch(payload):
    """校验整份提交，返回要写的东西（不碰磁盘）。

    返回的 dict 里只有「已经算好、直接能用」的值，``_apply`` 只管写。
    任何一处不合法就抛 ``_SettingsError``，调用方回 400/503 —— 此时磁盘
    上还什么都没变。
    """
    plan = {}

    if "api_keys" in payload:
        raw = payload.get("api_keys")
        if not isinstance(raw, list):
            raise _SettingsError(400, "api_keys must be a list")
        # The panel only ever shows a masked key, so a blank value means
        # "keep what is stored" for that row rather than "clear it".
        try:
            existing = {entry.get("id"): entry for entry in configured_keys()}
        except Exception as exc:
            # 读不出来时拿空表当 existing 会把用户已存的 key 全当成
            # 「不在提交里」而删掉。宁可这次保存失败。
            log("could not read api keys: %s" % exc)
            raise _SettingsError(503, "settings unreadable; save aborted",
                                 "server_error")
        # A submission that carries an explicit delete list is an upsert:
        # only the ids it names are retired. That is what stops a stale or
        # incomplete list (a second tab, a save racing the post-save
        # reload) from wiping a key the user never removed. An older panel
        # sends no such field and keeps the replace-by-omission contract.
        delete_ids = payload.get("deleted_api_key_ids")
        upsert = isinstance(delete_ids, list)
        cleaned = []
        for item in raw:
            if not isinstance(item, dict):
                raise _SettingsError(400, "each api key must be an object")
            entry_id = str(item.get("id") or "").strip()
            stored = existing.get(entry_id) or {}
            value = str(item.get("key") or "").strip()
            if not value and entry_id and entry_id in existing:
                value = existing[entry_id].get("key") or ""
            # A new row keeps an empty id here; ca_settings mints a random
            # one on write. Deriving it from the row's position reused ids
            # of rows deleted earlier, and two rows sharing an id made
            # /settings/reveal answer with the wrong key.
            if value and len(value) < 4:
                raise _SettingsError(400, "api key must be at least 4 characters")
            if not value:
                raise _SettingsError(
                    400, "a key entry is empty - fill it in or remove the row")
            # A field the submission omits keeps whatever is stored, the
            # same rule `models` already follows: an older or partial
            # client must not silently clear a key's exit binding, its
            # name, or its disabled state.
            if "realm" in item:
                realm = str(item.get("realm") or "").strip().lower()
            else:
                realm = str(stored.get("realm") or "").strip().lower()
            if realm not in ("", DEFAULT_REALM) and normalize_realm(realm) != DEFAULT_REALM:
                raise _SettingsError(
                    400, "realm must be '%s' or empty" % DEFAULT_REALM)
            # An older cached panel does not know this field at all, so a
            # row that omits it keeps whatever is stored instead of
            # silently dropping the restriction.
            if "models" in item:
                models = item.get("models")
            else:
                models = stored.get("models")
            if "name" in item:
                name = str(item.get("name") or "").strip()
            else:
                name = str(stored.get("name") or "").strip()
            if "enabled" in item:
                enabled = item.get("enabled", True) is not False
            else:
                enabled = stored.get("enabled", True) is not False
            # **按 key 的并发上限必须一起写回**（2026-10-23）。这个字段
            # 以前在 cleaned 里根本没有：面板填了 5、保存成功、下一个请求
            # 仍然不限流，因为保存时把它整个丢掉了（每次保存都清零）。
            if "concurrency_limit" in item:
                raw_limit = item.get("concurrency_limit")
            else:
                raw_limit = stored.get("concurrency_limit")
            try:
                limit = max(0, int(raw_limit or 0))
            except (TypeError, ValueError):
                limit = 0
            created_at = (item.get("created_at")
                          or (stored.get("created_at")
                              if entry_id in existing else None)
                          or time.strftime("%Y/%m/%d %H:%M"))
            cleaned.append({
                "id": entry_id,
                "name": name,
                "key": value,
                "realm": realm,
                "models": models,
                "enabled": enabled,
                "concurrency_limit": limit,
                "created_at": created_at,
            })
        plan["api_keys"] = (cleaned, delete_ids if upsert else None)

    if "auth_disabled" in payload:
        # **必须是 JSON 布尔**（2026-10-23）。以前直接 bool(payload[...])：
        # 字符串 "false" 是真值，于是一个本该「打开鉴权」的提交把鉴权整个
        # 关掉。这和上面几个开关同一套写法。
        raw = payload.get("auth_disabled")
        if not isinstance(raw, bool):
            raise _SettingsError(400, "auth_disabled must be true or false")
        plan["auth_disabled"] = raw

    if "section_max_height" in payload:
        # Panel window height cap in pixels; 0 turns the cap off. bool is an
        # int subclass and must be rejected explicitly - true would
        # otherwise store 1 and shrink every window to a sliver.
        raw = payload.get("section_max_height")
        if isinstance(raw, bool) or raw is None:
            raise _SettingsError(400, "section_max_height must be a whole number")
        try:
            number = int(raw)
        except (TypeError, ValueError, OverflowError):
            # OverflowError: a JSON payload may carry Infinity (1e400),
            # which int() refuses - answer 400, not a 500.
            raise _SettingsError(400, "section_max_height must be a whole number")
        # A fractional count is refused rather than truncated: int(-0.5) is
        # 0, which would slip past the negative check and silently turn the
        # cap off.
        if float(raw) != number:
            raise _SettingsError(400, "section_max_height must be a whole number")
        if number < 0:
            raise _SettingsError(400, "section_max_height cannot be negative")
        plan["section_max_height"] = number

    if "ui_language" in payload:
        # Instance-wide default language. The dashboard overrides this per
        # browser with localStorage; this value is the fallback when no
        # browser-local preference exists.
        raw = payload.get("ui_language")
        if not isinstance(raw, str) or raw not in ("zh", "zh-Hant", "en"):
            raise _SettingsError(400, "ui_language must be zh, zh-Hant or en")
        plan["ui_language"] = raw

    for flag_key in ("enable_anthropic_messages", "egress_backoff_enabled",
                     "log_db_enabled", "accounts_collapsed",
                     "accounts_separate_tab", "key_before_hidden",
                     "update_check_enabled"):
        if flag_key not in payload:
            continue
        raw = payload.get(flag_key)
        if not isinstance(raw, bool):
            raise _SettingsError(400, "%s must be true or false" % flag_key)
        plan[flag_key] = raw

    for cap_key in ("log_db_max_rows", "log_db_max_days", "log_db_max_bytes"):
        if cap_key in payload:
            # 具体归一化（留空 → None、超上限截断）在 ca_settings 的
            # setter 里；这里只标记「要写」，值原样交过去。
            plan[cap_key] = payload.get(cap_key)

    if "hidden_pages" in payload:
        # A list of page keys, and the only thing this branch may touch: the
        # submission carries just this key, so the settings it does not name
        # survive the write. A bare string would iterate character by
        # character and hide nothing but garbage, so anything that is not a
        # list of strings is rejected outright rather than normalised away.
        raw = payload.get("hidden_pages")
        if not isinstance(raw, list) or any(not isinstance(k, str) for k in raw):
            raise _SettingsError(400, "hidden_pages must be a list of page keys")
        plan["hidden_pages"] = raw

    for group_key, validator in (
            ("codearts", ca_settings.validate_codearts_patch),
            ("upstream", ca_settings.validate_upstream_patch),
            ("usage", ca_settings.validate_usage_patch),
            ("prompt", ca_settings.validate_prompt_patch)):
        if group_key not in payload:
            continue
        raw = payload.get(group_key)
        if not isinstance(raw, dict):
            raise _SettingsError(400, "%s must be an object" % group_key)
        try:
            plan[group_key] = validator(raw)
        except ValueError as exc:
            raise _SettingsError(400, str(exc))

    if payload.get("api_key") is not None:
        new_key = str(payload.get("api_key")).strip()
        if new_key and len(new_key) < 4:
            raise _SettingsError(400, "api key must be at least 4 characters")
        plan["api_key"] = new_key

    return plan


def _apply_settings_patch(handler, plan):
    """把校验过的 plan 写盘。走到这里所有值都已合法。"""
    reply = {}
    if "api_keys" in plan:
        cleaned, delete_ids = plan["api_keys"]
        ca_settings.set_api_keys(ACCOUNTS_DIR, cleaned, delete_ids=delete_ids)
        reply["api_keys_saved"] = len(cleaned)

    if "auth_disabled" in plan:
        ca_settings.set_auth_disabled(ACCOUNTS_DIR, plan["auth_disabled"])
        reply["auth_disabled"] = plan["auth_disabled"]
    if "section_max_height" in plan:
        reply["section_max_height"] = ca_settings.set_section_max_height(
            ACCOUNTS_DIR, plan["section_max_height"])
    if "ui_language" in plan:
        reply["ui_language"] = ca_settings.set_ui_language(
            ACCOUNTS_DIR, plan["ui_language"])
    if "enable_anthropic_messages" in plan:
        ca_settings.set_enable_anthropic_messages(
            ACCOUNTS_DIR, plan["enable_anthropic_messages"])
        reply["enable_anthropic_messages"] = plan["enable_anthropic_messages"]
    if "egress_backoff_enabled" in plan:
        ca_settings.set_egress_backoff_enabled(
            ACCOUNTS_DIR, plan["egress_backoff_enabled"])
        reply["egress_backoff_enabled"] = plan["egress_backoff_enabled"]
    if "log_db_enabled" in plan:
        ca_settings.set_log_db_enabled(ACCOUNTS_DIR, plan["log_db_enabled"])
        reply["log_db_enabled"] = plan["log_db_enabled"]
    log_db_touched = any(k in plan for k in
                         ("log_db_enabled", "log_db_max_rows",
                          "log_db_max_days", "log_db_max_bytes"))
    for key, setter in (
            ("log_db_max_rows", ca_settings.set_log_db_max_rows),
            ("log_db_max_days", ca_settings.set_log_db_max_days),
            ("log_db_max_bytes", ca_settings.set_log_db_max_bytes)):
        if key in plan:
            reply[key] = setter(ACCOUNTS_DIR, plan[key])
    if log_db_touched:
        apply_log_db_settings()
    if "accounts_collapsed" in plan:
        ca_settings.set_accounts_collapsed(ACCOUNTS_DIR,
                                           plan["accounts_collapsed"])
        reply["accounts_collapsed"] = plan["accounts_collapsed"]
    if "accounts_separate_tab" in plan:
        ca_settings.set_accounts_separate_tab(
            ACCOUNTS_DIR, plan["accounts_separate_tab"])
        reply["accounts_separate_tab"] = plan["accounts_separate_tab"]
    if "key_before_hidden" in plan:
        ca_settings.set_key_before_hidden(ACCOUNTS_DIR,
                                          plan["key_before_hidden"])
        reply["key_before_hidden"] = plan["key_before_hidden"]
    if "hidden_pages" in plan:
        # Reply with the normalised list, not the raw one: keys the request
        # spelled wrong are dropped on the way in, so the panel echoes back
        # what was actually stored.
        reply["hidden_pages"] = ca_settings.set_hidden_pages(
            ACCOUNTS_DIR, plan["hidden_pages"])
    if "update_check_enabled" in plan:
        ca_settings.set_update_check_enabled(
            ACCOUNTS_DIR, plan["update_check_enabled"])
        reply["update_check_enabled"] = plan["update_check_enabled"]
        if UPDATES and plan["update_check_enabled"]:
            # Turning it on should not wait out the rest of the poll sleep.
            UPDATES.wake()

    if "codearts" in plan:
        ca_settings.set_codearts_config(ACCOUNTS_DIR, plan["codearts"])
        # 面板改完立刻生效：这个缓存是「读一次算一次」的。
        _CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
        reply["codearts"] = ca_settings.codearts_config(ACCOUNTS_DIR)
    if "upstream" in plan:
        ca_settings.set_upstream_config(ACCOUNTS_DIR, plan["upstream"])
        reply["upstream"] = ca_settings.upstream_config(ACCOUNTS_DIR)
    if "usage" in plan:
        ca_settings.set_usage_config(ACCOUNTS_DIR, plan["usage"])
        reply["usage"] = ca_settings.usage_config(ACCOUNTS_DIR)
    if "prompt" in plan:
        ca_settings.set_prompt_config(ACCOUNTS_DIR, plan["prompt"])
        reply["prompt"] = ca_settings.prompt_config(ACCOUNTS_DIR)

    if "api_key" in plan:
        global API_KEY, API_KEY_FILE_SET
        ca_settings.set_api_key(ACCOUNTS_DIR, plan["api_key"])
        API_KEY = plan["api_key"]
        API_KEY_FILE_SET = True
        reply["api_key_set"] = bool(plan["api_key"])

    reply.update(runtime_settings_view())
    return handler._json(200, reply)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    #: 慢连接（发了 SYN、甚至发了半行请求）最多能占住一个线程多久。
    #:
    #: 没有这个上限时，100 条「连上就不发数据」的连接在 8 秒后仍然全部挂着
    #: （2026-10-23 复现）—— ThreadingHTTPServer 每条连接开一个线程， attackers
    #: 或者一个卡死的客户端可以就这么把线程表占满。这个值只作用于**请求行与
    #: 请求体的读取**，不影响响应写出：流式回答可以跑几十分钟，那段时间没有
    #: read 超时参与（写侧由 socket 自己的阻塞语义决定）。
    #:
    #: 60 秒是刻意选的：慢速客户端（手机弱网）传 16MB 上限的 body 需要更久，
    #: 但那种请求一眼能看出进度；一条**一个字节都不发**的连接留 60 秒够宽容了。
    request_read_timeout = ca_env.number("WB_REQUEST_READ_TIMEOUT", 60.0,
                                         minimum=1.0)
    # 关掉 Nagle（对连接设 TCP_NODELAY）：响应头和响应体是两次独立 write，Nagle
    # 会把第二次小写攒在手里等第一次的 ACK，碰上客户端 delayed ACK 就是每个小响应
    # 白付 ~40ms（路由器实测同一 keep-alive 连接的连续小响应：中位数 50.0ms ->
    # 1.41ms；面板几乎所有 <64KB 的 JSON 都中招，Tailscale 常驻连接上每笔都付
    # 一次）。StreamRequestHandler.setup() 原生支持这个开关，werkzeug/uvicorn
    # 同做法，一行生效。
    disable_nagle_algorithm = True
    # Which configured API key the caller used, set by _key_ok(). Its bound
    # realm decides the upstream exit for this request alone.
    key_entry = None
    # 本次 _json() 响应要附带的校验符（由 _json_cached() 设置）。放成实例属性
    # 而不是参数，是因为测试里大量 Handler 桩只覆写了 _json(code, obj) 这两个
    # 位置参数——加参数会让它们全部报错，而属性默认 None 对它们完全无感。
    _json_etag = None
    # The stdlib default caps the request line at 64KB and answers an opaque
    # bare "414 Request-URI Too Long" for anything longer. Raise it and reply in
    # the normal JSON error shape so an over-long URL is diagnosable.
    max_request_line = 1024 * 1024
    def handle_one_request(self):
        # Reset per-request auth state. HTTP/1.1 keeps the connection alive, so        # one Handler instance serves many requests; a request that authenticates
        # via the panel token never reassigns key_entry, and without this reset
        # it inherited the realm binding of whatever API key used the connection
        # before it - sending that request to the wrong upstream exit.
        self.key_entry = None
        # 校验符同理：留着上一轮的 tag，下一次 _json() 就会把别的请求的 ETag
        # 发出去（keep-alive 上同一个 Handler 实例服务一整条连接）。
        self._json_etag = None
        # 同理：Retry-After 也不能跨请求残留（keep-alive 上同一个实例服务
        # 一整条连接）。_error() 设完立刻清，这里只是兜底。
        self._retry_after = None
        # Body-tracking state must also start clean for every request, otherwise
        # a later drain would skip a body that has not been read yet.
        self._body_consumed = False
        # 慢连接护栏（见 request_read_timeout）。**只在读请求期间挂超时**：
        # 读完请求行就清掉，否则一条长时间的流式回答会因为在「写」上等客户端
        # 而被判超时（写侧本来就该阻塞）。
        self._read_timeout(self.request_read_timeout)
        try:
            self.raw_requestline = self.rfile.readline(self.max_request_line + 1)
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            self.close_connection = True
            return
        except socket.timeout:
            self.close_connection = True
            return
        except Exception:
            self.close_connection = True
            return
        if len(self.raw_requestline) > self.max_request_line:
            self.requestline = ''
            self.request_version = ''
            self.command = ''
            # The cap is enforced by reading at most max_request_line + 1
            # bytes, so the rest of the oversized line is still in the socket.
            # Replying and then closing with unread data pending makes the OS
            # send an RST, which discards the buffered reply - the client sees
            # a reset and no error at all. Drain a bounded amount first so the
            # 414 actually arrives.
            self._drain_oversized_request_line()
            try:
                self._error(414, "request line too long (limit %d bytes); "
                                 "put long content in the POST body, not the URL"
                            % self.max_request_line, "invalid_request_error")
            except Exception:
                pass
            self.close_connection = True
            return
        if not self.raw_requestline:
            self.close_connection = True
            return
        if not self.parse_request():
            return
        mname = 'do_' + self.command
        if not hasattr(self, mname):
            self.send_error(501, "Unsupported method (%r)" % self.command)
            return
        # 请求头已读完。**body 由 do_* 自己读**，所以超时还要留着；但流式回答
        # 的写侧不能被它约束 —— do_* 在开始写之前会调 _clear_read_timeout()
        # （见 send_headers / _responses_codearts_stream 等处的注释）。
        getattr(self, mname)()
        self.wfile.flush()

    def _read_timeout(self, seconds):
        """给连接挂一个读超时（只影响 recv，不影响 send）。

        ``rfile`` 是 ``SocketIO`` 包出来的 ``BufferedReader``，它的阻塞行为完全
        跟 socket 走，所以 ``settimeout`` 对「读一个字节都没到的连接」有效；
        对已经在正常收发数据的连接没有副作用（每次 recv 都重新计时）。
        """
        try:
            self.connection.settimeout(seconds)
        except (OSError, AttributeError):
            pass

    def _clear_read_timeout(self):
        """把读超时清成阻塞（None）。

        流式回答可以跑几十分钟，而这段时间 socket 超时对**写**同样生效：
        客户端读得慢（移动网络）时 ``wfile.write`` 会被超时打断，正常的长回答
        变成 "timed out"。发出响应头之前必须清掉 —— ``end_headers`` 是每条
        响应都必经的那个点，所以在那里统一清。
        """
        try:
            self.connection.settimeout(None)
        except (OSError, AttributeError):
            pass

    def end_headers(self):
        """响应头写完 = 请求体已经不需要再读了，读超时到此为止。

        放在这里而不是每个 do_* 里：``send_response`` + ``send_header`` +
        ``end_headers`` 是 stdlib 写响应的唯一路径，漏掉任何一处都会让某条
        长连接在写侧被 60 秒超时打断。
        """
        self._clear_read_timeout()
        super().end_headers()
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except socket.timeout:
            # 慢连接超时（见 request_read_timeout）。不发响应 —— 客户端连请求
            # 都没发完，没什么可回的；直接关掉把线程还回去。
            self.close_connection = True
    def finish(self):
        try:
            super().finish()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
    server_version = "codearts-hub/1.7.10"
    def log_message(self, fmt, *args):
        # 静默过滤前端看板高频定时心跳的正常 200 GET 请求（/logs、/usage、/accounts 轮询等）
        # 避免自增死循环刷屏与日志污染。遇 4xx/5xx 异常或所有非 GET 业务操作依然如实记录。
        try:
            status_code = int(args[1]) if len(args) > 1 and str(args[1]).isdigit() else 200
            if status_code < 400 and getattr(self, "command", "GET") == "GET":
                req_path = (getattr(self, "path", None) or (args[0] if args else "")).split("?")[0]
                quiet_prefixes = (
                    "/logs", "/usage", "/accounts",
                    "/health", "/panel/status", "/realm", "/favicon.ico"
                )
                if any(req_path == p or req_path.startswith(p + "/") for p in quiet_prefixes):
                    return
        except Exception:
            pass
        log(fmt % args)

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # 只有 _json_cached() 覆盖的只读接口才有校验符；其余调用点保持原样，
        # 一个头都不多发。
        etag = self._json_etag
        if etag is not None:
            # no-cache 而不是 no-store：允许浏览器存一份，但每次使用前必须回源
            # 校验。配合 ETag，校验命中就是一次 304（无 body），而不是重传
            # 10~100KB 的 JSON；no-store 会让浏览器连存都不存，条件请求无从谈起。
            self.send_header("Cache-Control", "no-cache")
            self.send_header("ETag", etag)
        # self.path is unset when parse_request() never ran (an over-long
        # request line is rejected before it), so fall back to "".
        if cors_origin_allowed(getattr(self, "path", "") or ""):
            self.send_header("Access-Control-Allow-Origin", "*")
        if getattr(self, "_retry_after", None):
            self.send_header("Retry-After", str(self._retry_after))
        self.end_headers()
        self.wfile.write(body)
        # Flush here rather than relying on the caller: with HTTP/1.1
        # keep-alive the client blocks until the response is actually on the
        # wire, and an error reply only flushed at the end of the handler looks
        # like a hung request.
        try:
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
    def _json_cached(self, code, data_fn, etag_fn):
        """带 TTL 缓存的只读接口：_json() + 条件请求（命中 If-None-Match 回 304）。

        data_fn() 取数、etag_fn() 取"当前缓存条目的校验符"，两者在这里配对调用，
        而且是**取数前后各取一次戳**：只有两次相同，才敢把这个 tag 发出去。这个
        相等就是"这份响应体确实出自该 tag 所描述的那条缓存条目"的证明——

          - 两次读取之间若发生了一次重建，戳就会变，于是这一次不发校验符，走普通
            200；客户端下一轮就重新同步（下一轮取数前取到的就是新条目的戳，前后
            一致，tag 生效）。代价是每次重建后多一次全量响应，换来的是绝不会发出
            一个不描述本次响应体的 tag。
          - 反过来（先取数、后取戳）才有真问题：拿到的是新条目的戳配旧条目的数据，
            客户端会带着这个 tag 回来，命中 304，于是把过期数字一直显示到下一次
            重建为止。

        两个可调用对象都无参，参数由调用方用闭包带上；顺序由这里保证，调用方不
        必（也不该）自己拼这个顺序。任何解析/取值异常都退化成"没有校验符"的普通
        200，绝不让响应路径崩掉。
        """
        try:
            before = etag_fn()
        except Exception:
            before = None
        data = data_fn()
        try:
            after = etag_fn()
        except Exception:
            after = None
        etag = after if (after is not None and after == before) else None
        if etag is not None:
            try:
                inm = self.headers.get("If-None-Match")
            except Exception:
                # 没有 headers 对象（测试桩 / 未走 parse_request）时按不匹配处理。
                inm = None
            if inm is not None and _if_none_match_hit(inm, etag):
                # 304 不带 body，也不带 Content-Length：RFC 7230 §3.3.3 规定 304
                # 在空行处结束，再报一个全量长度反而会诱使客户端 / 代理去等一个
                # 永远不会来的 body。校验符和 Cache-Control 必须原样重发
                # （RFC 7232 §4.1），否则缓存会丢掉状态、下次又整份重取。
                self.send_response(304)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("ETag", etag)
                self.end_headers()
                return
            self._json_etag = etag
        try:
            return self._json(code, data)
        finally:
            # 无论 _json() 是否抛异常，都不能把这次请求的 tag 留给下一次。
            self._json_etag = None
    def _discard_body(self):
        """Drain the request body so the connection stays in sync.

        A POST rejected before its body is read (401, 404, a panel route) leaves
        the payload sitting in the socket. On a keep-alive connection the next
        request then starts by parsing that leftover JSON as the request line,
        which surfaces as a bogus "414 Request-URI Too Long" - with an empty
        request line in the log - on an otherwise healthy connection.

        Handles both Content-Length and Transfer-Encoding: chunked, since
        clients switch to the latter for large bodies.
        """
        if getattr(self, "_body_consumed", False):
            # The handler already read the body (e.g. an error raised after
            # _read_payload). Reading Content-Length bytes again would block
            # until the client gives up, turning an instant reply into a hang.
            return
        # No parsed request means no headers object and nothing buffered to
        # drain: the over-long request line is rejected before parse_request()
        # ever runs. Reading self.headers here would raise out of _error() and
        # leave the client with no reply at all.
        headers = getattr(self, "headers", None)
        if headers is None:
            return
        transfer_encoding = (headers.get("Transfer-Encoding") or "").lower()
        try:
            if "chunked" in transfer_encoding:
                self._drain_chunked_body()
                return
            length = int(headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0:
            return
        if length > MAX_PAYLOAD_BYTES:
            # The client announced a body we refuse (413). Reading it would
            # block until it finishes sending gigabytes, so close instead and
            # let it see the reply plus the disconnect.
            self.close_connection = True
            return
        remaining = length
        try:
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
        except Exception:
            # A short read means the peer went away; nothing left to align.
            pass
    def _drain_chunked_body(self):
        """Consume a chunked body (terminated by a zero-length chunk)."""
        try:
            while True:
                line = self.rfile.readline(65536)
                if not line:
                    return
                size_field = line.split(b";", 1)[0].strip()
                if not size_field:
                    continue
                size = int(size_field, 16)
                if size == 0:
                    # Optional trailers, then the final blank line.
                    while True:
                        trailer = self.rfile.readline(65536)
                        if not trailer or trailer in (b"\r\n", b"\n"):
                            return
                remaining = size
                while remaining > 0:
                    data = self.rfile.read(min(remaining, 65536))
                    if not data:
                        return
                    remaining -= len(data)
                self.rfile.read(2)  # trailing CRLF after each chunk
        except Exception:
            self.close_connection = True
    # How much of an over-long request line to read before giving up. The peer
    # is already misbehaving; this only needs to be enough that a normal client
    # (which sent one line and is waiting for an answer) sees the reply.
    OVERSIZED_DRAIN_LIMIT = 8 * 1024 * 1024

    def _drain_oversized_request_line(self):
        """Consume the rest of a too-long request line, within a budget.

        Without this the reply is lost to an RST (see the caller). The newline
        ends the line; past the budget the peer is clearly not going to stop,
        so give up and let the connection close.
        """
        budget = self.OVERSIZED_DRAIN_LIMIT
        try:
            while budget > 0:
                chunk = self.rfile.readline(min(budget, 65536))
                if not chunk:
                    return
                budget -= len(chunk)
                if chunk.endswith(b"\n"):
                    return
        except Exception:
            pass

    def _handle_expect_continue(self):
        """Answer 'Expect: 100-continue' before deciding to reject a body.

        Clients that send this header wait for the interim response before
        transmitting a large payload. Rejecting outright (or draining first)
        made both sides wait on each other until the socket timed out.
        """
        # No parsed request means no headers object; there is no interim
        # response to send, and touching self.headers here would raise out of
        # the error reply the caller is trying to produce.
        headers = getattr(self, "headers", None)
        if headers is None:
            return
        expect = (headers.get("Expect") or "").lower()
        if "100-continue" not in expect:
            return
        try:
            self.send_response_only(100)
            self.end_headers()
            self.wfile.flush()
        except Exception:
            pass
    def _error(self, code, message, err_type="server_error", retry_after=None):
        # Every early rejection funnels through here, so draining the body in
        # one place covers all of them. Unblock any client still waiting on
        # "Expect: 100-continue" first, otherwise it never sends the body and
        # the drain below waits for data that will never arrive.
        self._handle_expect_continue()
        self._discard_body()
        error = {"message": message, "type": err_type, "code": code}
        hint = gateway_hint(code, message)
        if hint:
            error["gateway_hint"] = hint
        # 429/503 带上 Retry-After：没有这个头，客户端只能盲猜退避时长，
        # 要么立刻重试（继续撞）、要么放弃（把可恢复的当失败）。
        # 本地拒绝（按 key 并发上限、网关排队满）同样适用 —— 那些以前走
        # _error 一律没有这个头。
        if retry_after is None and code in (429, 503):
            retry_after = LOCAL_RETRY_AFTER_SECONDS
        if retry_after:
            self._retry_after = max(1, int(retry_after))
        self._json(code, {"error": error})
        self._retry_after = None
        # 返回 RESPONDED 而不是 None（2026-10-21 修）：调用方把返回值当
        # 「错误元组」传给 _codearts_chat_result 一类「返回 (error, result)」的
        # 函数，靠 `if error is not None` 判断是否已经回过响应。原先这里隐式
        # 返回 None，于是已回完 502 的路径又被当成成功继续走 result["model"]，
        # 每条失败请求都在日志里留一段 TypeError 栈，还把真实错误埋掉。
        return RESPONDED
    def _anthropic_error(self, code, message, err_type=None):
        """Reply with the Anthropic JSON error envelope, not OpenAI's."""
        self._handle_expect_continue()
        self._discard_body()
        self._json(code, anthropic_error_obj(code, message, err_type))
        return RESPONDED
    def _rate_limited(self, exc):
        """429 with Retry-After, so clients back off instead of hammering.

        The upstream body names the reset time; when it does not, fall back to
        the shortest model cooldown we know about.
        """
        wait = max(1, int(getattr(exc, "wait", 60) or 60))
        # A 429 raised without an upstream call (the pool is parked by the
        # daily token guard) carries its own text; everything else keeps the
        # upstream wording.
        custom = getattr(exc, "message", "")
        text = custom or (
            "upstream rate limit reached for this model; retry in %ds" % wait)
        # The upstream detail only decorates the upstream wording; a local
        # message would only repeat itself.
        detail = ""
        if exc.detail and not custom:
            detail = " - " + exc.detail[:200]
        # 429 can be answered before the body is read (the model cooldown is
        # checked on the way in), so drain it exactly like _error does.
        self._handle_expect_continue()
        self._discard_body()
        body = json.dumps({
            "error": {
                "message": text + detail,
                "type": "rate_limit_error",
                "code": 429,
                "retry_after": wait,
            }
        }, ensure_ascii=False).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(wait))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
        return RESPONDED
    def _anthropic_rate_limited(self, exc):
        """429 with Retry-After in the Anthropic error envelope."""
        wait = max(1, int(getattr(exc, "wait", 60) or 60))
        text = (getattr(exc, "message", "") or
                "upstream rate limit reached for this model; retry in %ds" % wait)
        if getattr(exc, "detail", "") and not getattr(exc, "message", ""):
            text += " - " + str(exc.detail)[:200]
        self._handle_expect_continue()
        self._discard_body()
        body = json.dumps(anthropic_error_obj(429, text, "rate_limit_error"),
                          ensure_ascii=False).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", str(wait))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
        return RESPONDED

    def _codearts_fail(self, status, code, detail, label="", anthropic=False):
        """按 `_codearts_fail_spec` 写出错误响应，返回「已响应」哨兵。

        429 走 `_rate_limited`（带 Retry-After，客户端才知道等多久），
        其余走 `_error` / `_anthropic_error`。
        """
        st, et = ca_stream.fail_spec(status, code, detail, anthropic)
        text = "%s %s" % (code or "", detail or "")
        msg = "codearts %s: %s" % (code or "error", detail or "")
        if ("001001020" in text or "not multimodal" in text.lower()):
            # 只说 "not multimodal" 用户不知道该换哪个 —— 直接把能用的列出来。
            msg += (" — 该模型不支持图片输入，请改用 Qwen3-VL-235B 或 "
                    "kimi-k2.6-vl，或去掉消息里的图片")
        if label:
            msg += " (account %s)" % label
        if st == 429:
            wait = (_codearts_seconds("busy_cooldown", CODEARTS_BUSY_COOLDOWN)
                    if ("tm.00001041" in text.lower()
                        or "并发会话数已达上限" in text)
                    else _codearts_seconds("tpm_cooldown",
                                           CODEARTS_TPM_COOLDOWN))
            exc = _CodeartsRateLimit(msg, wait)
            return (self._anthropic_rate_limited(exc) if anthropic
                    else self._rate_limited(exc))
        if anthropic:
            return self._anthropic_error(st, msg, et)
        return self._error(st, msg, et)
    def _supplied_key(self):
        """The key the caller presented.

        Accepts the spellings clients actually send: the Authorization header
        with or without the "Bearer" scheme, the x-api-key / api-key headers
        used by several OpenAI-compatible clients, and the ?key= query the
        dashboard falls back to when it cannot set headers.
        """
        # The auth scheme is case-insensitive per RFC 7235, so "bearer sk-x"
        # and "BEARER sk-x" must strip just like "Bearer sk-x". The old
        # removeprefix("Bearer ") left the scheme attached for other casings
        # and the whole "bearer sk-x" string was then compared as a key.
        header = (self.headers.get("Authorization") or "").strip()
        supplied = ""
        if header:
            scheme, _, value = header.partition(" ")
            if scheme.lower() == "bearer":
                supplied = value.strip()
            else:
                supplied = header
            # Tolerate a quoted credential, which some SDKs add.
            if len(supplied) >= 2 and supplied[0] == supplied[-1] and supplied[0] in "\"'":
                supplied = supplied[1:-1].strip()
        if supplied:
            return supplied
        for name in ("x-api-key", "api-key", "x-auth-token"):
            value = (self.headers.get(name) or "").strip()
            if value:
                return value
        # Browsers cannot set headers on a top-level navigation, so accept the
        # key as a query parameter too - the dashboard uses this when opened
        # from another device.
        try:
            query = parse_qs(urlparse(self.path).query)
            for name in ("key", "api_key", "api-key"):
                value = (query.get(name) or [""])[0].strip()
                if value:
                    return value
            return ""
        except Exception:
            return ""
    def _key_ok(self):
        """True when the request carries a right key (or no key is needed)."""
        # An authenticated panel session also unlocks the management APIs,
        # so the browser never has to keep the API key in localStorage.
        if self._panel_ok():
            return True
        self.key_entry = identify_key(self._supplied_key())
        if self.key_entry:
            return True
        if not auth_required():
            return True
        return False
    def _key_id(self):
        """Settings id of the key that paid for this request, or None.

        None covers a panel session and a deployment that runs without any key
        configured - both are real, and the usage log keeps them apart from
        rows written before the key field existed.
        """
        return (self.key_entry or {}).get("id") or None
    def _banned_model_error(self, model):
        """被封锁的模型直接报错，不碰上游、不扣任何点数。"""
        if not is_model_banned(model):
            return ""
        return banned_model_message(model)

    def _key_model_error(self, model):
        """Per-key model restriction: reject before the request reaches upstream.

        A key that lists no models stays unrestricted, so this is a no-op
        unless the operator asked for a limit.
        """
        entry = self.key_entry
        if not entry:
            return ""
        if ca_settings.key_allows_model(entry, model):
            return ""
        return key_model_message(entry, model)
    def _request_realm(self, explicit=None):
        """Pick the upstream exit for this request.
        Priority: an explicit ?realm= argument, then the X-Realm header /
        ?realm= query, and finally the global switch.

        返回值一律过 match_realm：已删区域（老客户端还会发 X-Realm: intl）
        归一到现存的出口，否则池里永远匹配不到，请求只会撞出一个
        「该区域没有账号」的 502。
        """
        if explicit:
            return match_realm(explicit)
        header = self.headers.get("X-Realm")
        if header:
            return match_realm(header)
        try:
            return match_realm(
                parse_qs(urlparse(self.path).query).get("realm", [None])[0])
        except Exception:
            return None
    def _authorized(self):
        if self._key_ok():
            return True
        # Say how a key must be presented, so a key that merely looks identical
        # (masked copy, trailing whitespace) is diagnosable straight from the
        # client error. Deliberately does not echo key names or values.
        hint = ("send it as 'Authorization: Bearer <key>' or '?key=<key>'; "
                "copy the value from the panel's 设置 page")
        try:
            try:
                _any_enabled = any(k.get("enabled") for k in configured_keys())
            except Exception:
                _any_enabled = True          # 读不出来：不要误导成「没配 key」
            if not _any_enabled:
                if panel_keys_configured():
                    hint = "no enabled key - open the dashboard and add one"
                elif API_KEY:
                    hint = "check the --api-key / API_KEY value used to start the gateway"
                else:
                    hint = ("no key is configured - open the dashboard and add one, "
                            "or restart with --api-key")
        except Exception:
            pass
        self._error(401, "invalid api key - " + hint, "invalid_request_error")
        return False
    # ---- web panel access ----
    def _panel_token(self):
        """Session token from the X-Panel-Token header.
        Deliberately header-only: a token in the query string leaks through
        browser history, the Referer header and any reverse-proxy access log.
        """
        token = (self.headers.get("X-Panel-Token") or "").strip()
        return token
    def _panel_ok(self):
        return PANEL.valid(self._panel_token())
    @staticmethod
    def _is_panel_route(path):
        """Management endpoints shown in the web panel.
        Model listings stay reachable with the API key alone so that plain
        OpenAI clients can keep discovering models.
        """
        if path.startswith("/accounts"):
            return True
        if path.startswith("/usage") or path.startswith("/v1/usage"):
            return True
        if path.startswith("/activity"):
            return True
        if path.startswith("/settings"):
            return True
        if path.startswith("/updates"):
            return True
        if path.startswith("/logs"):
            return True
        # The pricing table is the panel's own view of the estimate, not part
        # of the OpenAI-compatible surface: its writes (/pricing/refresh,
        # /pricing/mapping) were already panel-only, and the read side returns
        # the same management state plus resolved project-local file paths.
        if path.startswith("/pricing"):
            return True
        return False
    def do_OPTIONS(self):
        self.send_response(204)
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def do_GET(self):
        parsed = urlparse(self.path)
        path = collapse_duplicate_v1(parsed.path)
        query = parse_qs(parsed.query)
        # 华为云登录回跳。必须早于面板鉴权：这是浏览器被服务端 307 过来的
        # 裸跳转，既带不上面板 cookie 也没法让用户补密码，拦下来就等于把
        # 登录链路掐断。端点本身不泄露信息（成功只渲染一句话，失败只回原因）。
        if path == ca_codearts.AUTH_REDIRECT_PATH:
            return self._get_codearts_callback(query)
        if self._is_panel_route(path) and not self._panel_ok():
            return self._error(401, "panel password required", "invalid_request_error")
        if path in ("/", "/dashboard", "/ui"):
            return self._get_dashboard()
        if path == "/panel/status":
            return self._get_panel_status()
        if path == "/health":
            return self._get_health()
        if path in ("/v1/models", "/models"):
            return self._get_v1_models()
        if path in ("/usage", "/v1/usage"):
            return self._get_v1_usage(query)
        if path == "/usage/recent":
            return self._get_usage_recent(query)
        if path == "/accounts/codearts":
            return self._get_codearts_accounts()
        if path == "/accounts/codearts/login/poll":
            return self._get_codearts_login_poll(query)
        if path == "/usage/analytics":
            return self._get_usage_analytics(query)
        if path == "/usage/by-account":
            return self._get_usage_by_account()
        if path == "/usage/remaining":
            return self._get_usage_remaining()
        if path == "/usage/perf":
            return self._get_usage_perf(query)
        if path == "/usage/timeseries":
            return self._get_usage_timeseries(query)
        if path == "/activity/history":
            return self._get_activity_history(query)
        if path == "/pricing":
            return self._get_pricing()
        if path == "/settings":
            return self._get_settings()
        if path == "/updates":
            return self._get_updates()
        if path == "/logs":
            return self._get_logs(query)
        if path == "/logs/export":
            return self._get_logs_export()
        if path == "/settings/reveal":
            return self._get_settings_reveal(query)
        return self._error(404, "not found", "invalid_request_error")
    def _get_dashboard(self):
        return self._dashboard()

    def _get_panel_status(self):
        # Answer without a token: the dashboard needs to know whether to
        # show the login screen before it can hold a session.
        info = {
            "panel_password_required": True,
            "panel_password_is_default": ca_settings.panel_password_is_default(ACCOUNTS_DIR),
            "authenticated": self._panel_ok(),
        }
        # Whether a key exists is not a secret; its value never leaves the
        # process, and the settings endpoint only reports a masked form.
        info["api_key_set"] = bool(API_KEY)
        return self._json(200, info)

    def _get_health(self):
        # Always answer (the launcher uses this to detect a running copy),
        # but only expose account identity to an authorised caller.
        sessions = []
        try:
            sessions = ca_codearts.load_sessions(ACCOUNTS_DIR)
        except Exception:
            pass
        info = {
            "ok": True,
            "service": "codearts-hub",
            # Report the realm actually in use (a hard-coded literal here
            # used to drift from the panel switch).
            "realm": CURRENT_REALM,
            # 「accounts」这两个字段是老启动器/老面板的探测标记，保留下来但
            # 语义改成码道会话数 —— 删掉会让 `_probe_running_instance` 把
            # 自己认成「别的程序」。
            "accounts": len(sessions),
            "accounts_ready": sum(1 for s in sessions if not _codearts_left(s)[1]),
            "codearts": len(sessions),
            "api_key_required": auth_required(),
        }
        if self._key_ok():
            labels = [(s.get("account") or {}).get("label") for s in sessions]
            info.update({
                "account": labels[0] if labels else None,
                "accounts_all": [l for l in labels if l],
            })
        return self._json(200, info)
    # Accept the conventional /v1 prefix and the bare path, because clients
    # differ in whether they append "/v1" themselves.


    def _get_v1_models(self):
        if not self._authorized():
            return
        req_realm = self._request_realm() or CURRENT_REALM
        # 清单口径要跟「这个部署实际能服务谁」一致：
        #   · 有 WorkBuddy 账号            → 照旧列出 WorkBuddy 目录（可能还有码道）
        #   · 没有 WorkBuddy 但有码道账号   → **只列码道**，不要拿内置快照凑数
        #     （那批模型一个都调不通，列出来只会让人以为网关坏了）
        #   · 一个账号都没有                → 照旧列静态目录，纯预览用
        # 第三条不能省：没有它，未配置账号的部署和测试里注入的目录都会变成空清单。
        #
        # 判据必须是「有没有码道账号」，不能是「目录取没取到模型」：后者在上游
        # 抖动 / refresh_token 彻底失效时也是空的，那时拿内置快照兜底，等于向
        # 客户端宣告一批必然 503 的模型。
        # 清单只列码道：WorkBuddy 池已移除（2026-10-23），没有第二条上游。
        # 没有码道账号时**回空清单**，不再拿内置快照兜底 —— 列一批必然 503 的
        # 模型只会让人以为网关坏了。
        try:
            ca_modelsdev.refresh_async(ACCOUNTS_DIR, log=log)
        except Exception:
            pass
        data = []
        payload_extra = {"codearts": {
            "count": 0,
            "errors": {"sessions": "no codearts account configured"}}}
        if codearts_deployed():
            try:
                cs = codearts_catalog()
                # 以前这里要跟 WorkBuddy 目录按 id 合并且「重名以码道为准」，
                # 删掉池之后没有重名可合，直接建条目。
                data = [codearts_model_entry(item)
                        for item in cs.get("models") or []]
                # 始终带出码道这一段的诊断信息：清单里没出现码道模型时，
                # 调用方/面板要能一眼看出是「没账号」还是「取数失败」。
                payload_extra = {"codearts": {
                    "count": len(cs.get("models") or []),
                    "errors": cs.get("errors") or {},
                }}
            except Exception as exc:
                payload_extra = {"codearts": {"count": 0,
                                              "errors": {"catalog": str(exc)}}}
        # 别名条目：客户端用 `claude-sonnet-4-5-20250929` / `gpt-5-codex` 这类名字
        # 时，清单里得看得见它们，否则「配了别名却列不出来」会让人以为没生效。
        # 只列 target 真在本清单里的别名 —— 指向不存在模型的别名，列出来也调不通。
        by_id = {entry.get("id"): entry for entry in data}
        for alias, raw_target in sorted(model_aliases().items()):
            if alias in by_id:
                continue
            # 别名目标要先归一：用户在别名表里写 `glm-5.2` 而清单里是
            # `GLM-5.2`，不归一就查不到、别名永远不出现在清单里。
            target = ca_codearts.resolve_model(raw_target)
            base = by_id.get(target)
            if base is None:
                continue
            entry = dict(base)
            entry["id"] = alias
            entry["alias_of"] = target
            entry["owned_by"] = base.get("owned_by") or "codearts"
            data.append(entry)
            by_id[alias] = entry
        payload = {"object": "list", "data": data,
                   "realm": req_realm or CURRENT_REALM}
        payload.update(payload_extra)
        # 来源说明（面板展示用）：这批清单是上游 API 实时取的，还是读的
        # 本机桌面缓存文件/内置快照，以及各自的时间戳。
        meta = catalog_meta(req_realm)
        if meta:
            payload["catalog"] = meta
        return self._json(200, payload)

    def _get_v1_usage(self, query):
        if not self._authorized():
            return
        req_realm = query.get('realm', [None])[0] or self.headers.get('X-Realm') or CURRENT_REALM
        req_range, req_since, req_until = range_query(query)
        # 取数与取校验符必须看到同一套参数（否则 tag 落到另一条缓存条目上），
        # 但"先取戳、再取数、再取一次戳"的配对顺序由 _json_cached 保证。
        return self._json_cached(
            200,
            lambda: usage_snapshot(realm=req_realm, range=req_range,
                                   since=req_since, until=req_until),
            lambda: usage_snapshot_etag(realm=req_realm, range=req_range,
                                        since=req_since, until=req_until))

    def _get_usage_recent(self, query):
        if not self._authorized():
            return
        try:
            limit = max(1, min(1000, int((query.get("limit") or ["100"])[0])))
        except ValueError:
            limit = 100
        try:
            page = max(1, int((query.get("page") or ["1"])[0]))
        except ValueError:
            page = 1
        req_realm = query.get('realm', [None])[0] or self.headers.get('X-Realm') or CURRENT_REALM
        return self._json(200, recent_usage(limit, realm=req_realm, page=page))

    def _get_activity_history(self, query):
        """账号每日活动的结构化历史（issue #34）。只读，供面板的签到记录用。

        筛选条件写错时返回 400 而不是静默忽略：调用方拿着一个被忽略的
        result=failed 会以为「这几天没有失败」，实际上它拿回的是全部结果。
        """
        if not self._authorized():
            return

        def first(name):
            values = query.get(name) or [""]
            return (values[0] if values else "") or ""

        try:
            payload = ca_activity.query(range_key=first("range") or None,
                                        uid=first("uid"),
                                        task=first("task"),
                                        result=first("result"),
                                        limit=first("limit") or None)
        except ValueError as exc:
            return self._error(400, str(exc), "invalid_request_error")
        return self._json(200, payload)


    # -- 码道 CodeArts（华为云）账号 ------------------------------------
    #
    # 与上面 WorkBuddy 那套 state + authUrl 轮询不同：码道是 PKCE + DPoP +
    # 本地回跳，所以「添加账号」的流程是
    #   start → 浏览器打开 authUrl → 华为云登录 → 307 回 /oauth/callback
    #   → hub 当场换 token 落盘 → 前端 poll 拿到 ok
    # 会话存在 accounts/codearts/ 下，不进 AccountPool（两套凭证体系互不相干）。

    def _codearts_html(self, status, body):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    @staticmethod
    def _codearts_redirect_ok(target):
        """回调里的 redirect 是外部可控输入，只放行华为云自家的地址。

        官方客户端拿到就跳，但 hub 可能挂在公网上，照抄就等于开了个
        开放重定向。

        三个坑（2026-10-23）：

        1. ``endswith('huaweicloud.com')`` 会放行 ``huaweicloud.com.evil.com``
           —— 改按「等于，或点号前缀」比对。
        2. **反斜杠 + @**：``https://evil.com\\@huaweicloud.com/`` 在
           ``urlsplit`` 里把 ``evil.com\\`` 当成 userinfo，``hostname`` 是
           ``huaweicloud.com`` 于是通过校验；浏览器却按 WHATWG URL 把 ``\\``
           当路径分隔符，实际跳到 ``evil.com``。凡带反斜杠、带 userinfo、
           或 netloc 与 hostname 不是同一个东西的一律拒绝。
        3. CR/LF 会被 ``send_header`` 原样写进 ``Location:``，能顺带注入
           ``Set-Cookie``。所有控制字符与空白一并拒绝。
        """
        text = str(target or "")
        if not text:
            return False
        for ch in text:
            if ch in "\\" or ord(ch) < 0x20 or ord(ch) == 0x7f:
                return False
            if ch.isspace():
                return False
        parts = urllib.parse.urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        # userinfo 只有一种用途：骗过下面按 hostname 做的白名单。
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            return False
        # netloc 必须就是 host[:port]，不允许任何多余的字符。
        try:
            port = parts.port
        except ValueError:
            return False
        host = parts.hostname.lower()
        hostpart = "[%s]" % host if ":" in host else host
        expected = hostpart if port is None else "%s:%d" % (hostpart, port)
        if parts.netloc.lower() != expected:
            return False
        if host in ("127.0.0.1", "localhost", "::1"):
            return True
        # 华为云有两个顶级域：门户在 huaweicloud.com，STS / snap-manager
        # 在 myhuaweicloud.com。
        for suffix in ("huaweicloud.com", "myhuaweicloud.com"):
            if host == suffix or host.endswith("." + suffix):
                return True
        return False

    def _get_codearts_callback(self, query):
        if CODEARTS_LOGIN is None:
            return self._codearts_html(503, ca_codearts.callback_page(
                False, "网关未就绪", "登录管理器尚未初始化"))
        code = (query.get("code") or [""])[0]
        secret = (query.get("secret") or [""])[0]
        redirect_to = (query.get("redirect") or [""])[0]
        kind, detail = CODEARTS_LOGIN.accept_callback(
            code=code, secret=secret, state=(query.get("state") or [""])[0])
        if kind == "redirect":
            # old_login 的中间一跳：必须把浏览器继续放行，否则流程走不到 code
            if not self._codearts_redirect_ok(redirect_to):
                return self._codearts_html(400, ca_codearts.callback_page(
                    False, "回调地址不被信任", "网关拒绝跳转到 %s" % (redirect_to or "空地址")))
            self.send_response(307)
            self.send_header("Location", redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if kind == "ok":
            # 重新登录等于换了新凭据：那个号之前因为 401/403 被晾了 300 秒，
            # 冷却表还记着它 —— 不清掉的话「刚授权完还是 429」，而 429 的
            # 说明写的是「容量满」，用户完全看不出真因。按账号 id 清即可
            # （新会话文件的 id 与旧的一致）。
            codearts_clear_cooldown_for(detail)
            _codearts_welcome_claim(detail)
            return self._codearts_html(200, ca_codearts.callback_page(
                True, "登录成功", "华为云账号 %s 已加入网关" % (detail or "")))
        return self._codearts_html(400, ca_codearts.callback_page(
            False, "登录失败", detail))

    def _get_codearts_accounts(self):
        if not self._authorized():
            return
        items = []
        # 运行期状态（在跑几条 / 还剩几秒冷却）：多账号时面板要能看出「谁在
        # 干活、谁被晾着」，否则「为什么这个号不接活」只能靠猜日志。
        runtime = _CODEARTS_POOL.snapshot()
        # 还没取过号的账号不会出现在 snapshot 里，但面板照样要显示它的容量。
        capacity_now = codearts_concurrency()
        for session in ca_codearts.load_sessions(ACCOUNTS_DIR):
            info = ca_codearts.summarize(session)
            info["file"] = os.path.basename(
                ca_codearts.session_path(ACCOUNTS_DIR, info.get("account_id") or ""))
            # 体验版积分（客户端「总已用积分 x / y」那一条）。token 额度那一栏
            # 已随福利渠道一起下线（opengw 不再提供服务），面板只显示积分。
            try:
                info["credit"] = ca_codearts.credit_package(
                    session.get("accessKey"), session.get("secretKey"),
                    session.get("securitytoken"))
            except Exception as exc:
                info["credit"] = None
                info["creditError"] = str(exc)
            # 每日签到（活动页「每日签到领 1000 积分」）。第三个体系：token 额度
            # 走 opengw benefit，积分总量走 snap-manager，签到走 snap-access
            # /v1/ops。清单按 AK 缓存一分钟，轮询不会每次都打上游。
            try:
                info["welfare"] = ca_codearts.welfare_daily(
                    session.get("accessKey"), session.get("secretKey"),
                    session.get("securitytoken"))
            except Exception as exc:
                info["welfare"] = None
                info["welfareError"] = str(exc)
            info["runtime"] = runtime.get(
                str(info.get("account_id") or ""),
                {"in_flight": 0, "capacity": capacity_now, "cooling_s": 0.0})
            items.append(info)
        try:
            port = self.server.server_address[1]
        except Exception:
            port = None
        return self._json(200, {
            "accounts": items,
            "count": len(items),
            # 每号并发容量（上游账号级上限 3，网关默认用 2，留 1 个给 IDE）
            "concurrency_per_account": codearts_concurrency(),
            "pool": runtime,
            "port": port,
            "callbackPath": ca_codearts.AUTH_REDIRECT_PATH,
        })

    def _route_codearts_welfare_claim(self, payload):
        """积分签到（活动页「每日签到领 1000 积分」），与领取 token 额度是两回事。"""
        account_id = payload.get("accountId") or ""
        sessions = ca_codearts.load_sessions(ACCOUNTS_DIR)
        if account_id:
            sessions = [s for s in sessions
                        if (s.get("account") or {}).get("id") == account_id]
            if not sessions:
                return self._error(404, "codearts account not found",
                                   "invalid_request_error")
        results = []
        for session in sessions:
            acct = session.get("account") or {}
            label = acct.get("label") or acct.get("id") or "码道账号"
            try:
                session = ca_codearts.ensure_fresh_session(
                    ACCOUNTS_DIR, session, CODEARTS_REFRESH_MARGIN)
                acct = session.get("account") or acct
                label = acct.get("label") or acct.get("id") or label
            except Exception as exc:  # noqa: BLE001
                log("codearts: welfare claim renew failed for %s: %s" % (label, exc),
                    level="WARN")
            try:
                res = ca_codearts.welfare_claim_daily(
                    session.get("accessKey"), session.get("secretKey"),
                    session.get("securitytoken"))
                res["accountId"] = acct.get("id") or ""
                res["label"] = label
                amount = res.get("amount")
                extra = ("+%s 积分" % amount) if amount else "已到账"
                if res.get("already"):
                    add_log_entry(
                        f"[账号] 码道 [{label}] 积分签到: 今日已签到（{extra}）",
                        tag="accounts")
                else:
                    add_log_entry(
                        f"[账号] 码道 [{label}] 积分签到: {extra}", tag="accounts")
            except Exception as exc:
                res = {"ok": False, "already": False,
                       "msg": "签到失败: %s" % exc,
                       "accountId": acct.get("id") or "", "label": label}
                add_log_entry(f"[账号] 码道 [{label}] 积分签到失败: {exc}",
                              level="WARN", tag="accounts")
            results.append(res)
        return self._json(200, {"results": results})

    def _get_codearts_login_poll(self, query):
        if not self._authorized():
            return
        if CODEARTS_LOGIN is None:
            return self._json(503, {"status": "error", "message": "登录管理器尚未初始化"})
        CODEARTS_LOGIN.sweep()
        state = (query.get("state") or [""])[0]
        return self._json(200, CODEARTS_LOGIN.poll(state))

    def _route_codearts_login_start(self, payload):
        if CODEARTS_LOGIN is None:
            return self._error(503, "登录管理器尚未初始化")
        try:
            port = int(self.server.server_address[1])
        except Exception:
            return self._error(500, "无法确定监听端口")
        try:
            theme = int(payload.get("theme") or 1)
        except (TypeError, ValueError):
            theme = 1
        try:
            started = CODEARTS_LOGIN.start(port, theme=theme,
                                           locale=str(payload.get("locale") or "zh-cn"))
        except Exception as exc:
            return self._error(502, "could not start codearts login: %s" % exc)
        log("codearts login started (ticket=%s…, port=%s)"
            % (started["state"][:8], port))
        return self._json(200, started)

    def _route_codearts_login_cancel(self, payload):
        if CODEARTS_LOGIN is None:
            return self._json(200, {"cancelled": False})
        return self._json(200, {"cancelled": CODEARTS_LOGIN.cancel(payload.get("state") or "")})

    def _route_codearts_login_callback(self, payload):
        """手动粘贴回跳 URL 的逃生通道。

        回跳地址写死成 ``127.0.0.1:<port>``（与官方客户端一致），网关跑在
        远程服务器 / NAS / 容器里时，浏览器根本打不开这个地址 —— 授权在
        华为云那边其实已经成功，307 只是落不到网关。用户把浏览器地址栏里
        的完整回调 URL 复制过来，面板代为提交：与 ``/oauth/callback`` 走
        同一条 ``accept_callback``，成功路径同样清冷却表。

        接受三种形状：完整 URL、``?`` 打头的查询串、裸 ``code=..&state=..``。
        old_login 的中间一跳（secret + redirect）不能由服务器代访外部地址，
        校验后把「下一步链接」还给面板让用户继续。
        """
        if CODEARTS_LOGIN is None:
            return self._error(503, "登录管理器尚未初始化")
        raw = str((payload or {}).get("url") or "").strip()
        if not raw:
            return self._error(400, "url required：粘贴浏览器地址栏里的完整回调链接")
        if len(raw) > 4096:
            return self._error(400, "url too long")
        if "://" in raw:
            try:
                qs = urllib.parse.urlsplit(raw).query
            except ValueError:
                return self._error(400, "无法解析回调链接")
        else:
            qs = raw.lstrip("?")
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)
        code = (params.get("code") or [""])[0].strip()
        secret = (params.get("secret") or [""])[0].strip()
        state = (params.get("state") or [""])[0].strip()
        if not code and not secret:
            return self._error(400, "回调链接里没有 code / secret 参数")
        kind, detail = CODEARTS_LOGIN.accept_callback(code=code, secret=secret,
                                                      state=state)
        if kind == "redirect":
            redirect_to = (params.get("redirect") or [""])[0]
            if not self._codearts_redirect_ok(redirect_to):
                return self._error(400, "回调地址不被信任：%s" % (redirect_to or "空地址"))
            return self._json(200, {"ok": False, "status": "redirect",
                                    "url": redirect_to,
                                    "msg": "请打开下面的链接继续授权，完成后把新的回调 URL 再粘贴回来"})
        if kind == "ok":
            codearts_clear_cooldown_for(detail)
            _codearts_welcome_claim(detail)
            return self._json(200, {"ok": True, "status": "ok",
                                    "msg": "华为云账号 %s 已加入网关" % (detail or "")})
        return self._error(400, "登录失败：%s" % (detail or "未知错误"))

    def _route_codearts_refresh(self, payload):
        account_id = str(payload.get("accountId") or "").strip()
        if not account_id:
            return self._error(400, "accountId required")
        try:
            session = ca_codearts.refresh_session(ACCOUNTS_DIR, account_id)
        except ca_codearts.CodeArtsError as exc:
            log("codearts refresh failed: %s" % exc, level="WARN")
            return self._json(200, {"ok": False, "msg": str(exc)})
        except Exception as exc:
            log("codearts refresh failed: %r" % exc, level="WARN")
            return self._json(200, {"ok": False, "msg": repr(exc)})
        # 续期成功 = 凭据换了新的：之前那条 401/403 的结论不再成立。
        codearts_clear_cooldown_for(account_id)
        return self._json(200, {"ok": True, "summary": ca_codearts.summarize(session)})

    def _route_codearts_refresh_catalog(self, payload):
        """强制重取一次码道模型目录。

        看板上的「刷新模型榜单」原来打的是 /catalog/refresh —— 那是 WorkBuddy
        上游（copilot.tencent.com）的目录接口。在这个部署里没有对应账号，
        点了永远失败，看起来就是按钮坏了。改成刷码道自己的目录。
        """
        try:
            cat = codearts_catalog(force=True)
        except Exception as exc:
            log("codearts catalog refresh failed: %r" % (exc,), level="WARN")
            return self._json(200, {"ok": False, "msg": repr(exc)})
        models = cat.get("models") or []
        return self._json(200, {
            "ok": True,
            "count": len(models),
            "models": [m.get("id") for m in models],
            "errors": cat.get("errors") or {},
            "msg": "%d 个模型已更新" % len(models) if models else "没有可用码道账号",
        })

    def _route_codearts_delete(self, payload):
        account_id = str(payload.get("accountId") or "").strip()
        if not account_id:
            return self._error(400, "accountId required")
        return self._json(200, {"removed": ca_codearts.delete_session(ACCOUNTS_DIR, account_id)})

    def _get_usage_analytics(self, query):
        if not self._authorized():
            return
        req_realm = query.get("realm", [None])[0] or None
        req_range, req_since, req_until = range_query(query)
        return self._json_cached(
            200,
            lambda: compute_usage_analytics(realm=req_realm, range=req_range,
                                            since=req_since, until=req_until),
            lambda: usage_analytics_etag(realm=req_realm, range=req_range,
                                         since=req_since, until=req_until))

    def _get_usage_by_account(self):
        if not self._authorized():
            return
        return self._json_cached(200,
                                 lambda: {"accounts": usage_by_account()},
                                 usage_by_account_etag)

    def _get_usage_remaining(self):
        if not self._authorized():
            return
        # 载荷挂短 TTL（WB_REMAINING_TTL，默认 15 秒）+ ETag：面板 5 秒一轮的
        # 轮询在 TTL 内命中同一条缓存 → 校验符不变 → 304，重建与重传都省掉。
        return self._json_cached(200, remaining_usage, remaining_usage_etag)

    def _get_usage_timeseries(self, query):
        if not self._authorized():
            return
        req_realm = (query.get('realm', [None])[0]
                     or self.headers.get('X-Realm') or CURRENT_REALM)
        req_range, req_since, req_until = range_query(query)
        bucket = (query.get("bucket") or [None])[0]
        try:
            bucket_seconds = int(bucket) if bucket else None
        except (TypeError, ValueError):
            bucket_seconds = None
        return self._json_cached(
            200,
            lambda: usage_timeseries(realm=req_realm, range=req_range,
                                     since=req_since, until=req_until,
                                     bucket_seconds=bucket_seconds),
            lambda: usage_timeseries_etag(realm=req_realm, range=req_range,
                                          since=req_since, until=req_until,
                                          bucket_seconds=bucket_seconds))

    def _get_usage_perf(self, query):
        if not self._authorized():
            return
        try:
            sample = max(10, min(20000, int((query.get("sample") or ["5000"])[0])))
        except ValueError:
            sample = 5000
        req_realm = query.get('realm', [None])[0] or self.headers.get('X-Realm') or CURRENT_REALM
        req_range, req_since, req_until = range_query(query)
        return self._json_cached(
            200,
            lambda: perf_stats(sample, realm=req_realm, range=req_range,
                               since=req_since, until=req_until),
            lambda: perf_stats_etag(sample, realm=req_realm, range=req_range,
                                    since=req_since, until=req_until))


    def _get_pricing(self):
        if not self._authorized():
            return
        if PRICING:
            return self._json(200, PRICING.status())
        # 价格估算体系已下线（2026-10-22）：这里只回一个「不存在」的状态，
        # 面板不会再拉取价表，也不再显示任何折算金额。
        return self._json(200, {
            "interval_minutes": 0.0, "enabled": False, "running": False,
            "master_enabled": False,
            "policies": 0, "models": 0, "current": {}, "logs": [],
            "gaps": [], "gap_summary": {"total": 0, "or_missing": 0,
                                        "variant_unmatched": 0, "aliases": 0,
                                        "variants_enabled": False},
            "variant_inherit": False,
            "overrides_file": "", "policies_file": "", "timeline": "",
            "msg": "价格估算体系已移除，本网关只记积分",
        })

    def _get_settings(self):
        if not self._authorized():
            return
        return self._json(200, runtime_settings_view())

    def _get_updates(self):
        """What the running build is, and whether a newer stable release exists.

        Read-only and cheap: it reports the last check's outcome, never runs
        one. The panel's "check now" is the POST below.
        """
        if not self._authorized():
            return
        if UPDATES:
            return self._json(200, UPDATES.status())
        return self._json(200, {
            "current_version": running_version(),
            "latest_version": None, "update_available": False,
            "enabled": ca_settings.update_check_enabled(ACCOUNTS_DIR),
            "checking": False, "last_attempt": None, "last_success": None,
            "last_error": "", "release_url": "", "published_at": "",
            "msg": "更新检查未运行",
        })

    def _get_logs(self, query):
        if not self._authorized():
            return
        try:
            limit = int(query.get("limit", ["200"])[0])
        except (ValueError, TypeError):
            limit = 200
        level = query.get("level", [""])[0]
        tag = query.get("tag", [""])[0]
        search = query.get("search", [""])[0]
        try:
            since_id = int(query.get("since_id", ["0"])[0])
        except (ValueError, TypeError):
            since_id = 0
        result = get_logs(limit=limit, level=level, tag=tag, search=search, since_id=since_id)
        # 面板要据 mode 决定顶部文案（内存保留 vs 落库保留）与是否显示库容量，
        # 所以把模式与库统计一并带回；统计失败不该让整个日志请求失败。
        result["mode"] = "db" if _log_db_active() else "memory"
        if _log_db_active():
            try:
                stats = LOG_STORE.stats() or {}
            except Exception:
                stats = {}
            result["stored"] = stats.get("rows", 0)
            result["db_bytes"] = stats.get("bytes", 0)
        return self._json(200, result)

    def _get_logs_export(self):
        if not self._authorized():
            return
        log_data = get_logs(limit=5000)
        lines = [f"[{item['ts']}] [{item['level']}] [{item['tag']}] {item['msg']}" for item in log_data["logs"]]
        text_content = "\n".join(lines).encode("utf-8")
        filename = f"codearts-hub-{time.strftime('%Y%m%d-%H%M%S')}.log"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(text_content)))
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(text_content)
        return

    def _get_settings_reveal(self, query):
        # The panel only ever draws masked keys, so copying one needs an
        # explicit request. Panel session required, API key is not enough.
        if not self._panel_ok():
            return self._error(401, "panel password required", "invalid_request_error")
        wanted = (query.get("id") or [""])[0]
        try:
            entries = configured_keys()
        except Exception as exc:
            log("could not read api keys: %s" % exc)
            return self._error(503, "settings unreadable; cannot reveal key",
                               "server_error")
        for entry in entries:
            if entry.get("id") == wanted:
                return self._json(200, {"id": wanted, "key": entry.get("key") or ""})
        return self._error(404, "no such key", "invalid_request_error")

    def _dashboard(self):
        try:
            with open(DASHBOARD_HTML, "rb") as fh:
                body = fh.read()
        except Exception as exc:
            return self._error(500, f"dashboard.html unavailable: {exc}")
        # The static file carries a placeholder; replace it with the instance
        # default so the first paint already uses the right language.
        language = ca_settings.ui_language(ACCOUNTS_DIR)
        body = body.replace(
            b'data-ui-language="__WB_UI_LANGUAGE__"',
            ('data-ui-language="%s"' % language).encode("utf-8"),
        )
        # 面板首页是纯静态资源（服务端逐字节原样发出、不含任何机密），所以可以
        # 允许浏览器存储副本、每次打开再回源校验：校验命中回 304（无 body），
        # 省下整页（约 470KB）的重复下载，手机 / Tailscale 远程访问体感最明显。
        #
        # 校验符必须覆盖**所有**影响响应体的输入，不只是文件本身：body 还取决于
        # 上面注入的 ui_language——用户改一次界面语言，文件没动、body 却变了；
        # 若 tag 只看文件，客户端带旧 tag 回来会拿到 304 + 旧语言的页面。所以 tag
        # 由 (文件 mtime_ns, size, language) 三者派生：前两个代表文件字节（本文件
        # 只在应用更新时被整体替换、从不原地修改），第三个就是本次实际注入的值，
        # 三者组合变化 ⇔ 响应字节变化。mtime 用纳秒精度，同一秒内的两次替换也能
        # 得到不同 tag。
        etag = None
        try:
            st = os.stat(DASHBOARD_HTML)
            # 强校验符（不带 W/ 前缀）：响应是「文件字节 + 本次语言」的精确副本，
            # tag 变 ⇔ 字节变。
            etag = '"%x-%x-%s"' % (st.st_mtime_ns, st.st_size, language)
        except Exception:
            # stat 取不到（或时间戳无法表示）不是致命错误：退化为一律按普通
            # 200 处理，只是这一次没有条件请求支持，绝不让面板页本身打不开。
            etag = None
        # 只认 If-None-Match，不发送、也不理会 If-Modified-Since。Last-Modified
        # 只能描述文件的 mtime，而响应体还取决于语言：日期无法表达这个输入，
        # 一旦发布出去，偏好日期的客户端就会拿它校验，语言一变就拿到过期的
        # 304。ETag 覆盖全部输入、单靠它就足够完备，所以干脆不提供日期——
        # 不发布它，客户端就没有用它的理由（RFC 7232 §2.2 里 Last-Modified 只是
        # SHOULD，响应体并非单一文件、没有可一致表达的修改日期，只发 ETag 完备）。
        if etag is not None:
            inm = self.headers.get("If-None-Match")
            if inm is not None and _if_none_match_hit(inm, etag):
                # 304 不带 body：浏览器手里已有一份，一个字节都不用再传。也不带
                # Content-Length：304 按 RFC 7230 §3.3.3 在空行处结束，再报全量
                # 长度反而会诱使客户端 / 代理等待一个永远不会来的 body。校验符和
                # Cache-Control 必须原样重发（RFC 7232 §4.1），否则缓存会丢掉状态。
                self.send_response(304)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("ETag", etag)
                self.end_headers()
                return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # no-cache 而不是 no-store：允许存储，但每次使用前必须回源校验；配合
        # 上面的校验符，校验命中的代价是一次 304 而不是整页约 470KB。不加
        # max-age：没有它浏览器每次打开都会校验，应用更新后新版页面立即生效。
        self.send_header("Cache-Control", "no-cache")
        if etag is not None:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)
    def _read_chunked_body(self, max_bytes=MAX_PAYLOAD_BYTES):
        """Decode a Transfer-Encoding: chunked body into bytes.

        Some OpenAI-compatible clients stream large requests with chunked
        encoding instead of a Content-Length. Reading only Content-Length saw an
        empty body and answered 400 invalid JSON.
        """
        chunks = []
        total = 0
        while True:
            line = self.rfile.readline(65536)
            if not line:
                break
            size_field = line.split(b";", 1)[0].strip()
            if not size_field:
                continue
            try:
                size = int(size_field, 16)
            except ValueError:
                raise BadJSON()
            if size == 0:
                # Consume optional trailers up to the terminating blank line.
                while True:
                    trailer = self.rfile.readline(65536)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                break
            total += size
            if total > max_bytes:
                # Keep draining so the connection stays aligned, then refuse.
                self._drain_chunked_body()
                raise BodyTooLarge(total)
            remaining = size
            while remaining > 0:
                data = self.rfile.read(min(remaining, 65536))
                if not data:
                    raise BadJSON()
                chunks.append(data)
                remaining -= len(data)
            self.rfile.read(2)  # CRLF after the chunk data
        self._body_consumed = True
        return b"".join(chunks)
    def _read_payload(self, max_bytes=MAX_PAYLOAD_BYTES, allow_list=False):
        """Parse the request body into a dict (or a list when allow_list).
        Raises BodyTooLarge / BadJSON so every caller handles both cases the
        same way instead of each remembering to check for None.
        """
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        try:
            if "chunked" in transfer_encoding:
                raw_bytes = self._read_chunked_body(max_bytes=max_bytes)
                data = json.loads(raw_bytes.decode("utf-8", "replace") or "{}")
                if isinstance(data, dict):
                    return data
                if allow_list and isinstance(data, list):
                    return data
                return {}
            length = int(self.headers.get("Content-Length") or 0)
        except (BodyTooLarge, BadJSON):
            raise
        except Exception:
            raise BadJSON()
        if length > max_bytes:
            raise BodyTooLarge(length)
        if length < 0:
            raise BadJSON()
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            # Mark the body as taken so a later error reply does not try to
            # drain the same bytes again (that read would block forever).
            self._body_consumed = True
            data = json.loads(raw or "{}")
        except Exception:
            raise BadJSON()
        if isinstance(data, dict):
            return data
        if allow_list and isinstance(data, list):
            # The account-import endpoint accepts a bare array of accounts,
            # which is the most natural shape for a hand-written file.
            return data
        return {}
    def _payload_or_error(self, allow_list=False):
        """Read the body, replying with the right error and returning None."""
        try:
            return self._read_payload(allow_list=allow_list)
        except BodyTooLarge as exc:
            message = ("payload too large (%d bytes > %d limit)"
                       % (exc.length, MAX_PAYLOAD_BYTES))
            if self._anthropic_route():
                self._anthropic_error(413, message, "invalid_request_error")
            else:
                self._error(413, message, "invalid_request_error")
            return None
        except BadJSON:
            if self._anthropic_route():
                self._anthropic_error(400, "invalid JSON body", "invalid_request_error")
            else:
                self._error(400, "invalid JSON body", "invalid_request_error")
            return None
    def _anthropic_route(self):
        """True when the request path is one of the Anthropic Messages routes.

        Errors raised before the route dispatcher runs (body read, size cap)
        have to answer in the Anthropic envelope, or a Claude Code client sees
        an OpenAI-shaped error it cannot parse.
        """
        return self.path.split("?")[0] in (
            "/v1/messages", "/messages",
            "/v1/messages/count_tokens", "/messages/count_tokens",
        )
    def _handle_settings_save(self):
        """Persist panel-managed settings from the web settings tab.

        **先校验、后落盘**（2026-10-23）。以前是「边校验边写」：`api_keys`
        写完之后、`codearts` 校验失败返回 400 时，key 列表已经落盘了。面板
        看到的是一个失败的保存，磁盘上却是「一半生效」—— 用户以为没改成功，
        实际鉴权配置已经被换掉。现在两段式：`_validate_settings_patch()` 只
        算不写，全部通过之后才由 `_apply_settings_patch()` 写入。
        """
        payload = self._payload_or_error()
        if payload is None:
            return
        try:
            plan = _validate_settings_patch(payload)
        except _SettingsError as exc:
            return self._error(exc.status, exc.message, exc.err_type)
        return _apply_settings_patch(self, plan)

    def _handle_panel(self, path):
        """Panel login, logout and the settings screen (password + API key)."""
        payload = self._payload_or_error()
        if payload is None:
            return
        if path == "/panel/login":
            peer_ip = self.client_address[0] if hasattr(self, "client_address") and self.client_address else "127.0.0.1"
            # 限流键不能直接取对端地址：反代后对端是代理本身，见 login_rate_limit_key
            client_ip = login_rate_limit_key(peer_ip, getattr(self, "headers", None))
            now = time.time()
            with _login_lock:
                _prune_login_attempts(now)
                attempts = [t for t in _login_attempts.get(client_ip, []) if now - t < 60]
                if len(attempts) >= 5:
                    _login_attempts[client_ip] = attempts
                    wait_sec = int(60 - (now - attempts[0]))
                    return self._error(429, f"too many login attempts, please wait {max(1, wait_sec)}s", "rate_limit_error")
                # **先占位、后验密码**（2026-10-23）。以前是「查一次计数 → 放锁
                # 验密码 → 失败再加一」，中间那段空窗里有 0.5 秒反爆破睡眠：
                # 同一个 IP 并发 40 个错误密码，40 个请求都在计数为 0 时通过
                # 检查，全部 401，一次 429 都没有。计数必须在放锁之前落下。
                attempts.append(now)
                _login_attempts[client_ip] = attempts
            password = str(payload.get("password") or "")
            if not ca_settings.verify_panel_password(ACCOUNTS_DIR, password):
                # Small backoff delay to mitigate automated brute force
                time.sleep(0.5)
                return self._error(401, "invalid panel password", "invalid_request_error")
            with _login_lock:
                # 成功即清零：占位计入的是「尝试」，不能让正常用户攒到自己头上。
                _login_attempts.pop(client_ip, None)
            token = PANEL.create()
            return self._json(200, {
                "ok": True,
                "token": token,
                "using_default_password": ca_settings.panel_password_is_default(ACCOUNTS_DIR),
            })
        if path == "/panel/logout":
            PANEL.revoke(self._panel_token())
            return self._json(200, {"ok": True})
        # Everything past this point requires an authenticated panel session.
        if not self._panel_ok():
            return self._error(401, "panel password required", "invalid_request_error")
        if path == "/panel/password":
            current = str(payload.get("current") or "")
            new = str(payload.get("new") or "")
            if not ca_settings.verify_panel_password(ACCOUNTS_DIR, current):
                # 当前密码不对。这条 401 必须和「会话失效」区分开：以前前端
                # 把两者的 401 一起当掉线，令牌被清、登录闸门弹出来，错误
                # 文案还被 toast 的 'unauthorized' 过滤掉——用户看到的就是
                # 「点了修改，没提示，直接回到登录页」（2026-10-22 线上反馈）。
                # 前端现在用 localAuth 声明这条 401 不动会话，并把这段文案
                # 原样、持久地显示在表单下面。
                return self._error(
                    401,
                    "当前密码不正确，请重新输入；若忘了，可在服务端用 --panel-password-force 重置",
                    "invalid_request_error")
            if len(new) < 4:
                return self._error(400, "new password must be at least 4 characters", "invalid_request_error")
            if new == current:
                # 「改成一个一样的密码」是合法请求但什么都不变；如果回 200，
                # 用户会以为改成功了，然后拿旧密码去登录——正是「改完还是原来
                # 的密码」这种反馈。明确拒绝，让调用方看到原因。
                return self._error(
                    400,
                    "新密码不能与当前密码相同",
                    "invalid_request_error")
            # source='panel'：重启时不要再被 .credentials 的旧值覆盖
            ca_settings.set_panel_password(ACCOUNTS_DIR, new, source="panel")
            # 顺手把 .credentials 也改成新值，让「面板」与「启动参数」从此一致。
            # 失败（文件只读 / 不存在）也不算改密码失败：source=panel 已经保证
            # 重启后仍然是这个密码。只是下次运维改 .credentials 会显得没生效。
            env_file = ca_settings.env_password_path(os.path.dirname(
                os.path.abspath(__file__)))
            if new == ca_settings.DEFAULT_PANEL_PASSWORD:
                synced = False          # 默认密码不写进 env 文件
            else:
                synced = ca_settings.sync_env_password(env_file, new)
                if not synced:
                    log("panel      : could not sync %s, the new password still "
                        "survives restarts (panel source)" % env_file)
            # Rotating the password invalidates every browser session, including
            # this one: the dashboard must come back to the login gate and use
            # the new password. Handing out a fresh token here let the old tab
            # stay logged in, which looked like the change had not taken effect.
            PANEL.revoke_all()
            return self._json(200, {"ok": True, "synced_env": bool(synced)})
        return self._error(404, "not found", "invalid_request_error")
    def _handle_accounts(self, path, payload):
        """Account-management endpoints (dashboard uses these).

        WorkBuddy 池已移除（2026-10-23）：这里只剩码道的账号管理与几个与账号
        无关的面板动作（调度器、价格占位接口、日志清理）。
        """
        if path == "/accounts/codearts/login/start":
            return self._route_codearts_login_start(payload or {})
        if path == "/accounts/codearts/login/cancel":
            return self._route_codearts_login_cancel(payload or {})
        if path == "/accounts/codearts/login/callback":
            return self._route_codearts_login_callback(payload or {})
        if path == "/accounts/codearts/refresh":
            return self._route_codearts_refresh(payload or {})
        if path == "/accounts/codearts/refresh-catalog":
            return self._route_codearts_refresh_catalog(payload or {})
        if path == "/accounts/codearts/welfare/claim":
            return self._route_codearts_welfare_claim(payload or {})
        if path == "/accounts/codearts/delete":
            return self._route_codearts_delete(payload or {})
        if not isinstance(payload, dict):
            return self._error(400, "expected a JSON object", "invalid_request_error")
        if path == "/pricing/refresh":
            return self._route_pricing_refresh(payload)
        if path == "/logs/clear":
            return self._route_logs_clear(payload)
        return self._error(404, "unknown account endpoint", "invalid_request_error")


    def _route_update_check(self):
        """Run one release check now, on the operator's explicit request.

        Inline rather than "started, poll /updates": it is a single bounded
        GitHub request, and the answer is what the button is for. `manual=True`
        ignores both the daily switch and the 24h window.
        """
        if not UPDATES:
            return self._json(200, {"ok": False, "msg": "更新检查未运行"})
        status = UPDATES.check(manual=True)
        status["ok"] = True
        return self._json(200, status)

    def _route_pricing_refresh(self, payload):
        """价格估算体系已下线（2026-10-22），保留接口只为给出明确答复。"""
        return self._json(200, {"ok": False, "running": False,
                                "msg": "价格估算体系已移除，本网关只记积分"})


    def _route_logs_clear(self, payload):
        clear_logs()
        return self._json(200, {"ok": True})

    def _route_pricing_mapping(self, payload):
        """价格估算体系已下线（2026-10-22）。

        以前这里给面板手填「hub 模型 → OpenRouter id」的映射并触发取价。
        现在整套价格估算移除，接口保留为「明确拒绝」，避免前端拿到 404 后
        显示成网络错误。
        """
        return self._json(200, {"ok": False,
                                "msg": "价格估算体系已移除，本网关只记积分"})


    def _handle_responses(self, payload):
        """Serve /v1/responses by translating to chat completions upstream."""
        # The gateway is stateless: it keeps no store of previous responses,
        # so it cannot replay a prior turn. Silently ignoring the field would
        # answer a follow-up as if it were a fresh conversation - the client
        # gets a normal-looking reply with the context missing. Say so instead.
        if payload.get("previous_response_id"):
            return self._error(
                400,
                "previous_response_id is not supported: this gateway does not "
                "store response state. Send the full conversation in 'input' "
                "instead, or use a stateless client.",
                "invalid_request_error")
        # 工具可能在顶层，也可能整份在 input 的 additional_tools 条目里。回程
        # 的两处取值（custom_names 判定条目类型、request_meta 回显工具清单）
        # 必须和 responses_to_chat() 出站合并后的清单一致，否则两边看到的
        # 是不同工具集合，回程类型判错 → 客户端匹配不到执行器。
        all_tools = payload.get("tools")
        all_tools = list(all_tools) if isinstance(all_tools, list) else []
        all_tools.extend(additional_tools_from_input(payload))
        custom_names = custom_tool_names(all_tools)
        chat_req = responses_to_chat(payload)
        ns_map = chat_req.pop("_namespace_map", None)
        # Echo these back on the response object; see chat_to_response.
        request_meta = {
            "tools": all_tools,
            "tool_choice": payload.get("tool_choice", "auto"),
            "parallel_tool_calls": payload.get("parallel_tool_calls", True),
        }
        model = payload.get("model") or "deepseek-v4.1-flash"
        want_stream = bool(payload.get("stream"))
        log(
            "responses: model=%s stream=%s msgs=%d effort=%r tools=%d/%d custom_tools=%s"
            % (model, want_stream, len(chat_req.get("messages") or []),
               chat_req.get("reasoning_effort"),
               len(chat_req.get("tools") or []), len(all_tools),
               sorted(custom_names) or "-")
        )
        banned = self._banned_model_error(chat_req.get("model"))
        if banned:
            return self._error(400, banned, "invalid_request_error")
        key_blocked = self._key_model_error(chat_req.get("model"))
        if key_blocked:
            return self._error(400, key_blocked, "invalid_request_error")
        # 码道没有原生 Responses 端点（逆向本地客户端确认它只发
        # chat/completions 形状），这里用同一套翻译层桥接。
        if is_codearts_model(chat_req.get("model")):
            return self._responses_codearts(
                chat_req, want_stream, custom_names, request_meta, ns_map)
        # 网关只服务码道：别的名字一律 404，不回 503「没有可用账号」——
        # 那看起来像网关坏了，实际是这个部署不提供这个名字。
        return self._error(404, unserved_model_message(chat_req.get("model")),
                           "model_not_found")


    def _handle_messages_count_tokens(self, payload):
        """Best-effort Anthropic count_tokens endpoint.

        The WorkBuddy upstream has no Anthropic tokenizer. This estimate uses
        the same CJK-aware estimator as the gateway's own accounting and keeps
        the native response shape; it is intentionally not presented as an
        official model-token count.
        """
        try:
            chat = messages_to_chat(payload)
        except ValueError as exc:
            return self._anthropic_error(400, str(exc), "invalid_request_error")
        return self._json(200, {"input_tokens": _anthropic_estimate_chat_tokens(chat)})

    def _handle_messages(self, payload):
        """Serve an Anthropic Messages request through the chat pipeline."""
        try:
            chat_req = messages_to_chat(payload)
        except ValueError as exc:
            return self._anthropic_error(400, str(exc), "invalid_request_error")
        # Claude Code 发的模型名往往带日期后缀（claude-sonnet-4-5-20250929）
        # 或大小写与上游不同；归一只对认得出的码道模型生效。
        canonicalize_model(chat_req)
        model = chat_req.get("model") or "unknown"
        want_stream = bool(chat_req.get("stream"))
        log("messages: model=%s stream=%s msgs=%d effort=%r tools=%d"
            % (model, want_stream, len(chat_req.get("messages") or []),
               chat_req.get("reasoning_effort"), len(chat_req.get("tools") or [])))
        banned = self._banned_model_error(chat_req.get("model"))
        if banned:
            return self._anthropic_error(400, banned, "invalid_request_error")
        key_blocked = self._key_model_error(chat_req.get("model"))
        if key_blocked:
            return self._anthropic_error(400, key_blocked, "invalid_request_error")
        if is_codearts_model(chat_req.get("model")):
            return self._messages_codearts(chat_req, want_stream)
        return self._anthropic_error(
            404, unserved_model_message(chat_req.get("model")), "not_found_error")


    def do_POST(self):
        # 双 /v1 前缀兼容（OpenAI SDK 的 base_url 含 /v1、Anthropic SDK 不含，
        # 用户贴同一个地址必有一个多写一层）。见 collapse_duplicate_v1。
        path = collapse_duplicate_v1(self.path.split("?")[0])
        if path == "/settings/save":
            if not self._panel_ok():
                return self._error(401, "panel password required", "invalid_request_error")
            return self._handle_settings_save()
        if path == "/updates/check":
            # Panel-only management write, like the pricing ones. No body to
            # read: the action takes no parameters, so a button that posts
            # nothing must not be answered with "invalid JSON body".
            if not self._panel_ok():
                return self._error(401, "panel password required", "invalid_request_error")
            return self._route_update_check()
        if path in ("/pricing/refresh", "/pricing/mapping"):
            # Panel-only management writes (the pricing table is the panel's
            # own view of the estimate). Registered here because the generic
            # dispatcher below only routes chat and account paths - POST
            # /pricing/refresh used to 404, which made the panel's "立即取价"
            # button fail silently behind its toast.
            if not self._panel_ok():
                return self._error(401, "panel password required", "invalid_request_error")
            payload = self._payload_or_error()
            if payload is None:
                return
            if path == "/pricing/mapping":
                return self._route_pricing_mapping(payload)
            return self._route_pricing_refresh(payload)
        if path == "/catalog/refresh":
            # 旧面板的刷新按钮打的是这条（新面板已改打
            # /accounts/codearts/refresh-catalog）。以前这里调
            # ``self._route_catalog_refresh`` —— 那个方法**根本不存在**
            # （WorkBuddy 目录接口下线时被删了，路由却留着），于是点刷新
            # 直接 AttributeError，连接被掐断，面板看到的是「网络错误」
            # （2026-10-23）。转发到码道目录刷新，旧缓存页面也不会再撞墙。
            if not self._panel_ok():
                return self._error(401, "panel password required", "invalid_request_error")
            payload = self._payload_or_error()
            if payload is None:
                return
            return self._route_codearts_refresh_catalog(payload)
        if path in ("/panel/login", "/panel/logout", "/panel/password"):
            return self._handle_panel(path)
        if self._is_panel_route(path) and not self._panel_ok():
            return self._error(401, "panel password required", "invalid_request_error")
        is_messages_route = path in (
            "/v1/messages", "/messages",
            "/v1/messages/count_tokens", "/messages/count_tokens",
        )
        is_account_route = (
            path.startswith("/accounts/")
            or path == "/realm"
            or path.startswith("/logs")
        )
        if not is_account_route and not is_messages_route and path not in (
                "/v1/chat/completions", "/chat/completions",
                "/v1/completions", "/completions",
                "/v1/responses", "/responses"):
            return self._error(404, "not found", "invalid_request_error")
        if is_messages_route:
            if not self._key_ok():
                return self._anthropic_error(
                    401, "missing or invalid API key", "authentication_error")
        elif not self._authorized():
            return
        # Fail closed until the Anthropic-to-Chat bridge has verified prompt-cache
        # parity. Reject before forwarding or recording any paid usage.
        if is_messages_route and not _anthropic_messages_enabled():
            return self._anthropic_error(
                400,
                "Anthropic Messages is disabled by default: this gateway "
                "translates requests to Chat Completions and ignores "
                "cache_control. This can cause excessive credit consumption. "
                "Enable it in the Settings panel or set WB_ENABLE_ANTHROPIC_MESSAGES=1 "
                "to opt in at your own risk (see issue #367).",
                "invalid_request_error")
        payload = self._payload_or_error(allow_list=(path == "/accounts/import"))
        if payload is None:
            return
        if is_account_route:
            return self._handle_accounts(path, payload)
        # 优雅退出：SIGTERM 之后不再接新请求。这里回 503 而不是直接断连，
        # 客户端至少能看到「网关正在重启」并且知道要重试 —— 直接断连会被
        # 当成网络故障，触发一些客户端的退避重试策略。
        if shutting_down():
            return self._error(
                503, "gateway is restarting; retry in a few seconds",
                "server_error")
        _apply_background_model_alias(payload)
        # 在跑请求计数：SIGTERM 之后要等它们跑完再退（见 wait_for_inflight）。
        # 包住整段 chat 处理，异常也计数回来 —— 漏减会让退出永远等满 grace。
        request_started()
        # 请求 id 在这里落地：之后这条请求打出的每一行日志都自动带它。
        # 线程池里的线程会被下一个请求复用，所以 finally 里必须清掉，否则
        # 下一个请求的日志会顶着上一个请求的 id。
        set_request_id(new_request_id())
        try:
            return self._dispatch_chat_with_accounting(path, payload,
                                                       is_messages_route)
        finally:
            set_request_id("")
            request_finished()

    def _dispatch_chat_with_accounting(self, path, payload, is_messages_route):
        # Check per-key concurrency limit (#359)
        key_ok, cur_key_conc, max_key_conc = _acquire_key_slot(self.key_entry)
        if not key_ok:
            key_name = (self.key_entry or {}).get("name") or self._key_id() or "当前 Key"
            message = ("Rate limit reached: API key '%s' reached its concurrency limit (%d in flight); retry shortly"
                       % (key_name, max_key_conc))
            record_error(payload.get("model") or "unknown", 429, message,
                         stream=payload.get("stream"), key=self._key_id())
            if is_messages_route:
                return self._anthropic_error(429, message, "rate_limit_error")
            return self._error(429, message, "rate_limit_error")

        try:
            if is_messages_route:
                if path.endswith("/count_tokens"):
                    return self._handle_messages_count_tokens(payload)
                if not _chat_slots.acquire(timeout=CHAT_SLOT_WAIT_SECONDS):
                    message = ("gateway is at its concurrent chat limit "
                               "(%d in flight); retry shortly" % MAX_CONCURRENT_CHAT)
                    record_error(payload.get("model") or "unknown", 503, message,
                                 stream=payload.get("stream"), key=self._key_id())
                    return self._anthropic_error(503, message, "overloaded_error")
                try:
                    return self._handle_messages(payload)
                finally:
                    _chat_slots.release()
            # Both OpenAI-shaped routes below can hold a thread for up to 600s.
            # Take a slot for the duration; release it in finally so every early
            # return (including client disconnects) gives the slot back.
            if not _chat_slots.acquire(timeout=CHAT_SLOT_WAIT_SECONDS):
                # 这条分支以前**不记账**：本地排队满的请求在统计里完全消失
                # （既不算成功也不算失败），看起来像网关从没收到过它。
                message = ("gateway is at its concurrent chat limit "
                           "(%d in flight); retry shortly" % MAX_CONCURRENT_CHAT)
                record_error(payload.get("model") or "unknown", 503, message,
                             stream=payload.get("stream"), key=self._key_id())
                return self._error(503, message, "server_error")
            try:
                return self._dispatch_chat_post(path, payload)
            finally:
                _chat_slots.release()
        finally:
            _release_key_slot(self.key_entry)


    # ---- 码道模型：按模型名分流到华为云推理入口 ----
    def _client_disconnected(self):
        """下游客户端是不是已经把连接关了（或发了 FIN）。

        用在读上游的循环里：SSE 是一段段吐的，网关每读一块就问一次，发现对端
        走了就掐掉上游 —— 否则那个回答会一直被"读"下去，账号的并发会话名额
        （只有 3 个）就一直被一个没人要的请求占着。

        **只认 FIN，不认"有数据可读"**：HTTP/1.1 keep-alive 下客户端在处理期间
        发数据是异常行为，但把"有数据"当成断开会让正常的 pipelining 客户端
        被误杀。        所以 peek 到一个字节就返回 False，peek 到空字节（读到 EOF）
        才判断开。socket 已坏（对方 RST、本地已 close）一律按断开处理。

        **没有 connection 属性时返回 False**：单元测试的假 handler 就是这样，
        它没有真 socket，不能因此被判成「客户端已断开」—— 那样每个用例都会
        走进 aborted 分支，看起来像「角色归一坏了」。
        """
        try:
            sock = self.connection
        except AttributeError:
            return False
        try:
            readable, _, _ = select.select([sock], [], [], 0)
            if not readable:
                return False
            return not sock.recv(1, socket.MSG_PEEK)
        except (OSError, ValueError):
            return True

    def _codearts_no_slot(self, fail, model, t_start, anthropic=False):
        """拿不到名额时的统一答复：**先分清是哪种「没有」**。

        以前只有一条兜底：``gateway busy: every codearts account is at
        capacity``。三种完全不同的情况共用它，其中两种会骗人：

          · **池里没有可用号**（STS 全过期 / 没登录）→ 应该 503「去重新授权」，
            而 429「容量满，稍后重试」会让用户一直等一个永远不会好的东西；
          · **被面板日限额停掉** → 429 但原因是限额，不是并发；
          · **有号但都在冷却** → 429 是对的，但「at capacity」是错的：真实
            原因是刚才那次的失败还晾着。以前这里**不记账**，统计里一条都没有。

        返回 ``None`` 表示「其实有可用号，只是这次预算等不到冷却解冻」——
        调用方应退避后再试一轮，而不是直接回 429（见
        ``_CodeartsAccountPool.acquire`` 的预算说明：1041 的冷却 5 秒、重试
        预算 2 秒，单账号部署里第一轮退避后就被判成「永远没号」，于是每个
        请求都收到那条误导性的 429）。
        """
        if _CODEARTS_POOL.limits_blocked(model):
            msg = ("codearts daily limit reached: every account is parked by "
                   "the panel's daily token/credit limit; raise it in Settings "
                   "or wait for local midnight")
            record_error(model, 429, msg,
                         elapsed_ms=int((time.time() - t_start) * 1000),
                         key=self._key_id())
            return fail(429, msg, "rate_limit_error")
        if not _CODEARTS_POOL._usable():
            # 记账与响应同源：这条以前只回 503、**一行账都不落**，
            # 统计里看不到「没有账号」这个最常见的部署问题。
            msg = ("no usable codearts account (STS expired or not logged in); "
                   "re-authorize it in the panel")
            record_error(model, 503, msg,
                         elapsed_ms=int((time.time() - t_start) * 1000),
                         key=self._key_id())
            return fail(503, msg, "invalid_request_error")
        cooling = _CODEARTS_POOL.soonest_ready(model)
        if cooling > 0:
            # 还有号能用，只是都在冷却。冷却剩余可能远小于一次 acquire 的
            # 预算（1041 = 5 秒 vs 首轮 20 秒其实等得到；这里是预算被压到
            # 2 秒之后的那种情况），所以交给调用方退避再试 —— 只要退避总时
            # 长还够，就不该把用户挡在门外。
            if cooling <= sum(CODEARTS_RETRY_DELAYS):
                log("codearts all accounts cooling: model=%s next ready in "
                    "%.1fs; backing off" % (model, cooling))
                return None
            # 冷却比整套退避加起来还久（凭证失效 300 秒那种）：如实报。
            msg = ("all codearts accounts are cooling down after failures; "
                   "the earliest one is usable in %ds" % max(1, int(cooling)))
            record_error(model, 429, msg,
                         elapsed_ms=int((time.time() - t_start) * 1000),
                         key=self._key_id())
            return fail(429, msg, "rate_limit_error")
        log("codearts no slot: model=%s accounts=%s"
            % (model, _CODEARTS_POOL.snapshot()))
        msg = ("gateway busy: every codearts account is at capacity "
               "(%d per account); retry in a few seconds"
               % codearts_concurrency())
        record_error(model, 429, msg,
                     elapsed_ms=int((time.time() - t_start) * 1000),
                     key=self._key_id())
        return fail(429, msg, "rate_limit_error")

    def _codearts_chat_result(self, payload, want_stream=None, error_factory=None,
                              anthropic=False):
        """跑一次码道推理，把 SSE 聚合成结果。

        上游**只支持流式**（glm-5.3 传非流式直接 400 空响应体），所以这里
        统一按 stream=True 请求，客户端要非流式时由调用方聚合 —— 不把上游的
        形态限制泄漏给调用方。

        返回 (error, result)：失败时 error 是已构造好的响应元组；成功时
        result 带 content/reasoning/usage/raw，供 Chat / Responses / Messages
        三种协议各自渲染。error_factory 传对应协议的错误信封构造器（默认
        OpenAI），Messages 链路必须换成 Anthropic 的，否则 Claude Code 认不出
        错误体。
        """
        fail = error_factory or self._error
        model = str(payload.get("model") or "")
        # 角色名归一：OpenAI 的 chat 入口会带 "developer" 角色（Codex CLI 的
        # 系统提示就是这么发的），上游只认 system / user / assistant。
        # WorkBuddy 那条路走 build_upstream_body 时已经归一过一次，码道这条
        # 路是直通的，漏掉就会整条 400。正文一律不动 —— 多模态模型靠
        # content 里的图片分片表达。
        # 角色归一 + 消息修复。修复这一环以前只在 build_upstream_body
        # 里，而码道路径没有调用点 —— 孤立的 tool_call/tool_result、
        # 被拆开的并行批次、deepseek 思考模式缺 reasoning_content 都
        # 会原样送给上游（2026-10-23）。
        messages = repair_messages_for_upstream(
            ca_protocol.normalize_roles(payload.get("messages") or []),
            model)
        if want_stream is None:
            want_stream = bool(payload.get("stream"))
        # 输出上限走同一个口径（缺省 = 模型的目录值，负数/坏值按缺省）。
        # 以前这里自己再算一遍、写死 4096，于是 Chat 入口比 Messages /
        # Responses 少一大截额度。
        max_tokens = _codearts_max_tokens(payload)
        # 投影式 soft 裁剪（与流式路径同一套）。
        messages = prune_history_for_upstream(messages, model, max_tokens,
                                              source="chat-agg")

        t_start = time.time()
        status, text, last_exc = None, "", None
        account_label = None
        # 与流式路径同一个粘性口径（见 codearts_session_key）。
        sticky_key = codearts_session_key(getattr(self, "headers", None), payload)
        # 面板的超时与出口退避都是每请求读一次，不能落在重试环里。
        header_timeout, idle_timeout = upstream_timeouts()
        egress_on = ca_settings.egress_backoff_enabled(ACCOUNTS_DIR)
        egress_key = ca_upstream_pool.egress_key(ca_codearts.CHAT_PATH)
        # 每轮都重新向池子要号：失败时给这个号打冷却，下一轮自然换号。
        #
        # 分母随失败类型变化（名额满用短节奏 2/5/8，TPM 限流用长节奏
        # 5/12/25/40），所以日志里要标明是哪一套 —— 以前两条都写死 "N/3"，
        # 而 TPM 那条实际有四轮，读日志的人会以为第 3 次之后就不试了。
        delays = CODEARTS_BUSY_DELAYS
        delay_kind = "busy"
        attempt = 0
        while True:
            if self._client_disconnected():
                log("codearts aborted before retry: client gone model=%s" % model)
                return None, {"model": model, "content": "", "reasoning": "",
                              "usage": {}, "tool_calls": [], "raw": "",
                              "want_stream": bool(payload.get("stream")),
                              "aborted": True}
            wait = (CODEARTS_SLOT_WAIT if attempt == 0
                    else min(2.0, CODEARTS_SLOT_WAIT))
            session, account_key = _CODEARTS_POOL.acquire(
                wait, session_key=sticky_key, model=model)
            if session is None:
                err = self._codearts_no_slot(fail, model, t_start, anthropic)
                if err is not None:
                    return err, None
                # 池里其实有可用号，只是都在冷却、而这次预算等不到 ——
                # 用退避节奏再试一轮（以前会直接回 429，见函数内注释）。
                time.sleep(max(delays[attempt], 0.0))
                attempt += 1
                continue

            account_label = (session.get("account") or {}).get("label")
            # 与流式路径同一套会话生命周期：busy 登记 → 请求带 user-session-id
            # → 读完 idle 注销。聚合路径也要走，否则非流式请求照样漏名额。
            cred = (session.get("accessKey"), session.get("secretKey"),
                    session.get("securitytoken"))
            session_id, hb_ok, hb_detail = codearts_session_busy(
                cred, account_label, account_key=account_key)
            if not hb_ok:
                log("codearts session busy failed: %s" % hb_detail)
            try:
                # 思考开关：客户端给了 thinking / reasoning_effort 才透传，
                # 没给就沿用上游默认（保持旧行为不变）。
                # tools / tool_choice 必须一起送（上游原生支持 function
                # calling）；不送模型就看不到工具，只能编 <tool_call> 文本。
                status, text = ca_codearts.chat_for_model(
                    cred[0], cred[1], cred[2], model, messages,
                    max_tokens=max_tokens, stream=True,
                    timeout=header_timeout, idle_timeout=idle_timeout,
                    extra=_codearts_extra(payload, cred),
                    tools=payload.get("tools"),
                    tool_choice=payload.get("tool_choice"),
                    abort_check=self._client_disconnected,
                    session_id=session_id, session_retry=attempt)
                last_exc = None
                if status in (200, 201):
                    # 真的服务成功了才绑定会话：失败的那一轮可能刚被上游拒绝，
                    # 不该把这条对话钉在一个拒绝过它的号上。
                    _CODEARTS_POOL.remember(sticky_key, account_key)
                    if egress_on:
                        ca_egress.note_success(egress_key)
            except ca_codearts.ChatAborted:
                # 客户端已经走了：不再重试、不再写错误记录（这不是上游故障）。
                log("codearts aborted: client gone, upstream closed model=%s" % model)
                return None, {"model": model, "content": "", "reasoning": "",
                              "usage": {}, "tool_calls": [],
                              "raw": "", "want_stream": bool(payload.get("stream")),
                              "aborted": True}
            except Exception as exc:                 # noqa: BLE001
                status, text, last_exc = None, "", exc
            finally:
                # 先注销会话、再还本地名额：反过来的话，下一个拿到名额的请求
                # 可能在上游还没收到 idle 时就开始 busy，两个会话撞在一起。
                codearts_session_idle(cred, session_id)
                # 名额只包住「向上游要结果」这一段，读完了立刻还。
                _CODEARTS_POOL.release(account_key)
            retryable = last_exc is not None or ca_stream.retryable(status, text)
            if last_exc is None and status in (401, 403):
                # 凭据失效（STS 被吊销 / 过期没续上）**不是可重试错误** ——
                # 同一条请求再发一次还是 401，所以它进不了下面那个 if。
                # 但「这个号废了」这个结论必须留下来：冷却表就是下一轮挑号
                # 的依据。以前这条写在 `if retryable` 里面，而 401 恰好不
                # 可重试 —— 冷却永远不执行，吊销掉的号一直留在池子里被选中，
                # 有两个号时约一半请求报 credentials_error（2026-10-23）。
                # 冷却与「本次重不重试」是两件事：冷却讲的是下次怎么挑号，
                # 重试讲的是这一条要不要再发。
                _CODEARTS_POOL.penalize(account_key, CODEARTS_AUTH_COOLDOWN)
            if retryable and last_exc is None:
                if ca_stream.concurrency_full(status, text):
                    # 这个号的名额满了：晾几秒，下一轮换号
                    _CODEARTS_POOL.penalize(
                        account_key,
                        _codearts_seconds("busy_cooldown",
                                          CODEARTS_BUSY_COOLDOWN))
                    delays = CODEARTS_BUSY_DELAYS
                    delay_kind = "busy"
                elif status == 429 or "ModelArts.811" in (text or ""):
                    _CODEARTS_POOL.penalize(
                        account_key,
                        _codearts_seconds("tpm_cooldown",
                                          CODEARTS_TPM_COOLDOWN), model=model)
                    delays = CODEARTS_RETRY_DELAYS
                    delay_kind = "tpm"
            egress_wait = 0.0
            if egress_on and retryable and (
                    last_exc is not None or status in (502, 503, 504)):
                # 链路抖动记在出口上，不额外惩罚账号；退避是秒级，和原有的
                # 重试节奏取较大者，不叠成两段等待。
                egress_wait = min(ca_egress.note_transient(egress_key),
                                  EGRESS_SLEEP_MAX)
                log("codearts transient on the egress; backing off %.1fs"
                    % egress_wait)
            # 非流式的总时长上限：没有「首帧」承诺不等于可以无限重试。
            # 一次 0203 就 60s，5/12/25/40 的退避再加 4 轮首字节窗口，最坏
            # 4 分钟以上 —— 已经超过 ZCode 自己的 4 分钟超时（10-22 实测
            # 单个请求 346s / 405s，客户端早走了我们还在替它等）。
            #
            # **下一轮的退避 sleep 也必须算进去**（2026-10-23）。以前只算
            # 「还要再等一个首字节窗口」：TPM 退避是 5/12/25/40，实际执行到
            # 第 3 轮时耗时 5+12+窗口+12+窗口 ≈ 42s，预算 75s 看起来还装得下
            # 下一轮（+25s sleep +窗口 = 127s），于是硬撑到第 4 轮才停 ——
            # 真机 240 秒的总预算被用到 82 秒以上。sleep 是真花掉的时间，
            # 不算它就是算错了。
            expected = (min(header_timeout, 60.0)
                        if ca_stream.slow_failure(status, text, last_exc)
                        else CODEARTS_FAST_RETRY_COST)
            # 服务端给了退避提示（retry-after-ms/retry-after，见 open_chat
            # 的 [server-retry-after] 标记）就取较大者 —— 官方 rS 策略同款。
            server_wait = min(ca_stream.server_retry_after(text or ""), 60.0)
            next_sleep = (max(delays[attempt], egress_wait, server_wait)
                          if attempt < len(delays) else 0.0)
            if server_wait > 0 and next_sleep == server_wait:
                log("server retry-after hint: waiting %.0fs before the next "
                    "attempt" % server_wait)
            elapsed = time.time() - t_start
            need = expected + next_sleep
            if retryable and (elapsed > CODEARTS_TOTAL_BUDGET
                              or elapsed + need > CODEARTS_TOTAL_BUDGET):
                log("codearts total budget exhausted: model=%s %.0fs "
                    "(another attempt needs ~%.0fs: %.0fs backoff + ~%.0fs "
                    "upstream, budget %.0fs)"
                    % (model, elapsed, need, next_sleep, expected,
                       CODEARTS_TOTAL_BUDGET))
                retryable = False
            if not retryable or attempt >= len(delays):
                break
            log("codearts retry %d/%d (%s): model=%s acct=%s cause=%s"
                % (attempt + 1, len(delays), delay_kind, model, account_label,
                   (str(last_exc) if last_exc else (text or "")[:120])))
            time.sleep(next_sleep)
            attempt += 1

        if last_exc is not None:
            record_error(model, 502, str(last_exc)[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000),
                         account=account_label, key=self._key_id())
            return fail(502, "codearts unreachable: %s" % last_exc,
                        "upstream_error"), None

        if status not in (200, 201):
            code, detail = ca_stream.error_detail(text)
            # flow-control 429 附官方配额文案（一字不差抄 kernel 的 UK map）：
            # 客户端看到「今天额度用完了」比看到一串 error_code 有用得多。
            _fc = ca_stream.flow_control_from(text)
            if _fc is not None:
                _fc_msg = ca_stream.flow_control_message(_fc)
                if _fc_msg:
                    detail = ("%s | %s" % (detail, _fc_msg))[:200]
            st, _et = ca_stream.fail_spec(status, code, detail, anthropic)
            # 参数错（001001005）不说清是哪个参数，把形状留在日志里，
            # 下次才能区分「上下文太长 / max_tokens 越界 / 图片给了非多模态」。
            log("codearts request shape on failure: model=%s %s"
                % (model, _codearts_request_shape(payload, messages, max_tokens)))
            record_error(model, st, ("%s %s" % (code, detail))[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000),
                         account=account_label, key=self._key_id())
            # 限流 429（带 Retry-After）/ 凭据失效 / 参数错 400 / 模型不存在 404
            # / 其余 502 —— 同一张表，见 _codearts_fail_spec。
            return self._codearts_fail(status, code, detail, account_label,
                                       anthropic), None

        _tail = {}
        content, reasoning, usage, frame_err, tool_calls = ca_stream.collect_sse(
            text, _tail)
        if frame_err:
            # 有错误帧就是失败，**不看已经聚合出多少正文**。以前这里带了
            # `and not content and not reasoning and not tool_calls`：上游吐
            # 半截正文再塞一个错误帧时，会把拼出来的残句当正常结果回 200，
            # 客户端当完整回答用，账上记 completed。错误帧的意思只有一个 ——
            # 这一轮废了；半截正文留着只会让人误以为拿到了完整答案。
            _st, _et = ca_stream.frame_status(frame_err, anthropic)
            dump_failed_request(payload, messages, max_tokens)
            log("codearts stream finished with an error frame after %d chars: "
                "model=%s %s" % (len(content) + len(reasoning), model,
                                 frame_err[:160]))
            record_error(model, _st, frame_err[:200],
                         elapsed_ms=int((time.time() - t_start) * 1000),
                         account=account_label, usage=usage, stream=want_stream,
                         outcome="upstream_aborted", key=self._key_id())
            return fail(_st, "codearts error: %s" % frame_err, _et), None

        elapsed_ms = int((time.time() - t_start) * 1000)
        try:
            record_usage(model, usage, stream=want_stream,
                         elapsed_ms=elapsed_ms, account=account_label,
                         key=self._key_id(), outcome="completed")
        except Exception:
            pass

        return None, {
            "model": model,
            "content": content,
            "reasoning": reasoning,
            "usage": usage,
            "tool_calls": tool_calls,
            "raw": text,
            "want_stream": want_stream,
            # 上游的收尾原因（stop / length / tool_calls）。非流式渲染必须
            # 透传它：截断（length）被写成 stop 的话，客户端会把半截回答
            # 当完整结果，截断的工具参数还会当成完整 JSON 去解析。
            "finish_reason": _tail.get("finish_reason") or "",
        }

    def _reply_deferred(self, exc):
        """把 ``_DeferredHTTPError`` 写成响应（头还没发出去的场合）。

        ``_codearts_open_lease(defer_errors=True)`` 不做写操作，只把决定抛回来；
        真正写哪个信封由这里定 —— Anthropic 入口要 anthropic 的，其余要
        OpenAI 的。429 仍走 ``_rate_limited``（带 Retry-After）。
        """
        if exc.anthropic:
            return self._anthropic_error(exc.status, exc.message, exc.err_type)
        return self._error(exc.status, exc.message, exc.err_type,
                           retry_after=exc.retry_after)

    def _codearts_open_lease(self, payload, model, messages, max_tokens,
                             fail=None, anthropic=False, defer_errors=False):
        """拿**某个账号**的并发名额 + 建连（含重试与换号）。

        三种结果：
          · ``(error, None)`` —— 已经回过响应，调用方直接 return error；
          · ``(None, None)``  —— 客户端在等待期间走了，调用方直接 return None；
          · ``(None, lease)`` —— **调用方必须在 finally 里 lease.close()**。

        ``defer_errors=True`` 时改抛 ``_DeferredHTTPError`` 而不是自己写响应：
        那条路径可能在「断流重开」里被调用，此时 200 和 SSE 头**已经发出去**
        了，再写一个完整 HTTP 错误就会插进 SSE 流里（见 ``_DeferredHTTPError``）。
        调用方拿到异常后按「有没有发过头」二选一。

        每一轮重试都重新向池子要号：失败时先给这个号打冷却（并发满 5s、
        TPM 20s、授权错 300s），下一轮挑号自然就跳到别的账号去了。这就是
        多账号的故障转移 —— 不需要额外的分支，冷却表本身就是转移依据。

        重试只发生在还没给客户端发过任何字节之前。一旦开始转发，头部已经
        承诺 200，就没有干净的退路了 —— 那时出错只能作为帧内事件告知。

        **每一轮都会向上游登记一条会话**（`heartbeat busy` + 请求头带
        `user-session-id`）。这不是可选项：上游的并发闸不认「请求结束」，
        不 busy/idle 就只会在服务端超时时才回收，3 个名额会莫名其妙被占满
        （见 ca_codearts.HEARTBEAT_PATH 的注释）。建连失败时立刻 idle 掉刚
        busy 的那个 id，避免留下半开会话。
        """
        fail = fail or self._error
        t_start = time.time()
        status, text, last_exc = None, "", None
        account_label = None

        def _reply(code, message, err_type, retry_after=None):
            """失败出口：要么写响应（旧行为），要么把决定抛给调用方。"""
            if defer_errors:
                raise _DeferredHTTPError(code, message, err_type, retry_after,
                                         anthropic=anthropic)
            return fail(code, message, err_type)
        # 这条对话的稳定标识：多账号时让同一对话的每一轮尽量落在同一个号上
        # （上游 prompt cache 是按机器存的，换号等于前缀缓存全丢）。
        sticky_key = codearts_session_key(getattr(self, "headers", None), payload)
        # 与聚合路径同一口径：超时、出口退避每请求只读一次。
        header_timeout, idle_timeout = upstream_timeouts()
        egress_on = ca_settings.egress_backoff_enabled(ACCOUNTS_DIR)
        egress_key = ca_upstream_pool.egress_key(ca_codearts.CHAT_PATH)
        delays = CODEARTS_BUSY_DELAYS      # 先按「名额满」的短节奏
        delay_kind = "busy"
        attempt = 0
        while True:
            if self._client_disconnected():
                log("codearts aborted before open: client gone model=%s" % model)
                return None, None

            # 首轮等满（可能是真排队），后续轮等短一点：重试阶段要的是「快点
            # 换个号试试」，不是继续占着排队位置。
            wait = CODEARTS_SLOT_WAIT if attempt == 0 else min(
                2.0, CODEARTS_SLOT_WAIT)
            session, key = _CODEARTS_POOL.acquire(
                wait, session_key=sticky_key, model=model)
            if session is None:
                err = self._codearts_no_slot(_reply, model, t_start, anthropic)
                if err is not None:
                    return err, None
                # 有号、都在冷却，且冷却比这次预算短：退避一轮再看（与聚合
                # 路径同一口径，见 _codearts_no_slot）。
                time.sleep(max(delays[attempt], 0.0))
                attempt += 1
                continue

            account_label = (session.get("account") or {}).get("label")
            # 先向上游登记一条会话（busy），再带着同一个 user-session-id 发请求。
            # 不登记的话，每个请求都会让上游**隐式开一条永不注销的会话** ——
            # 3 个名额很快占满，之后一律 TM.00001041（2026-10-22 事故：客户端
            # 连接早断了，上游那边的会话还挂着）。
            cred = (session.get("accessKey"), session.get("secretKey"),
                    session.get("securitytoken"))
            session_id, hb_ok, hb_detail = codearts_session_busy(
                cred, account_label, account_key=key)
            if not hb_ok:
                # 登记失败**不阻断**：心跳是保命手段，不是前置条件。真拿不到
                # 名额时 open_chat 会回 1041，走下面的重试 / 换号。
                log("codearts session busy failed: %s" % hb_detail)
            try:
                status, resp, text = ca_codearts.open_chat(
                    cred[0], cred[1], cred[2], model, messages,
                    max_tokens=max_tokens, stream=True,
                    timeout=header_timeout, idle_timeout=idle_timeout,
                    extra=_codearts_extra(payload, cred),
                    tools=payload.get("tools"),
                    tool_choice=payload.get("tool_choice"),
                    session_id=session_id, session_retry=attempt)
                last_exc = None
            except Exception as exc:            # noqa: BLE001
                status, resp, text, last_exc = None, None, "", exc

            if resp is not None:
                # 建连成功才记粘性：失败的那一轮不该把这条对话绑到一个
                # 刚刚拒绝过我们的号上。
                _CODEARTS_POOL.remember(sticky_key, key)
                if egress_on:
                    ca_egress.note_success(egress_key)
                return None, _CodeartsLease(resp, account_label, t_start, key,
                                            session_id=session_id,
                                            session_cred=cred,
                                            idle_timeout=_codearts_stream_idle(),
                                            max_idle=_codearts_stream_max_idle())
            # 没拿到句柄：刚 busy 的那个 id 要立刻注销（哪怕 busy 本身没成）。
            # 不注销，上游可能已经记成半开会话，白占一个名额。
            codearts_session_idle(cred, session_id)

            # 这一轮失败：先把名额还掉，再决定是换号重试还是放弃。
            _CODEARTS_POOL.release(key)

            retryable = last_exc is not None or ca_stream.retryable(status, text)
            if last_exc is None and status in (401, 403):
                # 见上一条注释（聚合路径同口径）：凭据失效冷却与「这一条要不要
                # 重试」是两件事。401 不可重试，但那个号必须被晾起来，否则
                # 每一轮挑号都可能再选中它。
                _CODEARTS_POOL.penalize(key, CODEARTS_AUTH_COOLDOWN)
            if retryable and last_exc is None:
                if ca_stream.concurrency_full(status, text):
                    _CODEARTS_POOL.penalize(
                        key, _codearts_seconds("busy_cooldown",
                                               CODEARTS_BUSY_COOLDOWN))
                    delays = CODEARTS_BUSY_DELAYS
                    delay_kind = "busy"
                elif status == 429 or "ModelArts.811" in (text or ""):
                    _CODEARTS_POOL.penalize(
                        key, _codearts_seconds("tpm_cooldown",
                                               CODEARTS_TPM_COOLDOWN),
                        model=model)
                    delays = CODEARTS_RETRY_DELAYS
                    delay_kind = "tpm"
            egress_wait = 0.0
            if egress_on and retryable and (
                    last_exc is not None or status in (502, 503, 504)):
                # 与聚合路径同一口径：链路抖动记在出口上，不额外惩罚账号；
                # 退避秒级，和原有重试节奏取较大者，不叠成两段等待。
                egress_wait = min(ca_egress.note_transient(egress_key),
                                  EGRESS_SLEEP_MAX)
                log("codearts transient on the egress; backing off %.1fs"
                    % egress_wait)
            # 流式请求的建连重试有总预算：一次 APIG Backend timeout 就 60s，
            # 再试一轮客户端早走了（而且走了我们还在替它占着会话）。
            #
            # 关键是要**在开始下一轮之前**算清它装不装得下：只判断「已经花了
            # 多久」时，第 1 轮 60s（< 75s 预算）会放行第 2 轮，再跑 60s ——
            # 客户端要等 130s 才拿到 504（线上实测两次）。按「再来一轮至少要
            # 一个首字节窗口」预估，第 1 轮失败后就该停。
            # 预估「再来一轮要多久」不能一律按 60 秒：1041（并发会话满）与
            # 429（TPM 限流）都是**立刻**返回的，把它们也按 60 秒算，会让
            # 15 秒之后的每一次重试都被判成「装不下」—— 设计上 4 次的 TPM
            # 退避实际只能用 2 次。只有真正会等到首字节超时的失败（5xx /
            # 网络异常 / APIG.0203）才该按满窗口估。
            expected = (min(header_timeout, 60.0)
                        if ca_stream.slow_failure(status, text, last_exc)
                        else CODEARTS_FAST_RETRY_COST)
            # 同聚合路径：下一轮的退避 sleep 也要算，否则 75 秒的预算会被
            # 12/25/40 这些 sleep 一路撑过去（真机到 82 秒以上才停）。
            # 同聚合路径：服务端退避提示取较大者（官方 rS 策略同款）。
            server_wait = min(ca_stream.server_retry_after(text or ""), 60.0)
            next_sleep = (max(delays[attempt], egress_wait, server_wait)
                          if attempt < len(delays) else 0.0)
            if server_wait > 0 and next_sleep == server_wait:
                log("server retry-after hint: waiting %.0fs before the next "
                    "attempt" % server_wait)
            elapsed = time.time() - t_start
            need = expected + next_sleep
            if (retryable and payload.get("stream")
                    and (elapsed > CODEARTS_OPEN_BUDGET
                         or elapsed + need > CODEARTS_OPEN_BUDGET)):
                log("codearts open budget exhausted: model=%s %.0fs "
                    "(another attempt needs ~%.0fs: %.0fs backoff + ~%.0fs "
                    "upstream, budget %.0fs) shape=%s"
                    % (model, elapsed, need, next_sleep, expected,
                       CODEARTS_OPEN_BUDGET,
                       _codearts_request_shape(payload, messages, max_tokens)))
                retryable = False
            if not retryable or attempt >= len(delays):
                break
            log("codearts open retry %d/%d (%s): model=%s acct=%s cause=%s shape=%s"
                % (attempt + 1, len(delays), delay_kind, model, account_label,
                   (str(last_exc) if last_exc else (text or "")[:120]),
                   _codearts_request_shape(payload, messages, max_tokens)))
            time.sleep(next_sleep)
            attempt += 1

        elapsed_ms = int((time.time() - t_start) * 1000)
        if last_exc is not None:
            record_error(model, 502, str(last_exc)[:200],
                         elapsed_ms=elapsed_ms, account=account_label,
                         key=self._key_id())
            return _reply(502, "codearts unreachable: %s" % last_exc,
                          "upstream_error"), None

        code, detail = ca_stream.error_detail(text)
        # flow-control 429 附官方配额文案（一字不差抄 kernel 的 UK map）：
        # 客户端看到「今天额度用完了」比看到一串 error_code 有用得多。
        _fc = ca_stream.flow_control_from(text)
        if _fc is not None:
            _fc_msg = ca_stream.flow_control_message(_fc)
            if _fc_msg:
                detail = ("%s | %s" % (detail, _fc_msg))[:200]
        log("codearts request shape on failure: model=%s %s"
            % (model, _codearts_request_shape(payload, messages, max_tokens)))
        # 记账必须和回给客户端的状态码同源：以前这里写死 502，而
        # _codearts_fail 会按表把 APIG.0203 映射成 504 —— gw.log 与
        # usage.jsonl 记 502、客户端收 504，同一个失败两个答案。
        st, _et = ca_stream.fail_spec(status, code, detail, anthropic)
        dump_failed_request(payload, messages, max_tokens)
        record_error(model, st, ("%s %s" % (code, detail))[:200],
                     elapsed_ms=elapsed_ms, account=account_label,
                     key=self._key_id())
        # 按语义映射，见 _codearts_fail_spec：限流 429（带 Retry-After）、
        # 凭据失效 credentials_error、参数错 400、模型不存在 404、其余 502。
        # 以前这里一律 502 upstream_error，参数错误会被客户端当网关抖动重试。
        if defer_errors:
            # 上游状态码 → 客户端状态码的映射已经在上面（fail_spec）走过一遍，
            # 这里连带把它算出来的文案一起带给调用方，别让它在「发过头」的
            # 情况下再去猜该写什么。
            msg = "codearts %s: %s" % (code or "error", detail or "")
            if account_label:
                msg += " (account %s)" % account_label
            raise _DeferredHTTPError(st, msg, _et, anthropic=anthropic)
        return self._codearts_fail(status, code, detail, account_label,
                                   anthropic), None

    def _handle_codearts_chat_stream(self, payload):
        """把码道的 SSE **边收边转**给客户端。

        这是「转圈几分钟，然后一次性刷出全文」的解药。老路径
        （``_codearts_chat_result``）要等上游把整条流吐完才回放，客户端在整个
        生成期间收不到一个字节 —— 一条三千字的回答按 25 tok/s 算要两分钟，
        客户端只看得到转圈，还可能触发自己的空闲超时（ZCode 4 分钟）后重试，
        而重试会**再开一个上游会话**，几个叠起来就把账号的 3 个并发名额吃干净
        （2026-10-22 事故）。

        这里改成逐帧转发：客户端几秒内看到首字，上游吐完即结束、名额立刻释放；
        客户端中途断开时 iter_sse 的 abort_check 会抛 ChatAborted，finally 里
        lease.close() 关掉上游连接 → 上游立刻回收会话。

        **200 头推迟到第一帧才发**（照 CodeArts2API-Go 的 ``started``、
        Coding2API 的 ``emitted``）：首帧之前失败还能回一个干净的错误码，客户端
        会按正常失败重试；一旦发过头就只能靠帧内错误收尾。首帧之后若上游把
        chunked 流掐断（``UpstreamBroken``），绝不能让异常冒到 socketserver ——
        那就是「半截回答 + 连接凭空消失」。
        """
        model = str(payload.get("model") or "")
        # 角色归一 + 消息修复。修复这一环以前只在 build_upstream_body
        # 里，而码道路径没有调用点 —— 孤立的 tool_call/tool_result、
        # 被拆开的并行批次、deepseek 思考模式缺 reasoning_content 都
        # 会原样送给上游（2026-10-23）。
        messages = repair_messages_for_upstream(
            ca_protocol.normalize_roles(payload.get("messages") or []),
            model)
        max_tokens = _codearts_max_tokens(payload)
        # 投影式 soft 裁剪：压力大时保护窗之外的大工具结果换成占位符（只影响
        # 本次发上游的消息，入参列表不动）。
        messages = prune_history_for_upstream(messages, model, max_tokens,
                                              source="chat")
        created = int(time.time())
        cid = "chatcmpl-codearts-%s" % uuid.uuid4().hex[:24]
        t_start = time.time()

        content_parts, reasoning_parts, tool_parts = [], [], []
        usage, finish_reason, frame_err, truncated = {}, None, "", ""
        account_label = None
        account_key = None
        headers_sent = False
        restarts = 0

        def emit(obj):
            blob = "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"
            self.wfile.write(blob.encode("utf-8"))
            self.wfile.flush()

        def frame(delta, finish=None, extra=None):
            body = {"id": cid, "object": "chat.completion.chunk",
                    "created": created, "model": model,
                    "choices": [{"index": 0, "delta": delta,
                                 "finish_reason": finish}]}
            if extra:
                body.update(extra)
            return body

        def send_headers():
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            # nginx 默认会攒够一缓冲区才往下发，SSE 就变成「还是一坨」。
            # 这个头让 nginx 对我们这个响应关掉缓冲（默认 honor）。
            self.send_header("X-Accel-Buffering", "no")
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

        while True:
            try:
                error, lease = self._codearts_open_lease(
                    payload, model, messages, max_tokens, defer_errors=True)
            except _DeferredHTTPError as exc:
                # 建连失败。**只有一次建连（还没发过头）才回状态码**；重开那一轮
                # 头早就 200 了，只能写本协议的错误帧 —— 以前这里会再写一个完整
                # 的 HTTP 503，状态行直接插进 SSE 流里（2026-10-23）。
                if not headers_sent:
                    return self._reply_deferred(exc)
                log("codearts stream gave up after restart: model=%s %s"
                    % (model, exc.message))
                try:
                    emit({"error": {"message": exc.message,
                                    "type": "upstream_error", "code": 502}})
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError,
                        ConnectionAbortedError):
                    pass
                return None
            if error is not None:
                if not headers_sent:
                    return error
                # 只可能发生在「断流后重开」这一轮：头早就 200 了，回不了 JSON。
                log("codearts stream gave up after restart: model=%s" % model)
                try:
                    emit({"error": {"message": "codearts upstream unavailable",
                                    "type": "upstream_error", "code": 502}})
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError,
                        ConnectionAbortedError):
                    pass
                return None
            if lease is None:
                return None      # 客户端已经走了

            #: 这一轮读循环是不是「正常收尾」（没有错误帧、没有断流）。
            #: **必须由本轮自己在 finally 执行之前置位**：以前用的是循环外的
            #: ``hold_slot``，而它在 ``finally`` 里读到的永远是上一轮留下的
            #: False —— 那段判断等于死代码，名额（含最长 6 秒的同步 idle）
            #: 照样在 ``[DONE]`` 之前还，客户端白等（2026-10-23）。
            finished_normally = False

            account_label = lease.account_label
            account_key = lease.account_key
            # 成功的请求以前不留形状，出问题时无从对比「同样 30KB 上下文，
            # 为什么这次过了、那次没过」。一行一次，和 chat done 同量级。
            log("chat stream open: model=%s acct=%s %s"
                % (model, account_label,
                   _codearts_request_shape(payload, messages, max_tokens)))
            # 断流时把「已经收了多少字节、断之前静默了多久、心跳有没有真
            # 发出去、socket 拿没拿到」一起打出来 —— 这四项能区分「上游好好的
            # 被中间层掐了」「上游自己回收了会话」和「我们根本没在续期」。
            stream_stats = {}
            try:
                try:
                    for line in lease.lines(self._client_disconnected,
                                            stream_stats):
                        if line is ca_codearts.KEEPALIVE:
                            # 上游在思考、一个字都没吐。首帧前不能发（还没承诺
                            # 200，那时失败要能回错误码），首帧后发一条 SSE 注释
                            # 让中间层看到连接还活着。
                            if headers_sent:
                                try:
                                    self.wfile.write(b": keepalive\n\n")
                                    self.wfile.flush()
                                except (BrokenPipeError, ConnectionResetError,
                                        ConnectionAbortedError):
                                    return None
                            continue
                        if not line.startswith("data:"):
                            continue
                        raw = line[5:].strip()
                        if not raw or raw == "[DONE]":
                            continue
                        try:
                            piece = json.loads(raw)
                        except Exception:
                            continue
                        # 两种错误形状都认：error_code（码道）与 {"error":…}
                        # （OpenAI 兼容层）。判据只有一个 —— 这一轮已经废了。
                        frame_bad = ca_stream.frame_error(piece)
                        if frame_bad:
                            frame_err = frame_bad
                            break
                        if isinstance(piece.get("usage"), dict):
                            usage = piece["usage"]
                        if not headers_sent:
                            # 收到上游第一帧才提交 200 + SSE 头。在这之前失败，
                            # 还能回一个干净的错误码让客户端自己重试 —— Go 版
                            # CodeArts2API 的 started、Coding2API 的 emitted 都是
                            # 这个口径。头一发出去，就只剩「帧内错误」这一条退路。
                            try:
                                send_headers()
                                headers_sent = True
                                emit(frame({"role": "assistant", "content": ""}))
                            except (BrokenPipeError, ConnectionResetError,
                                    ConnectionAbortedError):
                                return None
                        bad_finish = False
                        for choice in piece.get("choices") or []:
                            delta = choice.get("delta") or {}
                            if delta.get("content"):
                                content_parts.append(delta["content"])
                            if delta.get("reasoning_content"):
                                reasoning_parts.append(delta["reasoning_content"])
                            # 工具调用也是「已经给客户端的东西」，而且是最不能
                            # 拼的那种：客户端按 index 归并同一个调用的参数分片。
                            # 断在半路后重开，新流又从 index=0 发同一个调用，
                            # 两段参数首尾相接 —— 半截 {"path": "a"} 接上重开的
                            # {"path": "a"} 就是坏 JSON，客户端解析失败。
                            # 以前这里只数 content / reasoning，重开条件对工具
                            # 调用视而不见（2026-10-23 复现）。
                            if delta.get("tool_calls"):
                                tool_parts.append(delta["tool_calls"])
                            # finish_reason=error 也是失败。以前只有 WorkBuddy
                            # 那条路认（#389），码道这侧会把它原样转发、再补一个
                            # 同样的 finish_reason 并记成 completed。
                            choice_finish = choice.get("finish_reason")
                            if ca_stream.finish_error(choice):
                                bad_finish = True
                                choice_finish = None
                            elif choice_finish:
                                finish_reason = choice_finish
                            if delta:
                                # 原样转发 delta：reasoning_content 与
                                # tool_calls（含各自的 index）都在里面，
                                # 自己重拼反而容易漏字段。
                                emit(frame(delta, choice_finish))
                        if bad_finish:
                            frame_err = frame_err or \
                                "upstream finished with finish_reason=error"
                            break
                except ca_codearts.ChatAborted:
                    log("codearts stream aborted: client gone model=%s" % model)
                    return None
                except ca_codearts.UpstreamBroken as exc:
                    # 上游把 chunked 流掐了（没写终止块）。**绝不能让它冒出去**：
                    # 头已经是 200，异常会一路冒到 socketserver，客户端拿到的就是
                    # 「半截回答 + 连接凭空消失」—— 既没有 finish_reason 也没有
                    # [DONE]，也就是用户说的「直接断流」。
                    truncated = str(exc)
                    log("codearts stream broken: model=%s after %dms %s "
                        "(bytes=%d silent=%.1fs pings=%d sock=%s) shape=%s"
                        % (model, int((time.time() - t_start) * 1000), exc,
                           stream_stats.get("bytes", 0),
                           stream_stats.get("silent_s", 0.0),
                           stream_stats.get("pings", 0),
                           stream_stats.get("sock"),
                           _codearts_request_shape(payload, messages, max_tokens)))
                except (BrokenPipeError, ConnectionResetError,
                        ConnectionAbortedError):
                    log("codearts stream closed by client model=%s" % model)
                    return None
                # 读循环跑到底、没有错误帧、没有断流、而且这一轮真的给客户端
                # 发过东西：本轮是正常收尾，名额留到 [DONE] 之后。
                # **必须连 headers_sent 一起判**：上游一帧都不给就干净关闭时，
                # 下面走的是「回错误码」而不是 [DONE]，名额若被留在这里就永远
                # 不会还（每个这种请求泄漏一个并发名额）。
                finished_normally = (not truncated and not frame_err
                                     and headers_sent)
            finally:
                # 先关上游连接（上游立刻回收会话）。
                lease.close_upstream()
                # 名额在这里先还掉。唯一的例外是「正常收尾」：那种情况下面
                # 还要写 finish 帧 + [DONE]，而 idle 是同步 HTTP（最长 6 秒），
                # 排在 [DONE] 之前就是让客户端白等 —— 见下面的 done_lease。
                if not finished_normally:
                    lease.release_slot()

            # 上游断了，但一个字都还没给客户端（只发过那个空的 role 帧）：
            # 换号重开一条，对客户端完全无感。**吐过内容就不能重开** —— 两段
            # 回答拼在一起比断流更难排查，而且上下文已经和第一次不同了。
            # tool_parts 也要算「吐过」：客户端按 index 归并工具调用的参数分片，
            # 重开的流又从 index=0 发同一个调用，两段参数会粘成坏 JSON。
            if (truncated and not content_parts and not reasoning_parts
                    and not tool_parts
                    and not frame_err
                    and restarts < CODEARTS_STREAM_RESTARTS
                    and (time.time() - t_start) < CODEARTS_STREAM_RESTART_BUDGET
                    and not self._client_disconnected()):
                restarts += 1
                # 这个号刚把连接掐了：晾一下再看，池子里有别的号就换过去。
                # 与 Go 版 CodeArts2API 的 withAccountRetry 同口径 —— 首帧前的
                # 失败算「这个号这次不行」，不该让同一个号连撞。
                if account_key:
                    _CODEARTS_POOL.penalize(
                        account_key,
                        _codearts_seconds("busy_cooldown",
                                          CODEARTS_BUSY_COOLDOWN))
                log("codearts stream restart %d/%d: model=%s reason=%s"
                    % (restarts, CODEARTS_STREAM_RESTARTS, model, truncated))
                truncated = ""
                continue
            # 走到这里说明这一轮是「正常收尾」（没有断流、没有错误帧）：
            # 名额延后到 [DONE] 写完再还 —— 读循环的 finally 已经置过
            # finished_normally，这里只把 lease 留到最后用。
            done_lease = lease
            break

        elapsed_ms = int((time.time() - t_start) * 1000)
        if not headers_sent:
            # 一帧有效数据都没接到（上游连上就断、或上来就是一个错误帧）：
            # 头还没发出去，能回干净的错误码让客户端按正常失败重试 ——
            # 比「200 + 半截流」诚实得多。
            reason = frame_err or truncated or "upstream returned no frames"
            code, err_type = ca_stream.frame_status(reason)
            record_error(model, code, reason[:200], elapsed_ms=elapsed_ms,
                         account=account_label, key=self._key_id())
            return self._error(code, "codearts error: %s" % reason, err_type)

        if frame_err:
            # 错误帧压过一切：不管之前吐没吐过内容，都不能再补 finish_reason
            # 收尾。以前这里只有 "and not content_parts and not reasoning_parts"
            # 一个分支，**出过内容时没有任何分支接住 frame_err** —— 直接落到
            # 下面的 `finish_reason or "stop"` + [DONE]，客户端把半截回答当完整
            # 结果，账上记成 completed（2026-10-23 复现：先发 content 再发
            # ModelArts.81101，客户端收到 200 + stop + [DONE]，usage.jsonl 只有
            # 一条 completed）。正是注释里说要避免的「给半截回答盖章」。
            #
            # 状态码仍过 `frame_status` 那张表：真被限流（1041 / 811xx）就该让
            # 客户端看到 429，而不是一个笼统的 502。
            code, err_type = ca_stream.frame_status(frame_err)
            partial = bool(content_parts or reasoning_parts)
            if partial:
                # 断在半路：和断流一样留一份请求形状，否则这条失败无从归因。
                dump_failed_request(payload, messages, max_tokens)
            # 一次失败只写一行：usage 跟着 record_error 落，别在下面再
            # record_usage 一次（那会让同一请求既算失败又算用量，总量翻倍）。
            record_error(model, code, frame_err[:200], elapsed_ms=elapsed_ms,
                         account=account_label, usage=usage, stream=True,
                         outcome="upstream_aborted", key=self._key_id())
            try:
                emit({"error": {
                    "message": ("codearts error after partial output: %s"
                                if partial else "codearts error: %s") % frame_err,
                    "type": err_type, "code": code}})
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError):
                pass
            return None

        if truncated:
            # 上游把流掐断了（不管有没有吐过内容）：**不能补 finish_reason=stop**
            # ——那等于给半截回答盖一个「正常结束」的章，客户端会当成完整结果
            # （CodeArts2api 的 routes/chat.py 也是这个口径）。发一条明确的
            # error 帧再 [DONE]，要不要重试交给客户端决定。
            # 断流也要留一份请求形状（工具定义），否则「92KB 的 schema 里到
            # 底有什么」永远只能靠猜 —— 0203 与中途静默都只在这种请求上复现。
            dump_failed_request(payload, messages, max_tokens)
            # 一次失败只写一行：usage 跟着 record_error 一起落，别在下面再
            # record_usage 一次 —— 那会让同一个请求既算失败又算一条用量，
            # 总量被放大一倍（record_error 的 docstring 写的就是这个约定）。
            record_error(model, 502, truncated[:200], elapsed_ms=elapsed_ms,
                         account=account_label, usage=usage, stream=True,
                         outcome="upstream_aborted", key=self._key_id())
            try:
                emit({"error": {
                    "message": "codearts upstream closed the stream: %s%s"
                               % (truncated,
                                  ca_stream.break_hint(stream_stats)),
                    "type": "upstream_error", "code": 502}})
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError):
                pass
            return None

        try:
            emit(frame({}, finish_reason or "stop", {"usage": usage}))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError):
            return None
        finally:
            # 客户端已经看到 [DONE] 了，这才发 idle、还名额。放在 [DONE] 之后
            # 是刻意的：idle 是同步 HTTP（最长 6 秒），排在前面就是让客户端
            # 白等一段它完全不关心的收尾时间。
            done_lease.release_slot()

        try:
            record_usage(model, usage, stream=True, elapsed_ms=elapsed_ms,
                         account=account_label, key=self._key_id(),
                         outcome="completed")
        except Exception:
            pass
        return None

    def _handle_codearts_chat(self, payload):
        """把一个 OpenAI 形状的请求转发给码道，再把结果转回 OpenAI 形状。"""
        # 模型健康降级：请求的模型熔断中时按链换健康的（未启用/链空则原样）。
        _apply_model_fallback(payload)
        for bad in (_codearts_choice_count_error(payload),
                    _codearts_response_format_error(payload),
                    ca_protocol.empty_conversation_error(payload.get("messages"))):
            if not bad:
                continue
            # 这两类都是「上游给不了你想要的形状」：既不能凑数，也不该假装
            # 生效。请求阶段就回 400，比让客户端解析半截结果容易查得多。
            record_error(payload.get("model") or "unknown", 400, bad,
                         stream=payload.get("stream"), key=self._key_id())
            return self._error(400, bad, "invalid_request_error")
        if CODEARTS_STREAM_PASSTHROUGH and payload.get("stream"):
            # 流式请求走真转发（边收边给）；非流式仍走「聚合后一次性返回」。
            return self._handle_codearts_chat_stream(payload)
        error, result = self._codearts_chat_result(payload)
        if error is not None:
            return error
        if result.get("aborted"):
            return None      # 客户端已经断开，一个字都不要再写
        model = result["model"]
        content = result["content"]
        reasoning = result["reasoning"]
        usage = result["usage"]
        tool_calls = result.get("tool_calls") or []
        want_stream = result["want_stream"]

        created = int(time.time())
        cid = "chatcmpl-codearts-%s" % uuid.uuid4().hex[:24]

        if not want_stream:
            msg = {"role": "assistant", "content": content}
            if reasoning:
                msg["reasoning_content"] = reasoning
            # 走结构化字段而不是把 <tool_call> 文本当正文 —— 客户端据此
            # 决定要不要真的去执行工具。
            if tool_calls:
                msg["tool_calls"] = tool_calls
            return self._json(200, {
                "id": cid, "object": "chat.completion", "created": created,
                "model": model,
                "choices": [{"index": 0, "message": msg,
                             "finish_reason": _chat_finish_reason(
                                 result.get("finish_reason"),
                                 bool(tool_calls))}],
                "usage": usage,
            })

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(obj):
            blob = "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"
            self.wfile.write(blob.encode("utf-8"))
            self.wfile.flush()

        def chunk(delta, finish=None, extra=None):
            body = {"id": cid, "object": "chat.completion.chunk",
                    "created": created, "model": model,
                    "choices": [{"index": 0, "delta": delta,
                                 "finish_reason": finish}]}
            if extra:
                body.update(extra)
            return body

        try:
            emit(chunk({"role": "assistant", "content": ""}))
            if reasoning:
                emit(chunk({"reasoning_content": reasoning}))
            if content:
                emit(chunk({"content": content}))
            # 工具调用逐个成帧。OpenAI 的流式形态里 delta.tool_calls 的
            # index 是「这是第几个调用」的定位符 —— 写成常量 0 会让客户端
            # 把并行的多个调用认成同一个，参数互相覆盖。
            for position, call in enumerate(tool_calls):
                emit(chunk({"tool_calls": [dict(call, index=position)]}))
            emit(chunk({}, "tool_calls" if tool_calls else "stop",
                       {"usage": usage}))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        return None

    def _responses_codearts(self, chat_req, want_stream, custom_names,
                            request_meta, namespace_map):
        """用 Responses 协议服务码道模型。

        翻译在进站时由 responses_to_chat() 完成；这里只负责把码道的
        chat-completions 结果转回 Responses 的 JSON / 事件流。
        """
        empty = ca_protocol.empty_conversation_error(chat_req.get("messages"))
        if empty:
            # 上游对「只有 instructions」的请求回 81001，报错点太远，先拦。
            return self._error(400, empty, "invalid_request_error")
        if want_stream and CODEARTS_STREAM_PASSTHROUGH:
            # 事件翻译器本来就直接吃 SSE 行流，接上实时行流就是真流式：
            # 上游吐一帧、客户端收一帧，不必等整条回答生成完。
            return self._responses_codearts_stream(
                chat_req, custom_names, request_meta, namespace_map)
        error, result = self._codearts_chat_result(
            chat_req, want_stream=want_stream)
        if error is not None:
            return error
        if result.get("aborted"):
            return None
        model = result["model"]
        if not want_stream:
            message = {"role": "assistant", "content": result["content"]}
            if result["reasoning"]:
                message["reasoning_content"] = result["reasoning"]
            finish = "stop"
            if result.get("tool_calls"):
                message["tool_calls"] = result["tool_calls"]
                finish = "tool_calls"
            chat_obj = {
                "choices": [{"index": 0, "message": message,
                             "finish_reason": finish}],
                "usage": result["usage"],
            }
            return self._json(200, chat_to_response(
                chat_obj, model, custom_names, request_meta, namespace_map))

        holder = {
            "usage": None,
            "custom_names": custom_names,
            "request_meta": request_meta,
            "namespace_map": namespace_map,
            "base_body": chat_req,
            "base_messages": chat_req.get("messages"),
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            for frame in stream_responses_events(
                    _BufferedSSELines(result["raw"]), model, holder):
                self.wfile.write(ca_protocol.clean_responses_frame(frame))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:                 # noqa: BLE001
            # 头已经发出去了，不能再回 JSON 错误；按既有流式路径的约定
            # 收尾，避免外层分发器触发「headers already sent」。
            log("responses/codearts stream aborted: %s" % exc)
            try:
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            except Exception:
                pass
            return
        return None

    def _responses_codearts_stream(self, chat_req, custom_names,
                                   request_meta, namespace_map):
        """Responses 协议的码道流式：直接吃上游实时 SSE，边翻译边下发。

        ``stream_responses_events`` 的入参本来就是一个「SSE 行流」，老的
        流式路径喂的是已经读完的 ``_BufferedSSELines``。这里换成本地实时行流
        （``lease.byte_lines``）就变成真转发 —— 翻译器不用改一行。
        """
        # 模型健康降级（chat 入口同一套；就地改 chat_req["model"]）。
        _apply_model_fallback(chat_req)
        model = str(chat_req.get("model") or "")
        # 角色归一 + 消息修复。修复这一环以前只在 build_upstream_body
        # 里，而码道路径没有调用点 —— 孤立的 tool_call/tool_result、
        # 被拆开的并行批次、deepseek 思考模式缺 reasoning_content 都
        # 会原样送给上游（2026-10-23）。
        messages = repair_messages_for_upstream(
            ca_protocol.normalize_roles(chat_req.get("messages") or []),
            model)
        # 投影式 soft 裁剪（chat 入口同一套，Responses 的翻译器按处理后的
        # 视图逐帧翻译，占位符会作为普通文本下发）。
        messages = prune_history_for_upstream(
            messages, model, _codearts_max_tokens(chat_req),
            source="responses")
        error, lease = self._codearts_open_lease(
            chat_req, model, messages, _codearts_max_tokens(chat_req))
        if error is not None:
            return error
        if lease is None:
            return None

        holder = {
            "usage": None,
            "custom_names": custom_names,
            "request_meta": request_meta,
            "namespace_map": namespace_map,
            "base_body": chat_req,
            "base_messages": chat_req.get("messages"),
        }
        tap = {"usage": None, "error": ""}
        # 断流归因（silent_s / bytes / pings）：另外两个入口原来不传 stats，
        # 于是「静默 60 秒被切」在它们的错误里看不出是同一件事。
        _break_stats = {}
        headers_sent = False

        def send_headers():
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

        try:
            try:
                _lines = ca_stream.tap_lines(
                    lease.byte_lines(self._client_disconnected, _break_stats),
                    tap, keepalive=ca_codearts.KEEPALIVE)
                for frame in stream_responses_events(_lines, model, holder):
                    if not headers_sent:
                        # 和 chat 入口同一口径：收到第一帧才提交 200。在这之前
                        # 失败（首帧即 1041、上游连不上）还能回一个干净的错误
                        # 码，客户端会按正常失败重试并可能换号 —— 这条入口以前
                        # 一拿到连接就 200，于是首帧限流只能以「200 + 空流」
                        # 收场，既不能重试也不能换号。
                        send_headers()
                        headers_sent = True
                    self.wfile.write(ca_protocol.clean_responses_frame(frame))
                    self.wfile.flush()
            except ca_stream.UpstreamErrorFrame as exc:
                # 上游在流里给了错误帧。翻译器不知道这件事，会照它的正常终态
                # 补 response.completed —— 客户端于是拿到「半截回答 + 完成」。
                # 这里接管：发 response.failed，并按失败记账。
                return self._responses_codearts_failed(
                    model, lease, holder, tap, exc.message,
                    "upstream_error_frame", headers_sent)
            except ca_codearts.ChatAborted:
                log("responses/codearts aborted: client gone model=%s" % model)
                # 客户端走了不是网关的失败，但它**必须**落一行：不记的话
                # 这条请求从统计里整个消失（既不算成功也不算失败）。走
                # record_usage 而不是 record_error —— 后者会把日志级别标成
                # ERROR，而「用户自己关掉了」不该出现在错误日志里。
                self._record_aborted(model, lease, tap, holder, self._key_id())
                return None
            except ca_codearts.UpstreamBroken as exc:
                # 上游把 chunked 流掐了：补一个 response.failed 再收尾，别让
                # Codex 只看到「流没了」而摸不着头脑。
                log("responses/codearts upstream broken: model=%s after %dms %s"
                    % (model, int((time.time() - lease.started_at) * 1000), exc))
                return self._responses_codearts_failed(
                    model, lease, holder, tap,
                    "%s%s" % (exc, ca_stream.break_hint(_break_stats)),
                    "upstream_closed", headers_sent)
            except (BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError):
                log("responses/codearts closed by client model=%s" % model)
                self._record_aborted(model, lease, tap, holder, self._key_id())
                return None
            except Exception as exc:                 # noqa: BLE001
                # **但账必须记**：以前这里只有一个 [DONE] 就 return，异常整个
                # 从统计里消失（10-23 有 6 个请求就是这么没的）。
                log("responses/codearts stream aborted: %s" % exc)
                record_error(model, 502, ("stream aborted: %s" % exc)[:200],
                             elapsed_ms=int((time.time() - lease.started_at) * 1000),
                             account=lease.account_label,
                             usage=(tap.get("usage")
                                    or (holder or {}).get("usage") or {}),
                             stream=True, outcome="upstream_aborted",
                             key=self._key_id())
                if not headers_sent:
                    # 头还没发：回真正的 HTTP 错误码。直接写 ``data: [DONE]``
                    # 会得到一个没有状态行、也没有 SSE 头的「裸」响应
                    # （2026-10-23）。
                    return self._error(502, "codearts stream aborted: %s" % exc,
                                       "upstream_error")
                try:
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except Exception:
                    pass
                return None

            elapsed_ms = int((time.time() - lease.started_at) * 1000)
            usage = tap["usage"] or holder.get("usage") or {}
            if tap.get("error"):
                # 走到这里还带着 error，说明错误帧没能打断翻译器（见
                # tap_lines 的契约）。宁可多记一条失败，也不能记成成功。
                record_error(model, 502, tap["error"][:200],
                             elapsed_ms=elapsed_ms, account=lease.account_label,
                             usage=usage, stream=True,
                             outcome="upstream_aborted", key=self._key_id())
                return None
            try:
                record_usage(model, usage, stream=True, elapsed_ms=elapsed_ms,
                             account=lease.account_label, key=self._key_id(),
                             outcome="completed")
            except Exception:
                pass
            return None
        finally:
            # 先关连接（上游立刻回收会话），再 idle + 还名额。反过来会让
            # 「本地已放行新人」和「上游还没收到 idle」重叠，白吃 1041。
            lease.close()

    def _record_aborted(self, model, lease, tap, holder, key):
        """客户端中途走了：落一行 ``client_aborted``。

        这条**必须**记，哪怕它是「用户自己关掉的」：不记的话这个请求在
        usage.jsonl 里根本没有痕迹，请求数、耗时样本、成功率分母全少一条
        —— 统计口径与「真的没发生过」无法区分。用 record_usage 而不是
        record_error：后者把日志级别标成 ERROR，而这种取消不是网关故障。
        """
        try:
            record_usage(model,
                         (tap or {}).get("usage")
                         or (holder or {}).get("usage") or {},
                         stream=True,
                         elapsed_ms=int((time.time() - lease.started_at) * 1000),
                         account=lease.account_label, key=key,
                         outcome="client_aborted")
        except Exception:
            pass

    def _responses_codearts_failed(self, model, lease, holder, tap, message,
                                   error_code, headers_sent=True):
        """Responses 流式的失败收尾：response.failed + [DONE]，并按失败记账。

        **一次失败只落一行**：usage 跟着 record_error 走，不再额外记一条
        completed。以前这里 `record_error` 之后无条件 `record_usage(...,
        outcome="completed")`，同一个请求既算失败又算成功。

        ``headers_sent=False`` 时**不发 SSE**、直接回真正的 HTTP 错误码：
        那时 200 还没承诺出去，客户端可以按正常失败重试（并且换号）。
        """
        elapsed_ms = int((time.time() - lease.started_at) * 1000)
        usage = (tap or {}).get("usage") or (holder or {}).get("usage") or {}
        status, err_type = ca_stream.frame_status(message)
        log("responses/codearts failed: model=%s %s" % (model, str(message)[:160]))
        dump_failed_request(holder.get("base_body") or {},
                            (holder or {}).get("base_messages") or [], 0)
        record_error(model, status, str(message)[:200], elapsed_ms=elapsed_ms,
                     account=lease.account_label, usage=usage, stream=True,
                     outcome="upstream_aborted", key=self._key_id())
        if not headers_sent:
            # 首帧之前失败：头还没发出去，能回干净的错误码。以前这条入口一
            # 拿到连接就 200，于是首帧即 1041 只能以「200 + 空流」收场 ——
            # 既不能重试也不能换号。
            return self._error(status, "codearts error: %s" % message, err_type)
        try:
            rid = ((holder or {}).get("response_id")
                   or "resp_%s" % uuid.uuid4().hex[:24])
            self.wfile.write(ca_protocol.clean_responses_frame((
                "event: response.failed\ndata: " + json.dumps({
                    "type": "response.failed",
                    "response": {"id": rid, "object": "response",
                                 "status": "failed",
                                 "error": {"code": error_code,
                                           "message": str(message)}}},
                    ensure_ascii=False) + "\n\n").encode("utf-8")))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except Exception:
            pass
        return None

    def _messages_codearts(self, chat_req, want_stream):
        """用 Anthropic Messages 协议服务码道模型。

        Messages 入口默认关闭，但一旦打开，码道模型同样不能落进
        WorkBuddy 空池；错误信封也必须换成 Anthropic 的，否则 Claude Code
        会把 503 当成不可重试的协议错误。
        """
        def anthropic_error(code, message, err_type=None):
            return self._anthropic_error(code, message, err_type)

        empty = ca_protocol.empty_conversation_error(chat_req.get("messages"))
        if empty:
            return anthropic_error(400, empty, "invalid_request_error")
        if want_stream and CODEARTS_STREAM_PASSTHROUGH:
            # 同 Responses：翻译器吃 SSE 行流，喂实时流就是真转发。
            return self._messages_codearts_stream(chat_req, anthropic_error)

        error, result = self._codearts_chat_result(
            chat_req, want_stream=want_stream, error_factory=anthropic_error,
            anthropic=True)
        if error is not None:
            return error
        if result.get("aborted"):
            return None
        model = result["model"]
        if not want_stream:
            message = {"role": "assistant", "content": result["content"]}
            if result["reasoning"]:
                message["reasoning_content"] = result["reasoning"]
            # **工具调用必须一起带上**。以前这里只塞了 content 与 reasoning，
            # 于是 Claude Code 拿到的永远是 content:[] + stop_reason:end_turn
            # —— Agent 以为模型说完了，这一轮直接结束，一次工具都不会调
            # （2026-10-23 实测复现）。finish_reason 也要跟着改：有工具调用
            # 就必须是 tool_use，chat_to_messages 靠它映射 stop_reason。
            tool_calls = result.get("tool_calls") or []
            if tool_calls:
                message["tool_calls"] = tool_calls
            chat_obj = {
                "id": "chatcmpl-codearts-%s" % uuid.uuid4().hex[:24],
                "model": model,
                "choices": [{"index": 0, "message": message,
                             "finish_reason": _chat_finish_reason(
                                 result.get("finish_reason"),
                                 bool(tool_calls))}],
                "usage": result["usage"],
            }
            # stop 列表只用来回填 stop_sequence（上游通常不回显命中的串）。
            return self._json(200, ca_protocol.chat_to_messages(
                chat_obj, chat_req.get("stop")))

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        if cors_origin_allowed(self.path):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        holder = {"usage": None, "stop_sequences": chat_req.get("stop")}
        try:
            for frame in ca_protocol.stream_messages_events(
                    _BufferedSSELines(result["raw"]), model, holder):
                self.wfile.write(frame)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:                 # noqa: BLE001
            log("messages/codearts stream aborted: %s" % exc)
            try:
                self.wfile.write(ca_protocol.anthropic_sse_frame("error", {
                    "error": {"type": "api_error", "message": str(exc)}}))
                self.wfile.flush()
            except Exception:
                pass
            return
        return None

    def _messages_codearts_stream(self, chat_req, anthropic_error):
        """Anthropic Messages 协议的码道流式（Claude Code 走这条）。"""
        _apply_model_fallback(chat_req)
        model = str(chat_req.get("model") or "")
        # 角色归一 + 消息修复。修复这一环以前只在 build_upstream_body
        # 里，而码道路径没有调用点 —— 孤立的 tool_call/tool_result、
        # 被拆开的并行批次、deepseek 思考模式缺 reasoning_content 都
        # 会原样送给上游（2026-10-23）。
        messages = repair_messages_for_upstream(
            ca_protocol.normalize_roles(chat_req.get("messages") or []),
            model)
        # 投影式 soft 裁剪（chat 入口同一套）。
        messages = prune_history_for_upstream(
            messages, model, _codearts_max_tokens(chat_req),
            source="messages")
        error, lease = self._codearts_open_lease(
            chat_req, model, messages, _codearts_max_tokens(chat_req),
            fail=anthropic_error, anthropic=True)
        if error is not None:
            return error
        if lease is None:
            return None

        holder = {"usage": None, "stop_sequences": chat_req.get("stop")}
        tap = {"usage": None, "error": ""}
        _break_stats = {}
        headers_sent = False

        def send_headers():
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            if cors_origin_allowed(self.path):
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

        try:
            try:
                for frame in ca_protocol.stream_messages_events(
                        ca_stream.tap_lines(
                            lease.byte_lines(self._client_disconnected,
                                             _break_stats), tap,
                            keepalive=ca_codearts.KEEPALIVE),
                        model, holder):
                    if not headers_sent:
                        # 和 chat / Responses 同一口径：第一帧到了才提交 200。
                        send_headers()
                        headers_sent = True
                    self.wfile.write(frame)
                    self.wfile.flush()
            except ca_stream.UpstreamErrorFrame as exc:
                # 上游在流里给了错误帧。翻译器会照正常终态补 message_stop，
                # 客户端于是把半截回答当完整结果。这里接管，发 event: error。
                log("messages/codearts error frame: model=%s %s"
                    % (model, exc.message[:160]))
                dump_failed_request(chat_req, messages,
                                    _codearts_max_tokens(chat_req))
                status, err_type = ca_stream.frame_status(exc.message,
                                                          anthropic=True)
                record_error(model, status, exc.message[:200],
                             elapsed_ms=int((time.time() - lease.started_at) * 1000),
                             account=lease.account_label,
                             usage=(tap["usage"] or holder.get("usage") or {}),
                             stream=True, outcome="upstream_aborted",
                             key=self._key_id())
                if not headers_sent:
                    # 首帧之前错误：头还没发，回干净的错误码（可重试 / 换号）。
                    return anthropic_error(
                        status, "codearts error: %s" % exc.message, err_type)
                try:
                    self.wfile.write(ca_protocol.anthropic_sse_frame("error", {
                        "error": {"type": err_type,
                                  "message": "codearts error: %s" % exc.message}}))
                    self.wfile.flush()
                except Exception:
                    pass
                return None
            except ca_codearts.ChatAborted:
                log("messages/codearts aborted: client gone model=%s" % model)
                # 客户端取消也要落一行（见 _record_aborted 的注释）。
                self._record_aborted(model, lease, tap, holder, self._key_id())
                return None
            except ca_codearts.UpstreamBroken as exc:
                # Claude Code 认 event: error，收到它会按可重试错误处理；
                # 静默断连反而会被当成「回答就这么短」。
                log("messages/codearts upstream broken: model=%s after %dms %s"
                    % (model, int((time.time() - lease.started_at) * 1000), exc))
                message = "upstream closed the stream: %s%s" % (
                    exc, ca_stream.break_hint(_break_stats))
                # 断流同样只落一行账（usage 跟着 record_error）。
                dump_failed_request(chat_req, messages,
                                    _codearts_max_tokens(chat_req))
                record_error(model, 502, message[:200],
                             elapsed_ms=int((time.time() - lease.started_at) * 1000),
                             account=lease.account_label,
                             usage=(tap["usage"] or holder.get("usage") or {}),
                             stream=True, outcome="upstream_aborted",
                             key=self._key_id())
                if not headers_sent:
                    return anthropic_error(
                        502, message, "api_error")
                try:
                    self.wfile.write(ca_protocol.anthropic_sse_frame("error", {
                        "error": {"type": "api_error", "message": message}}))
                    self.wfile.flush()
                except Exception:
                    pass
                return None
            except (BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError):
                self._record_aborted(model, lease, tap, holder, self._key_id())
                return None
            except Exception as exc:                 # noqa: BLE001
                log("messages/codearts stream aborted: %s" % exc)
                # 账必须记：以前这里只补一个 error 帧就 return，异常整个从
                # 统计里消失（既不算成功也不算失败）。
                record_error(model, 502, ("stream aborted: %s" % exc)[:200],
                             elapsed_ms=int((time.time() - lease.started_at) * 1000),
                             account=lease.account_label,
                             usage=(tap["usage"] or holder.get("usage") or {}),
                             stream=True, outcome="upstream_aborted",
                             key=self._key_id())
                if not headers_sent:
                    # **首帧之前不要写 SSE**：Status 行还没发，直接写
                    # ``event: error`` 得到的是一个没有状态行的「裸 SSE」响应
                    # —— 客户端（Claude Code / requests）看到的第一行不是
                    # ``HTTP/1.1 …``，会当成协议错误，连状态码都拿不到
                    # （2026-10-23）。这里回干净的 Anthropic 错误信封。
                    return anthropic_error(
                        502, "codearts stream aborted: %s" % exc, "api_error")
                try:
                    self.wfile.write(ca_protocol.anthropic_sse_frame("error", {
                        "error": {"type": "api_error", "message": str(exc)}}))
                    self.wfile.flush()
                except Exception:
                    pass
                return None

            elapsed_ms = int((time.time() - lease.started_at) * 1000)
            usage = tap["usage"] or holder.get("usage") or {}
            if tap.get("error"):
                # 走了到这里还带着 error：说明错误帧没能打断翻译器。宁可
                # 多记一条失败，也不能把失败记成成功。
                record_error(model, 502, tap["error"][:200],
                             elapsed_ms=elapsed_ms, account=lease.account_label,
                             usage=usage, stream=True,
                             outcome="upstream_aborted", key=self._key_id())
                return None
            try:
                record_usage(model, usage, stream=True, elapsed_ms=elapsed_ms,
                             account=lease.account_label, key=self._key_id(),
                             outcome="completed")
            except Exception:
                pass
            return None
        finally:
            lease.close()

    def _dispatch_chat_post(self, path, payload):
        # 模型名先归一到上游真名（大小写无关）。必须排在封锁 / 限模型判定
        # 之前：面板里配的是真名，客户端发小写时不能绕过封禁。
        canonicalize_model(payload)
        # 先挡背景请求：Codex 自己发的（记忆整理／环境建议／自动复核）
        # 不算「使用者实际使用」，一律本地拒绝，不碰上游。
        if BLOCK_BACKGROUND_REQUESTS:
            reason = background_request_reason(payload)
            if reason:
                try:
                    log("background request blocked: model=%s trigger=(%s)"
                        % (payload.get("model"), reason), level="INFO")
                except Exception:
                    pass
                return self._error(400, background_request_message(reason),
                                   "invalid_request_error")
        if path in ("/v1/responses", "/responses"):
            return self._handle_responses(payload)
        # 模型封锁和 per-key 限模型在分流之前判：码道走的也是这个入口，
        # 漏判的话面板里的封禁 / 按 key 限模型会被码道这条路绕过去
        #（/v1/responses 和 /v1/messages 都是在分流前判的，三个入口必须一致）。
        banned = self._banned_model_error(payload.get("model"))
        if banned:
            return self._error(400, banned, "invalid_request_error")
        key_blocked = self._key_model_error(payload.get("model"))
        if key_blocked:
            return self._error(400, key_blocked, "invalid_request_error")
        # 码道模型走另一套凭证体系，先按模型名分流。
        if is_codearts_model(payload.get("model")):
            return self._handle_codearts_chat(payload)
        # 网关只服务码道：非码道模型一律 404，不回 503（那看起来像网关坏了）。
        return self._error(404, unserved_model_message(payload.get("model")),
                           "model_not_found")


def running_version():
    """The version this process reports, e.g. "1.6.19".

    tests/_test_release_engineering.py pins the two version literals and asserts
    they agree, so the update checker reads the running one from the handler
    instead of becoming a third copy that could drift away from both.
    """
    return Handler.server_version.split("/", 1)[-1]

def main():
    args = _parse_cli_args()
    _apply_cli_overrides(args)
    if _probe_running_instance(args):
        return
    api_key_generated = _bootstrap_runtime(args)
    if _report_first_run(args):
        return
    _log_startup_summary(args, api_key_generated)
    _serve_forever(args)

def _parse_cli_args():
    ap = argparse.ArgumentParser(description="CodeArts Agent（华为云码道）-> OpenAI-compatible proxy")
    ap.add_argument("--host", default=os.environ.get("HOST") or "127.0.0.1")
    ap.add_argument("--port", type=int,
                    default=ca_env.number("PORT", 8788, minimum=1, integer=True))
    ap.add_argument("--lan", action="store_true",
                    help="listen on every interface so other devices on the LAN can "
                         "reach it (implies --host 0.0.0.0 and forces an api key)")
    ap.add_argument("--api-key", default=os.environ.get("API_KEY") or os.environ.get("WB_PROXY_KEY") or None,
                    help="require this bearer token on /v1/* (optional; ignored once "
                         "the panel has ever held a key)")
    ap.add_argument("--system-prompt", default=DEFAULT_SYSTEM_PROMPT,
                    help="system message injected when the request has none (required upstream)")
    ap.add_argument("--usage-dir", default=None,
                    help="where to store usage.jsonl (default: ./usage)")
    ap.add_argument("--accounts-dir", default=os.environ.get("ACCOUNTS_DIR") or None,
                    help="where the per-account credential files live (default: ./accounts)")
    ap.add_argument("--panel-password", default=None,
                    help="set the web panel password on startup (default: admin). "
                         "Ignored once the password has been changed in the panel, "
                         "so a restart no longer reverts it - use "
                         "--panel-password-force to override deliberately")
    ap.add_argument("--panel-password-force", action="store_true",
                    help="apply --panel-password even when the panel set the "
                         "password itself (the reset path for a forgotten one)")
    args = ap.parse_args()
    return args

def _apply_cli_overrides(args):
    global USAGE_DIR, USAGE_LOG, LIMIT_EVENTS_FILE, ESTIMATE_DAILY_FILE, \
        RECENT_INDEX_FILE
    # LAN mode binds every interface. The key is generated below, once
    # ACCOUNTS_DIR is resolved, so it can be persisted and reused.
    if args.lan and args.host == "127.0.0.1":
        args.host = "0.0.0.0"
    if args.usage_dir:
        USAGE_DIR = os.path.abspath(args.usage_dir)
        USAGE_LOG = os.path.join(USAGE_DIR, "usage.jsonl")
        # 事件日志（remaining 预算样本的来源）必须跟着 --usage-dir 走：这个
        # 常量在 import 时按默认目录算过，漏掉它真机上会一直写 ENOENT
        # （2026-10-10 实测 /usr/lib/codearts2api/usage/limit-events.jsonl）。
        LIMIT_EVENTS_FILE = os.path.join(USAGE_DIR, "limit-events.jsonl")
        # 按天归档的估算数据同理（少了它，跨天归档会一直写默认目录/ENOENT）。
        ESTIMATE_DAILY_FILE = os.path.join(USAGE_DIR, "estimate-daily.json")
        # recent 的行偏移索引同理（漏掉它，换目录后索引写到旧目录，
        # 新目录每次冷启动都要重扫一遍日志）。
        RECENT_INDEX_FILE = os.path.join(USAGE_DIR, "usage-recent-index.json")
    # 账号活动历史与用量日志同目录，并且要在任何后台线程起来之前定下来：调度器
    # 的第一轮巡检不能落在 --usage-dir 生效之前，否则记录会写进默认目录。
    ca_activity.set_data_dir(USAGE_DIR)

def _probe_running_instance(args):
    # Refuse to start a second copy. On Windows SO_REUSEADDR lets two sockets
    # bind the same port, which silently splits incoming connections between
    # them - confusing and hard to diagnose.
    try:
        probe = urllib.request.urlopen(
            f"http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}/health",
            timeout=2,
        )
        existing = json.loads(probe.read().decode("utf-8"))
    except Exception:
        existing = None  # nothing answering /health - let the bind below decide
    if isinstance(existing, dict):
        # Only OUR /health carries the account-pool fields ("accounts"). Other
        # services can occupy the same port and also answer /health with JSON
        # (a dev proxy, another gateway); treating that as "already running" made this
        # launcher exit silently while the port belonged to someone else - the
        # dashboard then showed a foreign UI and API calls failed with 401/404.
        foreign = existing.get("service") or "accounts" not in existing
        if foreign:
            who = existing.get("service") or "an unknown HTTP service"
            print()
            print(f"  [ERROR] port {args.port} is already taken by another program: {who}")
            print("          codearts-hub itself is NOT running - nothing was started.")
            print()
            print("  Fix: start codearts-hub on a different port, e.g.")
            print("          %s" % launcher_hint(args.port + 1))
            print(f"          python3 ca_proxy.py --port {args.port + 1}")
            print()
            print("  Check who owns the port:  %s" % port_owner_hint(args.port))
            print()
            raise SystemExit(1)
        print()
        print(f"  [已有一个反代在 {args.port} 端口运行，无需重复启动]")
        print(f"  账号: {existing.get('uid', '?')} @ {existing.get('domain', '?')}")
        print(f"  看板: http://127.0.0.1:{args.port}/")
        print()
        print("  如果要重启: 先把原来那个窗口关掉（或结束 python 进程），再运行本程序。")
        print()
        # Return True so main() stops here. A bare return gives None, which
        # main() reads as "no running copy" and it would carry on to bind the
        # port that is already taken.
        return True
    return False

def _bootstrap_runtime(args):
    global ACCOUNTS_DIR, API_KEY, SYSTEM_PROMPT
    global API_KEY_FILE_SET, LOG_STORE, CODEARTS_LOGIN
    api_key_generated = False
    API_KEY = args.api_key
    SYSTEM_PROMPT = args.system_prompt
    if args.accounts_dir:
        ACCOUNTS_DIR = os.path.abspath(args.accounts_dir)
    # 日志落库（默认关闭）：在账号池之前初始化，好让「池加载失败」这类最需要
    # 事后留档的启动日志也能进库。关闭时这里只造一个 enabled=False 的空壳，
    # 不建文件、不改日志路径。
    LOG_STORE = ca_logstore.LogStore(os.path.join(USAGE_DIR, "logs.sqlite3"))
    apply_log_db_settings()
    # LAN mode must not ship a known key: the gateway spends the account's own
    # upstream quota, so a guessable default lets anyone on the network drain
    # it. Generate one on first use, persist it, and reuse it afterwards.
    if args.lan and not API_KEY:
        API_KEY, api_key_generated = ca_settings.ensure_launcher_key(ACCOUNTS_DIR)
    # A legacy panel key wins over an auto-generated LAN key so a change made
    # in the browser survives a restart of the launcher. Once the panel holds
    # any key, identify_key() accepts panel keys alone and this fallback is
    # never consulted.
    global API_KEY_FILE_SET
    saved_key, key_from_panel = ca_settings.api_key_override(ACCOUNTS_DIR)
    if key_from_panel and not args.api_key:
        API_KEY = saved_key
        API_KEY_FILE_SET = True
    if args.panel_password:
        # 启动参数里的密码不再是「覆盖」，而是「初次设置」。原因见
        # ca_settings.apply_launcher_password 的注释：.credentials 是部署时写的，
        # 用户在面板里改过之后它不会跟着变，无条件覆盖等于每次重启都把用户的
        # 改动抹掉（2026-10-21 实测：一天被抹 28 次，用户以为自己输错了）。
        action = ca_settings.apply_launcher_password(
            ACCOUNTS_DIR, args.panel_password, force=args.panel_password_force)
        if action == "applied":
            log("panel      : password set from --panel-password")
        elif action == "kept":
            log("panel      : keeping the password set in the panel "
                "(use --panel-password-force to override)")
        # 'same' 什么都不用说：这是正常重启
    elif ca_settings.panel_password_is_default(ACCOUNTS_DIR):
        log("panel      : password is still the default 'admin' - change it in the panel")
    # WorkBuddy 账号池已整体移除（2026-10-23）：网关只服务码道，没有第二套
    # 上游凭证体系可加载。
    CODEARTS_LOGIN = ca_codearts.LoginManager(ACCOUNTS_DIR, log=log)
    load_persisted_realm()
    # 每日积分签到的后台线程（2026-10-24 回归）：opengw 的「每日额度领取」
    # 确实死了，但积分签到走的是另一条活通道（snap-access /v1/ops/*，
    # 实测 daily campaign 返回 CONFIRMED/ELIGIBLE），旧调度器删的时候把它
    # 一起埋了。这里只做签到这一件事：每 30 分钟醒来，对每个账号到点
    # （本地时区每天 00:05 后第一次）尝试 welfare_claim_daily；
    # 成功/已签 → 当天不再重复；失败 → 下个周期再试（activity_history
    # 记录每次真实尝试）。
    # 目录兜底：每天至少从上游 API 取一次（活跃使用的部署里 300s 缓存早就
    # 刷得更新，这个线程只兜长时间没人访问 / 一直吃缓存文件或内置快照）。
    # 价格估算体系已下线（2026-10-22）：不再初始化取价器，不再读价表，
    # 也不再有 OpenRouter 映射。计费只按码道积分。
    global UPDATES
    # Release discovery only: the checker asks GitHub what the newest stable
    # release is and reports it. It never downloads, replaces or restarts
    # anything, and with the daily switch off (the default) it sends nothing.
    UPDATES = ca_updates.UpdateChecker(
        current_version=running_version(),
        settings_dir=ACCOUNTS_DIR,
        log=lambda msg: add_log_entry("[更新] %s" % msg, tag="update"),
    )
    UPDATES.start()
    start_checkin_scheduler()
    start_sts_refresher()
    return api_key_generated

def _report_first_run(args):
    """首次启动提示。WorkBuddy 池移除后只剩一件事：没有码道账号就说清楚。"""
    if codearts_deployed():
        return
    # Do NOT exit here: the dashboard has to stay reachable so the first
    # codearts account can be added through the browser login flow.
    log("no codearts account yet - starting anyway so you can log in via the dashboard")

def _log_startup_summary(args, api_key_generated):
    try:
        sessions = ca_codearts.load_sessions(ACCOUNTS_DIR)
    except Exception:
        sessions = []
    log("accounts   : %d codearts session(s)" % len(sessions))
    for sess in sessions:
        left, expired, renewable = _codearts_left(sess)
        label = (sess.get("account") or {}).get("label") or "?"
        state = ("expired (renewable=%s)" % bool(renewable) if expired
                 else "%.1fh left" % (left / 3600.0))
        log("  - %s  %s" % (label, state))
    log("store      : %s" % ACCOUNTS_DIR)
    log("realm      : %s" % CURRENT_REALM)
    if args.host == "0.0.0.0":
        ips = local_ip_addresses() or ["<this-pc-ip>"]
        print()
        print("  " + "=" * 62)
        print("  LAN MODE - reachable from other devices")
        print()
        for ip in ips:
            print("    API       : http://%s:%s/v1" % (ip, args.port))
            print("    Dashboard : http://%s:%s/" % (ip, args.port))
        print()
        print("    API Key   : %s" % API_KEY)
        if api_key_generated:
            print("                (newly generated & saved to accounts/settings.json)")
        else:
            print("                (reused from accounts/settings.json)")
        print()
        print("    Open the dashboard (key already included):")
        print("      http://%s:%s/?key=%s" % (ips[0], args.port, API_KEY))
        print()
        print("    Clients: Base URL = the API address above, then paste the key.")
        print()
        if IS_WINDOWS:
            print("    If nothing can connect, allow python through the")
            print("    firewall: run allow-firewall.bat once as administrator.")
        elif sys.platform == "darwin":
            print("    If other devices cannot connect, allow incoming")
            print("    connections for Python (macOS asks automatically the")
            print("    first time it listens; on macOS 15+ also allow Local")
            print("    Network access for your terminal). Helper script:")
            print("    ./allow-firewall.command")
        else:
            print("    If other devices cannot connect, open the port in")
            print("    your firewall (ufw / firewalld) for the LAN subnet.")
        print("  " + "=" * 62)
        print()
        sys.stdout.flush()
    if not codearts_deployed():
        print()
        print("  " + "=" * 62)
        print("  NO CODEARTS ACCOUNT YET")
        print()
        print("  Open the dashboard and click [Login with Huawei Cloud]:")
        print("      http://127.0.0.1:%s/" % args.port)
        print()
        print("  The browser flow adds the account automatically.")
        print("  This window must stay open.")
        print("  " + "=" * 62)
        print()
        sys.stdout.flush()

class GatewayServer(ThreadingHTTPServer):
    """主服务的 HTTP 服务类：只为把 listen backlog 从 stdlib 默认的 5 提到 128。

    backlog=5 在突发并发下（面板打开一页就是 ~7 个并发请求，多标签更糟）会让
    内核来不及 accept 的 SYN 被丢弃、客户端按 1s 粒度重传，表现为一部分请求整整
    慢 1 秒（路由器实测：64 并发突发 43/64 卡 >=1s、最长 2.8s；backlog=128 后
    0/64、最长 0.18s）。listen() 在 TCPServer.__init__ 里就被调用，所以必须是
    类属性——实例化之后再改就晚了。
    """
    request_queue_size = 128

def _serve_forever(args):
    try:
        server = GatewayServer((args.host, args.port), Handler)
    except OSError as exc:
        # Port stolen between the probe above and this bind, or held by
        # something that does not answer /health: report it in plain words
        # instead of dumping a raw socketserver traceback.
        print()
        print(f"  [ERROR] failed to listen on {args.host}:{args.port} - {exc}")
        print("          the port is reserved or held by another program;")
        print("          codearts-hub did NOT start.")
        print()
        print("  Fix: stop the program holding the port, or pick another port:")
        print("          %s" % port_owner_hint(args.port))
        print("          %s" % launcher_hint(args.port + 1))
        print()
        raise SystemExit(1)
    # Only claim the address once the socket really exists, so a failed bind
    # never prints a "listening" line that contradicts the error below.
    # Report the state the request path actually enforces: the panel can turn
    # key checking on after startup, so reading API_KEY alone printed "off"
    # while every /v1 call was still being rejected with 401.
    try:
        _panel_keys = [k for k in configured_keys() if k.get("enabled")]
    except Exception as _exc:
        _panel_keys = []
        log("settings     : cannot read api keys (%s)" % _exc)
    if auth_required():
        if _panel_keys:
            _key_state = "on (%d key(s) from the panel)" % len(_panel_keys)
        elif API_KEY and not panel_keys_configured():
            _key_state = "on (--api-key)"
        else:
            _key_state = "on (no enabled key - add one in the panel)"
    else:
        _key_state = "off"
    log(f"listening  : http://{args.host}:{args.port}/v1  (api key: {_key_state})")
    log(f"dashboard  : http://{args.host}:{args.port}/")
    # 上一次进程被杀/重启时，finally 里的 idle 没机会执行，那几条 busy 还挂在
    # 上游占着名额。后台补发一次（不拖启动，见 reap_codearts_sessions）。
    threading.Thread(target=reap_codearts_sessions,
                     name="codearts-session-reap", daemon=True).start()
    if _panel_keys and API_KEY and all(k.get("key") != API_KEY for k in _panel_keys):
        log("api key   : --api-key ignored (panel keys take precedence)")
    # Keep the handler referenced for the process lifetime: SetConsoleCtrlHandler
    # stores a raw pointer, so a collected callback would crash on close.
    _ctrl_handler = install_console_close_handler()

    def _drain_sessions():
        """退出前把还在登记表里的会话 idle 掉。

        这是 **best-effort 的最后一手**：正常收尾路径上每条请求自己会 idle，
        走到这里还剩条目说明有请求没跑完（或者 idle 失败过）。补一遍总比
        留着它们占上游名额好 —— 下次启动的 reap 还会再试。
        """
        try:
            reap_codearts_sessions()
        except Exception:
            pass

    _sigterm_handler = install_sigterm_handler(server, on_shutdown=_drain_sessions)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("bye")
    finally:
        # shutdown() 是收尾线程调的，serve_forever 一返回就 join 它：等补发 idle
        # 写完再关 socket，别在它还在用连接的时候把服务器收掉。
        drain = _DRAIN_THREAD.get("thread")
        if drain is not None and drain is not threading.current_thread():
            drain.join(max(1.0, SHUTDOWN_GRACE_SECONDS * 0.3))
        try:
            server.server_close()
        except Exception:
            pass

if __name__ == "__main__":
    try:
        # Keep console output readable regardless of the active code page.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()


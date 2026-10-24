"""STS 后台续期线程：续期必须是时间驱动，不能只靠流量驱动。

2026-10-24 生产实测：请求路径（_admit / 目录刷新）确实会在用号时兜底续，
但没人发请求就没人续 —— 账号从过期一直躺到下一波流量才被发现（日志里
"renewed STS (was -2453s left)" / "(was -4546s left)"，迟到 41/76 分钟），
期间所有请求 502。这套用例钉住 _sts_refresher_once / loop 的行为：

  - 巡检会对每个快到期的账号调 ensure_fresh_session（margin 用网关全局值）；
  - 目录读失败、单个账号续期失败，都不会弄死巡检；
  - start_sts_refresher 起的是 daemon 线程且真的会循环 tick。

全程 monkeypatch，无网络访问。
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts
import ca_proxy as proxy

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def with_sessions(sessions, summarize=None, ensure=None):
    """把 ca_codearts 的三个入口换成桩，返回 (记录表, 恢复函数)。"""
    calls = []
    orig = (ca_codearts.load_sessions, ca_codearts.summarize,
            ca_codearts.ensure_fresh_session)

    def fake_load(_dir):
        return list(sessions)

    def fake_summarize(_sess):
        if summarize is not None:
            return summarize
        return {"sts_remaining_seconds": 120, "sts_expired": False,
                "renewable": True}

    def fake_ensure(_dir, sess, margin=None):
        calls.append((sess, margin))
        if ensure is not None:
            return ensure(sess)
        return {"renewed": True}

    ca_codearts.load_sessions = fake_load
    ca_codearts.summarize = fake_summarize
    ca_codearts.ensure_fresh_session = fake_ensure

    def restore():
        (ca_codearts.load_sessions, ca_codearts.summarize,
         ca_codearts.ensure_fresh_session) = orig

    return calls, restore


print("[1] 巡检会对每个快到期的账号续期，margin 用网关全局值")

sessions = [{"account": {"id": "a1", "label": "acct-a"}},
            {"account": {"id": "a2", "label": "acct-b"}}]
calls, restore = with_sessions(sessions)
try:
    proxy._sts_refresher_once()
finally:
    restore()
check("两个账号都被巡到", len(calls) == 2, calls)
check("margin 传的是 CODEARTS_REFRESH_MARGIN",
      all(m == proxy.CODEARTS_REFRESH_MARGIN for _, m in calls), calls)

print()
print("[2] 目录读失败 / 单账号续期失败，都弄不死巡检")

def raising_load(_dir):
    raise RuntimeError("accounts dir gone")

orig_load = ca_codearts.load_sessions
ca_codearts.load_sessions = raising_load
try:
    check("load_sessions 抛错时 once() 不抛",
          proxy._sts_refresher_once() is None)
finally:
    ca_codearts.load_sessions = orig_load

def fail_first(sess, _margin=None):
    if (sess.get("account") or {}).get("id") == "a1":
        raise RuntimeError("STS5.1806")
    return {"renewed": True}

calls, restore = with_sessions(sessions, ensure=fail_first)
try:
    proxy._sts_refresher_once()
finally:
    restore()
check("第一个账号失败后第二个仍被巡到", len(calls) == 2, calls)

print()
print("[3] start_sts_refresher 起的是 daemon 线程，且真的在 tick")

ticks = []
orig_once = proxy._sts_refresher_once
orig_tick = proxy.CODEARTS_STS_TICK_SECONDS


def counting_once():
    ticks.append(time.time())
    if len(ticks) >= 2:
        raise SystemExit          # loop 只接 Exception，SystemExit 正好收线程


proxy._sts_refresher_once = counting_once
proxy.CODEARTS_STS_TICK_SECONDS = 0.05
proxy.start_sts_refresher()
deadline = time.time() + 5
thread = next((t for t in threading.enumerate() if t.name == "codearts-sts"),
              None)          # 先抓线程对象：它 tick 满两次就会按设计自杀
while time.time() < deadline and len(ticks) < 2:
    time.sleep(0.02)
proxy._sts_refresher_once = orig_once
proxy.CODEARTS_STS_TICK_SECONDS = orig_tick
check("codearts-sts 线程已启动且为 daemon",
      thread is not None and thread.daemon is True, threading.enumerate())
check("巡检函数至少被 tick 了两次", len(ticks) >= 2, ticks)

print()
print("[4] 常量自洽：巡检间隔必须显著小于续期 margin")

check("tick(%.0fs) < margin(%.0fs)"
      % (proxy.CODEARTS_STS_TICK_SECONDS, proxy.CODEARTS_REFRESH_MARGIN),
      proxy.CODEARTS_STS_TICK_SECONDS < proxy.CODEARTS_REFRESH_MARGIN / 2)

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

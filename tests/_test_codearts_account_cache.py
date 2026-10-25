# -*- coding: utf-8 -*-
"""账号弹窗提速的两块地基：credit_package 的按 AK 缓存 + 账号列表并行化。

不联网。背景：面板打开「码道账号」弹窗（或每 5 秒轮询）会为每个账号串行打
两路上游 HTTP（credit_package ~1-2s + welfare_daily），2 个账号就是 4 次串行
等待 —— 「每次进去都加载很久」。修复是两件事：credit_package 自己带与
_welfare_cache 同款（60s TTL / 失败 30s / 锁）的缓存；_get_codearts_accounts
把每账号的两路查询放进线程池并行。这个套件把两件事都钉住。

跑法：python tests/_test_codearts_account_cache.py
"""
import io
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolated_dirs import isolated_data_dirs  # noqa: E402
isolated_data_dirs("wb-codearts-account-cache-")

import ca_codearts as C  # noqa: E402
import ca_proxy as P  # noqa: E402

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  | " + str(extra) if extra else ""))


class _Counter:
    """桩掉 ca_codearts._http：数请求次数，回一份固定 payload。"""

    def __init__(self, payload=None, exc=None):
        self.payload = payload if payload is not None else {
            "metrics": [{"name": "usageTotalPackageCredit",
                         "package_credit_amount": 100.0,
                         "package_credit_used": 40.0,
                         "package_credit_remain": 60.0}],
            "package": {"package_name_cn": "体验版"},
            "start_date": "2026-10-15", "end_date": "2026-11-16",
        }
        self.exc = exc
        self.calls = []
        self.lock = threading.Lock()

    def __call__(self, method, url, headers=None, body=None, timeout=None,
                 query=None):
        with self.lock:
            self.calls.append(url)
        if self.exc is not None:
            raise self.exc
        return json.loads(json.dumps(self.payload))


def _with_stub(counter, fn):
    saved = C._http
    C._http = counter
    try:
        return fn()
    finally:
        C._http = saved


print("== credit_package 按 AK 缓存（与 _welfare_cache 同款） ==")

# 1. 缓存命中：同一 AK 第二次调用不再落 HTTP，结果一致。
stub = _Counter()
_c1 = _with_stub(stub, lambda: C.credit_package("AK-hit", "SK", "TOK"))
_c2 = _with_stub(stub, lambda: C.credit_package("AK-hit", "SK", "TOK"))
check("第二次调用不落 HTTP（桩只被打一次）", len(stub.calls) == 1, stub.calls)
check("两次结果一致", _c1 == _c2 and _c1["used"] == 40.0, (_c1, _c2))

# 2. 不同 AK 各自取：按 AK 隔离，不是全局一份。
_c3 = _with_stub(stub, lambda: C.credit_package("AK-other", "SK", "TOK"))
check("不同 AK 各打一次上游", len(stub.calls) == 2, stub.calls)
check("另一个 AK 拿到的也是解析结果", _c3["total"] == 100.0, _c3)

# 3. TTL 过期后重新取。直接把缓存条目的到期时间拨到过去 —— 不真等 60 秒。
saved_ttl = C.CREDIT_CACHE_TTL
C.CREDIT_CACHE_TTL = 0.0   # 写入即过期
try:
    _c4 = _with_stub(stub, lambda: C.credit_package("AK-ttl", "SK", "TOK"))
    n_after_first = len(stub.calls)
    _c5 = _with_stub(stub, lambda: C.credit_package("AK-ttl", "SK", "TOK"))
    check("TTL 过期后重新落 HTTP", len(stub.calls) == n_after_first + 1,
          (n_after_first, len(stub.calls)))
    check("过期后取到相同结果", _c4 == _c5, (_c4, _c5))
finally:
    C.CREDIT_CACHE_TTL = saved_ttl

# 4. 失败短缓存：第一次失败把错误缓存住，TTL 内重试不再打上游。
C._credit_cache.clear()
err_stub = _Counter(exc=C.CodeArtsError("上游炸了"))
_n = 0


def _raise_twice():
    global _n
    for _ in range(2):
        try:
            _with_stub(err_stub, lambda: C.credit_package("AK-fail", "SK", "TOK"))
            _n += 0  # 不该到这里
        except C.CodeArtsError as exc:
            _n += 1
            _last = str(exc)
    return _n, _last


_count, _msg = _raise_twice()
check("失败重试只打一次上游（错误被短缓存）",
      _count == 2 and len(err_stub.calls) == 1, (err_stub.calls, _count))
check("缓存命中的失败原样抛出", "上游炸了" in _msg, _msg)

# 5. None 是成功值（账号没有体验版套餐）：不许被当成失败、也不许每次都重打。
C._credit_cache.clear()
none_stub = _Counter(payload={"metrics": [], "package": {}})
_n1 = _with_stub(none_stub, lambda: C.credit_package("AK-none", "SK", "TOK"))
_n2 = _with_stub(none_stub, lambda: C.credit_package("AK-none", "SK", "TOK"))
check("没有套餐返回 None 且被缓存（不重复打上游）",
      _n1 is None and _n2 is None and len(none_stub.calls) == 1,
      (none_stub.calls, _n1, _n2))

# 6. use_cache=False：跳过读缓存照打上游，但结果照写缓存。
C._credit_cache.clear()
stub = _Counter()
_with_stub(stub, lambda: C.credit_package("AK-fresh", "SK", "TOK"))
_f = _with_stub(stub, lambda: C.credit_package("AK-fresh", "SK", "TOK", use_cache=False))
check("use_cache=False 绕开缓存读", len(stub.calls) == 2, stub.calls)
_g = _with_stub(stub, lambda: C.credit_package("AK-fresh", "SK", "TOK"))
check("use_cache=False 的结果仍写回缓存", len(stub.calls) == 2 and _f == _g,
      stub.calls)

# 7. 并发冒烟：多线程同时打同一个 AK，不炸、结果一致、上游调用有界（没有
# single-flight，最坏情况是几个线程各打一次，但 dict 的读写都必须在锁内完成）。
C._credit_cache.clear()
conc_stub = _Counter()
_results = []
_errors = []


def _hammer():
    try:
        _results.append(_with_stub(
            conc_stub, lambda: C.credit_package("AK-race", "SK", "TOK")))
    except Exception as exc:  # noqa: BLE001
        _errors.append(exc)


_threads = [threading.Thread(target=_hammer) for _ in range(8)]
for _t in _threads:
    _t.start()
for _t in _threads:
    _t.join()
check("8 线程并发取同一 AK：无异常", not _errors, _errors)
check("8 线程并发取同一 AK：结果一致",
      all(r == _results[0] for r in _results), _results)
check("8 线程并发取同一 AK：上游调用有界",
      1 <= len(conc_stub.calls) <= 8, conc_stub.calls)

C._credit_cache.clear()
# credit_package_clear_cache：全清 / 按 AK 清。
stub = _Counter()
_with_stub(stub, lambda: C.credit_package("AK-x1", "SK", "TOK"))
_with_stub(stub, lambda: C.credit_package("AK-x2", "SK", "TOK"))
C.credit_package_clear_cache("AK-x1")
_with_stub(stub, lambda: C.credit_package("AK-x1", "SK", "TOK"))
_with_stub(stub, lambda: C.credit_package("AK-x2", "SK", "TOK"))
check("按 AK 清缓存：只让目标账号重新取",
      len(stub.calls) == 3, stub.calls)
C.credit_package_clear_cache()
_with_stub(stub, lambda: C.credit_package("AK-x2", "SK", "TOK"))
check("全清后重新取", len(stub.calls) == 4, stub.calls)

# welfare 缓存的锁真的在位（并行化前置条件的回归钉）。
check("_welfare_cache 读写走锁", hasattr(C, "_welfare_cache_lock")
      and isinstance(C._welfare_cache_lock, type(threading.Lock())), "")
check("_credit_cache 读写走锁", isinstance(C._credit_cache_lock,
                                           type(threading.Lock())), "")

print()
print("== /accounts/codearts 并行化（每账号两路查询进线程池） ==")


def _sess(aid):
    return {"accessKey": "AK-" + aid, "secretKey": "SK-" + aid,
            "securitytoken": "TOK", "account": {"id": aid, "label": "账号" + aid},
            "expires_at": "2099-01-01T00:00:00.000Z"}


class _FakeServer:
    server_address = ("127.0.0.1", 9000)


class _FakeAccountsHandler:
    """只补 _get_codearts_accounts 用到的三样：鉴权、_json、server 地址。"""

    server = _FakeServer()

    def __init__(self):
        self.sent = None

    def _authorized(self):
        return True

    def _json(self, status, obj):
        self.sent = (status, obj)
        return obj


def _setup_accounts(aids):
    P_ACCOUNTS = P.ACCOUNTS_DIR
    for aid in aids:
        C.save_session(P_ACCOUNTS, _sess(aid))


# 两账号 + 屏障桩：每个账号的 credit_package 都要在屏障前等到**另一个账号也
# 进来了**才放行 —— 串行执行会在这里超时炸（BrokenBarrierError → creditError），
# 并行执行则两次 wait 都顺利通过。这是并行与否的确定性判据，不靠计时。
_barrier = threading.Barrier(2, timeout=30)
_credit_seen = []
_welfare_seen = []


def _stub_credit(ak, sk, tok, **kw):
    _credit_seen.append(ak)
    _barrier.wait()
    return {"used": 1, "total": 10, "remaining": 9, "percent": 10.0,
            "package_name": "体验版", "package_type": "", "status": "",
            "start_date": None, "end_date": None, "basic": None, "bonus": None,
            "ondemand": None, "token_usage": None}


def _stub_welfare(ak, sk, tok, **kw):
    _welfare_seen.append(ak)
    return {"campaign_id": 1, "title": "每日签到领1000积分", "type": "USER_LOGIN",
            "status": "ELIGIBLE", "amount": 1000, "unit": "CREDIT",
            "claimable": True, "description": "", "claimed_at": "",
            "expire_at": ""}


_saved_credit = C.credit_package
_saved_welfare = C.welfare_daily
_saved_cap = P.codearts_concurrency
C.credit_package = _stub_credit
C.welfare_daily = _stub_welfare
P.codearts_concurrency = lambda: 2
P._STS_DEAD_EXTERNALLY.clear()
try:
    _setup_accounts(["acc1", "acc2"])
    _h = _FakeAccountsHandler()
    P.Handler._get_codearts_accounts(_h)
    _payload = _h.sent[1] if _h.sent else {}
finally:
    C.credit_package = _saved_credit
    C.welfare_daily = _saved_welfare
    P.codearts_concurrency = _saved_cap

_accounts = _payload.get("accounts") or []
check("两个账号都进了响应", len(_accounts) == 2,
      [a.get("account_id") for a in _accounts])
check("两个账号的 credit 都取到了（并行过屏障，未超时炸）",
      all(a.get("credit") == {"used": 1, "total": 10, "remaining": 9,
                              "percent": 10.0, "package_name": "体验版",
                              "package_type": "", "status": "", "start_date": None,
                              "end_date": None, "basic": None, "bonus": None,
                              "ondemand": None, "token_usage": None}
          for a in _accounts),
      [(a.get("account_id"), a.get("credit"), a.get("creditError"))
       for a in _accounts])
check("两个账号的 welfare 都取到了",
      all(a.get("welfare", {}).get("status") == "ELIGIBLE" for a in _accounts),
      [(a.get("account_id"), a.get("welfare"), a.get("welfareError"))
       for a in _accounts])
check("没有 creditError / welfareError",
      all("creditError" not in a and "welfareError" not in a for a in _accounts),
      _accounts)
check("每账号一次 credit + 一次 welfare（与串行相同的调用面）",
      sorted(_credit_seen) == ["AK-acc1", "AK-acc2"]
      and sorted(_welfare_seen) == ["AK-acc1", "AK-acc2"],
      (_credit_seen, _welfare_seen))
check("响应带 upstream_slots（网关并发 vs 上游名额分开说）",
      _payload.get("upstream_slots") == P.CODEARTS_UPSTREAM_SLOTS,
      _payload.get("upstream_slots"))
check("响应带 concurrency_per_account（网关信号量容量）",
      _payload.get("concurrency_per_account") == 2,
      _payload.get("concurrency_per_account"))
check("每号 runtime 容量与网关并发一致（snapshot 填的是信号量，不是上游名额）",
      all(a.get("runtime", {}).get("capacity") == 2 for a in _accounts),
      [a.get("runtime") for a in _accounts])
check("summarize 字段照旧齐全（并行化不丢列）",
      all(a.get("account") and a.get("expires_at") and "file" in a
          and "sts_dead_external" in a for a in _accounts),
      _accounts)

# 并行化之后结果与串行一致：把屏障桩换成普通桩，同一批会话再跑一遍，
# 与上面那份响应逐字段比（runtime/cooldown 这类运行期状态本来就是同一来源）。
def _plain_credit(ak, sk, tok, **kw):
    return {"used": 1, "total": 10, "remaining": 9, "percent": 10.0,
            "package_name": "体验版", "package_type": "", "status": "",
            "start_date": None, "end_date": None, "basic": None, "bonus": None,
            "ondemand": None, "token_usage": None}


_saved_credit = C.credit_package
_saved_welfare = C.welfare_daily
_saved_cap = P.codearts_concurrency
C.credit_package = _plain_credit
C.welfare_daily = _stub_welfare
P.codearts_concurrency = lambda: 2
try:
    _h2 = _FakeAccountsHandler()
    P.Handler._get_codearts_accounts(_h2)
    _payload2 = _h2.sent[1] if _h2.sent else {}
finally:
    C.credit_package = _saved_credit
    C.welfare_daily = _saved_welfare
    P.codearts_concurrency = _saved_cap

_by_id = {a["account_id"]: a for a in _accounts}
_by_id2 = {a["account_id"]: a for a in (_payload2.get("accounts") or [])}
check("并行与串行的账号字段逐项一致",
      sorted(_by_id) == sorted(_by_id2) and all(
          _by_id[k].get("credit") == _by_id2[k].get("credit")
          and _by_id[k].get("welfare") == _by_id2[k].get("welfare")
          and _by_id[k].get("sts_expired") == _by_id2[k].get("sts_expired")
          and _by_id[k].get("runtime") == _by_id2[k].get("runtime")
          for k in _by_id),
      "compare failed")

# 单账号 / 空列表不炸（workers 计算的下界）。
_saved_credit = C.credit_package
_saved_welfare = C.welfare_daily
C.credit_package = _plain_credit
C.welfare_daily = _stub_welfare
try:
    for f in os.listdir(os.path.join(P.ACCOUNTS_DIR, "codearts")):
        os.remove(os.path.join(P.ACCOUNTS_DIR, "codearts", f))
    _h3 = _FakeAccountsHandler()
    P.Handler._get_codearts_accounts(_h3)
    check("空账号列表照常返回空", _h3.sent[1]["accounts"] == []
          and _h3.sent[1]["count"] == 0, _h3.sent)
    C.save_session(P.ACCOUNTS_DIR, _sess("solo"))
    _h4 = _FakeAccountsHandler()
    P.Handler._get_codearts_accounts(_h4)
    check("单账号照常返回", len(_h4.sent[1]["accounts"]) == 1, _h4.sent)
finally:
    C.credit_package = _saved_credit
    C.welfare_daily = _saved_welfare

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

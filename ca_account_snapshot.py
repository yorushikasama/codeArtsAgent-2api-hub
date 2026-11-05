"""账号面板的积分 / 签到快照：定时拉取、落盘，面板只读。

## 为什么要这个文件

面板打开时要按账号查两路上游：积分（`credit_package`）和每日签到
（`welfare_daily`）。线上实测（4 账号，2026-11-04）：

    credit  cold  2.594s      welfare cold  1.101s
    credit  warm  0.000s      welfare warm  0.000s

进程内本来就有 60 秒 TTL 的缓存，所以**热的时候是 0 秒**。慢的场景有三个：

1. **进程重启后缓存全空** —— 重启后第一次进面板必然等一整个冷启动
   （4 账号并行也要 3.6 秒，瓶颈是单账号那两路上游）。
2. **TTL 60 秒 vs 面板 5 秒轮询** —— 离开一两分钟再回来，值已经过期，
   `allow_stale` 只能先给旧值再后台刷；「刚过期那一下」仍会撞同步请求。
3. **失败缓存只有 30 秒** —— 那个 1806 死号每次都要白等 1.4 秒再报错。

这个模块把这件事从「请求路径上的懒加载」改成**后台定时物化**：一个 daemon
线程每 `ACCOUNT_SNAPSHOT_TICK` 秒拉一遍全部账号，写进
`accounts/account-snapshot.json`；面板直接读文件，实测 0 秒。

## 几条设计约束（都是踩过的坑）

- **面板读盘失败时必须还能用**。文件不存在 / 半截 JSON / 版本不认识，一律
  退回原来的「请求时现取」路径，绝不因为快照坏了就让面板打不开。
- **写盘是原子的**（临时文件 + os.replace）。面板进程可能在任意时刻读到
  这个文件，写一半被读到就是坏 JSON。
- **快照是缓存，不是事实来源**。它只存展示用的数字，不存任何凭据；删掉它
  的后果只是「下一次进面板慢 3.6 秒」，不是数据丢失。
- **不要每个 tick 都重写文件**。上游数字没变时不落盘，避免路由器上 flash
  被无意义地写（与用量 checkpoint 同一条顾虑）。
"""
import json
import os
import threading
import time

import ca_env

SNAPSHOT_FILE = "account-snapshot.json"

#: 快照 schema。字段增删时 +1，读到不认识的就当没有（退回慢路径）。
SNAPSHOT_SCHEMA = 1

#: 后台刷新间隔（秒）。上游这两路是「余额」类数据，一分钟一变已经够密；
#: 比它更快只会让上游以为我们在轮询。
ACCOUNT_SNAPSHOT_TICK = ca_env.number("CODEARTS_ACCOUNT_SNAPSHOT_TICK", 60.0,
                                      minimum=10.0)

#: 超过这么久没刷新成功，面板上就标「数据可能过期」。
ACCOUNT_SNAPSHOT_STALE = ca_env.number("CODEARTS_ACCOUNT_SNAPSHOT_STALE", 300.0,
                                       minimum=60.0)

_state = {
    "snapshot": None,      # 最近一次成功写出的内容（内存副本，省一次读盘）
    "path": None,          # 上次读写的路径，换 accounts 目录时据此重载
    "lock": threading.Lock(),
}


def snapshot_path(accounts_dir):
    return os.path.join(accounts_dir, SNAPSHOT_FILE)


def load_snapshot(accounts_dir):
    """读快照；没有 / 坏了 / 版本不认识都返回 None（调用方退回慢路径）。"""
    path = snapshot_path(accounts_dir)
    with _state["lock"]:
        cached = _state["snapshot"]
        if cached is not None and _state["path"] == path:
            return cached
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("schema") != SNAPSHOT_SCHEMA:
        return None
    accounts = raw.get("accounts")
    if not isinstance(accounts, dict):
        return None
    with _state["lock"]:
        _state["snapshot"] = raw
        _state["path"] = path
    return raw


def snapshot_age(raw, now=None):
    """快照距今多少秒；没有时间戳返回 None。"""
    if not isinstance(raw, dict):
        return None
    at = raw.get("at")
    if not isinstance(at, (int, float)) or at <= 0:
        return None
    return max(0.0, (now if now is not None else time.time()) - at)


def account_entry(raw, account_id):
    """快照里某个账号的 {credit, welfare}；没有就返回 None。

    键用 account id（`01a11965c88b…`），不用 AK：AK 是凭据，哪怕只是截断
    展示也不该成为落盘索引；account id 本来就在会话文件和用量日志里。
    """
    if not isinstance(raw, dict):
        return None
    accounts = raw.get("accounts")
    if not isinstance(accounts, dict):
        return None
    entry = accounts.get(str(account_id or ""))
    return entry if isinstance(entry, dict) else None


def write_snapshot(accounts_dir, entries, now=None):
    """原子写快照。`entries` 是 {account_id: {credit, welfare}}。

    返回写出的 dict；写盘失败也不抛 —— 调用方是后台线程，坏一次不影响服务
    （内存副本仍然更新，面板在同进程内照样命中）。
    """
    stamp = now if now is not None else time.time()
    payload = {"schema": SNAPSHOT_SCHEMA, "at": stamp,
               "accounts": entries or {}}
    path = snapshot_path(accounts_dir)
    with _state["lock"]:
        previous = _state["snapshot"]
        # 数字没变就不落盘：上游余额本来一分钟都可能不动，没必要每 tick
        # 写一次 flash。
        #
        # 但 **`at` 必须照样往前推**：它表示「上次成功刷新完成的时间」，
        # 不是「上次写盘的时间」。两者混为一谈时，上游余额只要几分钟没变
        # （余额本来就常常不动），面板就会误报「5 分钟前的快照」——后台其实
        # 一次都没漏过。这里的 `at` 只进内存副本，落盘的那份在下面按需更新。
        changed = (previous is None
                   or previous.get("accounts") != payload["accounts"])
        _state["snapshot"] = payload
        _state["path"] = path
    if not changed:
        return payload
    tmp = path + ".tmp"
    try:
        os.makedirs(accounts_dir, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return payload


def _fetch_one(session):
    """一个账号的两路上游。任何一路失败都不影响另一路。"""
    import ca_codearts

    out = {}
    access_key = session.get("accessKey")
    secret_key = session.get("secretKey")
    security_token = session.get("securitytoken")
    try:
        out["credit"] = ca_codearts.credit_package(
            access_key, secret_key, security_token, use_cache=False)
    except Exception as exc:                     # noqa: BLE001
        out["credit"] = None
        out["creditError"] = str(exc)[:200]
    try:
        out["welfare"] = ca_codearts.welfare_daily(
            access_key, secret_key, security_token, use_cache=False)
    except Exception as exc:                     # noqa: BLE001
        out["welfare"] = None
        out["welfareError"] = str(exc)[:200]
    return out


def refresh_once(accounts_dir=None, log=None):
    """拉一遍全部账号并落盘。返回写出的快照（或 None）。

    给后台线程和测试共用。单个账号失败**不拆整份快照**：其余账号的数字
    仍然是新鲜的，把整份丢掉只会让所有人都退回慢路径。
    """
    import concurrent.futures

    import ca_codearts

    try:
        sessions = ca_codearts.load_sessions(accounts_dir)
    except Exception as exc:                     # noqa: BLE001
        if log:
            log("account-snapshot: cannot load sessions: %s" % exc)
        return None
    if not sessions:
        return write_snapshot(accounts_dir, {})

    workers = min(8, max(1, len(sessions) * 2))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            fetched = list(pool.map(_fetch_one, sessions))
    except Exception:                            # noqa: BLE001  线程池起不来
        fetched = [_fetch_one(session) for session in sessions]

    entries = {}
    for session, extra in zip(sessions, fetched):
        acct = session.get("account") or {}
        account_id = str(acct.get("id") or "")
        if account_id:
            entries[account_id] = extra
    return write_snapshot(accounts_dir, entries)


def _loop(accounts_dir, log):
    while True:
        try:
            if not _shutting_down():
                refresh_once(accounts_dir, log=log)
        except Exception as exc:                 # noqa: BLE001  兜底，别死线程
            if log:
                log("account-snapshot: loop error: %r" % (exc,), level="WARN")
        time.sleep(ACCOUNT_SNAPSHOT_TICK)


#: ca_proxy 在启动时注入自己的 shutting_down()，让退出时不再起新的一轮
#: 上游请求（否则 SIGTERM 之后还要等一轮 3.6 秒的 HTTP 才肯退出）。
_SHUTDOWN_PROBE = lambda: False                    # noqa: E731


def bind(shutting_down=None):
    global _SHUTDOWN_PROBE
    if shutting_down is not None:
        _SHUTDOWN_PROBE = shutting_down


def _shutting_down():
    try:
        return bool(_SHUTDOWN_PROBE())
    except Exception:                            # noqa: BLE001
        return False


def start_refresher(accounts_dir, log):
    """起后台刷新线程。已在跑就不再起第二个（重复调用是安全的）。"""
    with _state["lock"]:
        existing = _state.get("thread")
        if existing is not None and existing.is_alive():
            return existing
        thread = threading.Thread(target=_loop, args=(accounts_dir, log),
                                  name="codearts-account-snapshot", daemon=True)
        _state["thread"] = thread
    thread.start()
    if log:
        log("accounts   : snapshot refresher on (tick %.0fs, stale %.0fs)"
            % (ACCOUNT_SNAPSHOT_TICK, ACCOUNT_SNAPSHOT_STALE))
    return thread


def reset():
    """丢开内存副本（测试用；磁盘文件不动）。"""
    with _state["lock"]:
        _state["snapshot"] = None
        _state["path"] = None

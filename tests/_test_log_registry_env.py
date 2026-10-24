"""日志、配置、登记表与落盘配额（2026-10-23 第四轮）。

这一批都是「不报错，但东西在悄悄变形」的问题：

1. **上游错误体带换行，一条日志被拆成两条**：``log()`` 原样把消息写进
   stderr，``{"error_msg": "bad request\\r\\n at line 3"}`` 于是变成一条
   有前缀的行 + 一条没有前缀的行。线上已出现 14 次。
2. **重试日志的 "N/3" 分母与真实轮数不符**：TMP 限流那条用的是 4 轮退避
   （5/12/25/40），日志也写 "/3"。
3. **日志没有请求 id**：一次请求的重试、断流、失败是三条独立日志，并发一
   起来就对不上号。
4. **环境变量设成 "0" 或非数字**：前者悄悄关掉功能，后者让网关在 import
   阶段 ValueError 退出，连端口都没开始监听。
5. **会话登记表**：坏数据（字符串条目 / at 不是数字）会让清理线程抛出，
   剩下的会话一条都不补发；凭据按 label 索引，重名时拿错号；每次心跳都要
   整文件读 + 整文件写。
6. **failed-req-*.json 没有总数上限**：只按「5 分钟内一份」限速，长期运行
   的部署会攒出一堆没人管的快照。
7. **签到永久失败被无限重试**：``invalid channel`` 这类错误与时间无关，按
   30 秒缓存等于每 30 秒必失败一次，一天两千多次，历史里攒了 100 条。

不联网。
"""

import io
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_activity as A  # noqa: E402
import ca_codearts as C  # noqa: E402
import ca_env as E       # noqa: E402
import ca_proxy as P     # noqa: E402

PASS = FAIL = 0


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def section(name):
    print("\n" + name)


_tmp = tempfile.mkdtemp(prefix="round4-")
P.ACCOUNTS_DIR = _tmp
P.USAGE_LOG = os.path.join(_tmp, "usage.jsonl")


# ---------------------------------------------------------------------------
# 1. 日志：换行转义 + 一条消息只有一行
# ---------------------------------------------------------------------------

section("1. log() 不把一条消息写成两行")

check("裸换行被转义成两个字面字符",
      P._one_line("a\nb") == "a\\nb", P._one_line("a\nb"))
check("CRLF 两个都转义", P._one_line("a\r\nb") == "a\\r\\nb",
      P._one_line("a\r\nb"))
check("制表符也转义（列对齐会骗人）",
      P._one_line("x\ty") == "x\\ty", P._one_line("x\ty"))
check("其余控制字符走 \\xNN", P._one_line("a\x00b") == "a\\x00b",
      P._one_line("a\x00b"))
check("普通文本原样（不做无谓改写）",
      P._one_line("plain text here") == "plain text here")
check("末尾空白照旧裁掉", P._one_line("trail   ") == "trail")
check("中间的空白不动", P._one_line("a  b") == "a  b")
check("结果里没有一个裸换行",
      "\n" not in P._one_line("x\ny\nz\n") and "\r" not in P._one_line("x\ry"))

# 真正走一遍 log()：stderr 里只能多出**一行**。
_buf = io.StringIO()
_saved_stderr = sys.stderr
sys.stderr = _buf
try:
    P.log("upstream said:\nAPIG.0203 backend timeout\nretry?")
finally:
    sys.stderr = _saved_stderr
_lines = [ln for ln in _buf.getvalue().split("\n") if ln]
check("一条消息只产生一行 stderr", len(_lines) == 1, _lines)
check("转义出现在那一行里", "\\nAPIG.0203" in _lines[0], _lines[0])

_entry = P.add_log_entry("body:\r\nsecond line")
check("面板/落库的 msg 同样是一条",
      "\n" not in _entry["msg"] and "\r" not in _entry["msg"], _entry["msg"])


# ---------------------------------------------------------------------------
# 2. 请求 id：同一条请求的日志能被串起来
# ---------------------------------------------------------------------------

section("2. 请求 id 出现在日志行首")

P.set_request_id("abc12345")
_buf = io.StringIO()
_saved_stderr = sys.stderr
sys.stderr = _buf
try:
    P.log("codearts retry 1/3 (busy): model=m")
finally:
    sys.stderr = _saved_stderr
_line = [ln for ln in _buf.getvalue().split("\n") if ln][0]
check("行首带 [请求 id]", "[abc12345]" in _line, _line)
P.set_request_id("")
_buf = io.StringIO()
sys.stderr = _buf
try:
    P.log("no request context")
finally:
    sys.stderr = _saved_stderr
_line = [ln for ln in _buf.getvalue().split("\n") if ln][0]
check("没有请求上下文时不硬塞一个空方括号", "[]" not in _line, _line)
check("id 是 8 位十六进制",
      len(P.new_request_id()) == 8
      and all(c in "0123456789abcdef" for c in P.new_request_id()))

# 线程隔离：别的线程不该看到这条请求的 id（否则日志会互相串）。
import threading  # noqa: E402
_seen = {}


def _other():
    _seen["id"] = P.current_request_id()


P.set_request_id("main0001")
_t = threading.Thread(target=_other)
_t.start()
_t.join()
P.set_request_id("")
check("请求 id 是按线程记的（不会串到别的请求上）",
      _seen.get("id") == "", _seen)


# ---------------------------------------------------------------------------
# 3. 重试日志：分母跟着实际那套退避走
# ---------------------------------------------------------------------------

section("3. 重试日志的分母与真实轮数一致")

_src = io.open(P.__file__, encoding="utf-8").read()
check("两条重试日志都标出了退避类型",
      'codearts retry %d/%d (%s)' in _src
      and 'codearts open retry %d/%d (%s)' in _src, None)
check("TPM 那套确实是 4 轮（分母不会再被写成 3）",
      len(P.CODEARTS_RETRY_DELAYS) == 4, P.CODEARTS_RETRY_DELAYS)
check("名额满那套是 3 轮", len(P.CODEARTS_BUSY_DELAYS) == 3,
      P.CODEARTS_BUSY_DELAYS)
check("两套退避都写进了日志模板（不是只写死一个数）",
      'delay_kind = "tpm"' in _src and 'delay_kind = "busy"' in _src, None)


# ---------------------------------------------------------------------------
# 4. 环境变量：坏值与 "0"
# ---------------------------------------------------------------------------

section("4. 环境变量坏值回落默认、不崩")


def _env(name, value, default, **kw):
    saved = os.environ.get(name)
    os.environ[name] = value
    try:
        return E.number(name, default, **kw)
    finally:
        if saved is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = saved


check("非数字回落默认", _env("ZZ_T1", "20s", 20.0) == 20.0,
      _env("ZZ_T1", "20s", 20.0))
check("空串回落默认", _env("ZZ_T1", "   ", 20.0) == 20.0)
check("未设置回落默认", E.number("ZZ_DEFINITELY_UNSET", 7.0) == 7.0)
check("正常值照常生效", _env("ZZ_T1", "35", 20.0) == 35.0)
check('"0" 默认不算合法值（回到默认，而不是悄悄关掉功能）',
      _env("ZZ_T1", "0", 20.0) == 20.0, _env("ZZ_T1", "0", 20.0))
check("显式 zero_ok 时 0 才生效",
      _env("ZZ_T1", "0", 20.0, zero_ok=True) == 0.0)
check("低于下限回落默认",
      _env("ZZ_T1", "-5", 20.0, minimum=1.0) == 20.0)
check("整型解析带空白也认", _env("ZZ_T1", " 12 ", 3, integer=True) == 12)

saved = os.environ.get("CODEARTS_SLOT_WAIT")
os.environ["CODEARTS_SLOT_WAIT"] = "20 seconds"
try:
    import importlib
    P2 = importlib.reload(P)
    check("坏值不会让网关在 import 阶段退出",
          P2.CODEARTS_SLOT_WAIT == 20.0, P2.CODEARTS_SLOT_WAIT)
finally:
    if saved is None:
        os.environ.pop("CODEARTS_SLOT_WAIT", None)
    else:
        os.environ["CODEARTS_SLOT_WAIT"] = saved
    P = importlib.reload(P)
    P.ACCOUNTS_DIR = _tmp
    P.USAGE_LOG = os.path.join(_tmp, "usage.jsonl")

check("flag() 认 0/1/true/false，认不出来用默认",
      E.flag("ZZ_NOPE", True) is True)


# ---------------------------------------------------------------------------
# 5. 会话登记表
# ---------------------------------------------------------------------------

section("5. 会话登记表：坏数据、重名凭据、心跳不整文件读写")

_path = P._sessions_path()
os.makedirs(os.path.dirname(_path) or _tmp, exist_ok=True)

# 5.1 坏形状：字符串条目、at 不是数字、顶层不是 dict
with open(_path, "w", encoding="utf-8") as _fh:
    json.dump({"good": {"at": time.time(), "uid": "u1", "acct": "L"},
               "string-entry": "oops",
               "bad-at": {"at": "yesterday", "acct": "L"},
               "no-at": {"acct": "L"}}, _fh)
_data = P._sessions_read()
check("字符串条目被丢掉（不是整表读成空）",
      "string-entry" not in _data and "good" in _data, sorted(_data))
check("at 读不出来时按 0 处理，不是让读取方炸掉",
      _data.get("bad-at", {}).get("at") == 0.0, _data.get("bad-at"))
check("缺 at 同样按 0", _data.get("no-at", {}).get("at") == 0.0)
check("uid 被保留（补发 idle 靠它取凭据）",
      _data["good"]["uid"] == "u1", _data["good"])

with open(_path, "w", encoding="utf-8") as _fh:
    _fh.write("[1, 2, 3]")
check("顶层不是对象 -> 空表，不抛", P._sessions_read() == {}, P._sessions_read())

with open(_path, "w", encoding="utf-8") as _fh:
    _fh.write("{not json")
check("半截 JSON -> 空表，不抛", P._sessions_read() == {})

# 5.2 creds 按 uid 索引：两个账号同名，各走各的凭据
with open(_path, "w", encoding="utf-8") as _fh:
    json.dump({"s1": {"at": time.time(), "uid": "id-1"},
               "s2": {"at": time.time(), "uid": "id-2"},
               "s3": {"at": time.time(), "acct": "dup"}}, _fh)
_saved_load = C.load_sessions
_saved_hb = C.heartbeat
_calls = []
C.load_sessions = lambda _d: [
    {"account": {"id": "id-1", "label": "dup"}, "accessKey": "AK1",
     "secretKey": "SK", "securitytoken": "TK"},
    {"account": {"id": "id-2", "label": "dup"}, "accessKey": "AK2",
     "secretKey": "SK", "securitytoken": "TK"},
]
C.heartbeat = lambda *a, **k: (_calls.append((a[3], a[0])), (True, "ok"))[1]
try:
    P.reap_codearts_sessions()
finally:
    C.load_sessions = _saved_load
    C.heartbeat = _saved_hb
_by_session = dict(_calls)
check("uid 索引真的生效：s1 用 AK1、s2 用 AK2",
      _by_session.get("s1") == "AK1" and _by_session.get("s2") == "AK2",
      _calls)
check("重名 label 的兜底键被弃用（s3 不发心跳，不猜号）",
      "s3" not in _by_session, _calls)
_left = P._sessions_read()
check("没凭据可用的那条留着等下次启动（不静默丢账）", "s3" in _left, _left)

# 5.3 单条心跳抛异常不该终止整轮
with open(_path, "w", encoding="utf-8") as _fh:
    json.dump({"a1": {"at": time.time(), "uid": "id-1"},
               "a2": {"at": time.time(), "uid": "id-2"}}, _fh)
_calls.clear()


def _hb_one_boom(cred, sk, tk, sid, kind, **kw):
    _calls.append((sid, kind))
    if sid == "a1":
        raise RuntimeError("network exploded")
    return True, "ok"


C.load_sessions = lambda _d: [
    {"account": {"id": "id-1", "label": "x"}, "accessKey": "AK1",
     "secretKey": "SK", "securitytoken": "TK"},
    {"account": {"id": "id-2", "label": "y"}, "accessKey": "AK2",
     "secretKey": "SK", "securitytoken": "TK"},
]
C.heartbeat = _hb_one_boom
try:
    P.reap_codearts_sessions()
finally:
    C.load_sessions = _saved_load
    C.heartbeat = _saved_hb
check("一条心跳抛异常，剩下的照常补发",
      sorted(s for s, _k in _calls) == ["a1", "a2"], _calls)
check("抛异常那条按失败留着（下次再来）",
      "a1" in P._sessions_read(), P._sessions_read())

# 5.4 心跳不整文件读写：30 次 track 只读盘一次
P._sessions_write({})
P._SESSION_REGISTRY["data"] = None
_reads = {"n": 0}
_orig_read = P._sessions_read


def _counting_read():
    _reads["n"] += 1
    return _orig_read()


P._sessions_read = _counting_read
try:
    for _i in range(30):
        P.track_codearts_session("hb%02d" % _i, "L", "u1")
finally:
    P._sessions_read = _orig_read
check("30 次 busy 心跳只读一次文件（其余走内存副本）",
      _reads["n"] == 1, _reads["n"])
check("登记表内容确实写全了", len(P._sessions_read()) == 30)

# 5.5 上限仍然生效
P._sessions_write({})
for _i in range(P.CODEARTS_SESSION_MAX + 6):
    P.track_codearts_session("cap%02d" % _i, "L", "u1")
check("超过上限时砍到 CODEARTS_SESSION_MAX",
      len(P._sessions_read()) == P.CODEARTS_SESSION_MAX,
      len(P._sessions_read()))
check("砍的是最老的（最新那条一定还在）",
      "cap%02d" % (P.CODEARTS_SESSION_MAX + 5) in P._sessions_read())


# ---------------------------------------------------------------------------
# 6. failed-req 快照：总数与年龄上限
# ---------------------------------------------------------------------------

section("6. failed-req-*.json 有总数上限并自动清理")

_dump_dir = tempfile.mkdtemp(prefix="dumps-")
P.CODEARTS_DUMP_MAX = 5
_saved_max_age = P.CODEARTS_DUMP_MAX_AGE
P.CODEARTS_DUMP_MAX_AGE = 3600.0
try:
    for _i in range(12):
        _p = os.path.join(_dump_dir, "failed-req-%d.json" % _i)
        with open(_p, "w", encoding="utf-8") as _fh:
            _fh.write("{}")
        os.utime(_p, (1000 + _i, 1000 + _i))
    _removed = P._prune_failed_dumps(_dump_dir, now=1011)
    _left_names = sorted(n for n in os.listdir(_dump_dir)
                         if n.startswith("failed-req-"))
    check("超量的旧快照被删掉", _removed == 7, _removed)
    check("只留最新的 N 份", len(_left_names) == 5, _left_names)
    check("留下的确实是最近的那几份",
          _left_names == ["failed-req-10.json", "failed-req-11.json",
                          "failed-req-7.json", "failed-req-8.json",
                          "failed-req-9.json"], _left_names)

    # 年龄：超龄的删，但刚写下的那一份就算超龄也不删（否则上限调小会自杀）。
    # 单独一个目录：混在上面那批里时，旧的会先被「超量」规则删掉，
    # 这条检查就测不到年龄那条分支了。
    _age_dir = tempfile.mkdtemp(prefix="dumps-age-")
    for _i in range(3):
        _p = os.path.join(_age_dir, "failed-req-old%d.json" % _i)
        with open(_p, "w", encoding="utf-8") as _fh:
            _fh.write("{}")
        os.utime(_p, (0, 0))
    _keep = os.path.join(_age_dir, "failed-req-old2.json")
    P._prune_failed_dumps(_age_dir, keep_path=_keep, now=10 ** 6)
    check("超龄的快照被删", not os.path.exists(
        os.path.join(_age_dir, "failed-req-old1.json")))
    check("刚写下的那份不被自己删掉", os.path.exists(_keep))

    # 目录不存在 / 不是目录都不该抛
    check("目录读不到时返回 0 而不是抛",
          P._prune_failed_dumps(os.path.join(_dump_dir, "nope")) == 0)

    # 调用点：落盘之后必须真的修剪，否则上限等于没设。
    _call_dir = tempfile.mkdtemp(prefix="dumps-call-")
    _saved_usage = P.USAGE_LOG
    P.USAGE_LOG = os.path.join(_call_dir, "usage.jsonl")
    _saved_flag = os.environ.get("WB_DUMP_FAILED_TOOLS")
    os.environ["WB_DUMP_FAILED_TOOLS"] = "1"
    # 上一段把年龄上限压到 1 小时了；这里测的是**数量**那条，放开年龄。
    P.CODEARTS_DUMP_MAX_AGE = 10 ** 9
    try:
        for _i in range(P.CODEARTS_DUMP_MAX + 4):
            # 每份的时间戳往前推 1 小时，绕开「5 分钟内只留一份」的限速
            _p = os.path.join(_call_dir, "failed-req-%d.json" % _i)
            with open(_p, "w", encoding="utf-8") as _fh:
                _fh.write("{}")
            _stamp = time.time() - (P.CODEARTS_DUMP_MAX + 4 - _i) * 3600
            os.utime(_p, (_stamp, _stamp))
        P.dump_failed_request({"model": "m", "tools": []}, [], 8)
        _after = [n for n in os.listdir(_call_dir)
                  if n.startswith("failed-req-")]
        check("dump_failed_request 落盘时会修剪（调用点接上了上限）",
              len(_after) == P.CODEARTS_DUMP_MAX, len(_after))
    finally:
        P.USAGE_LOG = _saved_usage
        P.CODEARTS_DUMP_MAX_AGE = 3600.0   # 外层 finally 会再恢复成真值
        if _saved_flag is None:
            os.environ.pop("WB_DUMP_FAILED_TOOLS", None)
        else:
            os.environ["WB_DUMP_FAILED_TOOLS"] = _saved_flag
finally:
    P.CODEARTS_DUMP_MAX_AGE = _saved_max_age
    P.CODEARTS_DUMP_MAX = 20


# ---------------------------------------------------------------------------
# 7. 签到：永久失败不再无限重试
# ---------------------------------------------------------------------------

section("7. 签到永久失败按小时级缓存，不再每 30 秒撞一次")

check("invalid channel 判为永久失败",
      C.welfare_permanent_failure(
          C.CodeArtsError("[4000] invalid channel, group not found")))
check("group not found 判为永久失败",
      C.welfare_permanent_failure(C.CodeArtsError("group not found")))
check("清单里没有每日签到判为永久失败",
      C.welfare_permanent_failure(C.CodeArtsError("活动清单里没有「每日签到」")))
check("401 不算永久失败（重新授权就好）",
      not C.welfare_permanent_failure(C.CodeArtsError("401 unauthorized")))
check("5xx 不算永久失败（抖动）",
      not C.welfare_permanent_failure(
          C.CodeArtsError("HTTP 500", status=500)))
check("429 不算永久失败（等一会儿就好）",
      not C.welfare_permanent_failure(C.CodeArtsError("429 too many")))

_saved_req = C._welfare_request
_saved_cache_clear = dict(C._welfare_cache)
C._welfare_cache.clear()
_polls = {"n": 0}


def _permanent(*a, **k):
    _polls["n"] += 1
    raise C.CodeArtsError("[4000] invalid channel, group not found")


C._welfare_request = _permanent
_saved_time = C.time.time
_clock = {"now": _saved_time()}
C.time.time = lambda: _clock["now"]
try:
    # 面板 5 秒一轮，跑满 20 分钟：短 TTL（30 秒）会在这里打上游 40 次，
    # 小时级 TTL 只打一次。
    for _ in range(240):
        _clock["now"] += 5.0
        try:
            C.welfare_daily("AK-P", "SK", "TK")
        except Exception:
            pass
finally:
    C.time.time = _saved_time
    C._welfare_request = _saved_req
check("20 分钟的轮询只打一次上游（永久失败被记住）",
      _polls["n"] == 1, _polls["n"])

C._welfare_cache.clear()
_soft = {"n": 0}


def _transient(*a, **k):
    _soft["n"] += 1
    raise C.CodeArtsError("HTTP 503 busy", status=503)


C._welfare_request = _transient
_clock2 = {"now": _saved_time()}
C.time.time = lambda: _clock2["now"]
try:
    for _ in range(5):
        _clock2["now"] += 5.0               # 5 次轮询 = 25 秒，仍在短 TTL 内
        try:
            C.welfare_daily("AK-T", "SK", "TK")
        except Exception:
            pass
finally:
    C.time.time = _saved_time
    C._welfare_request = _saved_req
    C._welfare_cache.clear()
    C._welfare_cache.update(_saved_cache_clear)
check("瞬时失败仍按短 TTL 缓存（25 秒内不重复打上游）",
      _soft["n"] == 1, _soft["n"])


# ---------------------------------------------------------------------------
# 8. 出口名与 WorkBuddy 残留
# ---------------------------------------------------------------------------

section("8. realm 只剩 codearts，WorkBuddy 残留已清")

check("DEFAULT_REALM 是 codearts", P.DEFAULT_REALM == "codearts",
      P.DEFAULT_REALM)
check("历史行里的 cn 归一到 codearts",
      P.normalize_realm("cn") == "codearts")
check("历史行里的 intl 同样归一",
      P.normalize_realm("intl") == "codearts")
check("查询 'all' 仍然表示不过滤", P.match_realm("all") == "all")
check("历史别名的桶能查到（不是稳定返回 0）",
      P._count_usage_rows_uncached("cn")
      == P._count_usage_rows_uncached("codearts"))
check("活动历史的 REALMS 同时认新名与老名",
      "codearts" in A.REALMS and "cn" in A.REALMS, A.REALMS)
check("PRODUCT_CONFIG_CACHE（WorkBuddy 桌面缓存）已删除",
      not hasattr(P, "PRODUCT_CONFIG_CACHE"))
check("免费模型判定（WorkBuddy 积分护栏）已删除",
      not hasattr(P, "free_models_by_realm")
      and not hasattr(P, "credits_is_free"))
check("模型条目不再自称 workbuddy",
      P.model_entry("m", {}).get("owned_by") == "codearts",
      P.model_entry("m", {}).get("owned_by"))


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

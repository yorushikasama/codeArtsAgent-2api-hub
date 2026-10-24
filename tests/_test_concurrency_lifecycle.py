"""并发、生命周期与统计口径的回归测试（2026-10-23 第二轮）。

这一批全是「不报错、但结果不对」的问题：统计失真、并发多放行、重试时机错。
每条都用桩复现过，这里钉住修复后的语义。

1. **信号量缩容再扩容多放行**：容量 2 → 1 → 2，实际能跑到 3，正好打满上游的
   3 个会话名额。根因是用 ``capacity - free`` 反推在跑数。
2. **单账号冷却不起作用**：所有号都在冷却时直接拿最早解冻的那个用 ——
   单账号部署里等于冷却完全没作用。
3. **预算估算把每次失败都当 60 秒**：过了 15 秒之后，连 0.1 秒就返回的
   1041 都不再重试；TPM 退避设计 4 次，实际只能用 2 次。
4. **并发上限 8**：上游每号只有 3 个名额，配到 4 以上必然撞 1041。
5. **环境变量不生效**：CODEARTS_CONCURRENCY 等设了也没用，settings 总会
   补上默认值。
6. **错误分类子串匹配过宽**：文本里含「参数」就判 400、5xx 里含
   ``authentication`` 就判凭据失效。
7. **SIGTERM 没有处理**：进程收到信号 0.1 秒就退出，在跑的请求既没有错误
   记录也没有用量记录，``finally`` 里的 idle 发不出去。
8. **本地拒绝不带 Retry-After**，且排不上队的 503 不记账。
9. **Responses / Messages 的首帧之前就发 200**：首帧即 1041 时既不能重试
   也不能换号。
10. **客户端取消不记账**：请求从统计里整个消失。

不联网。
"""

import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C   # noqa: E402
import ca_proxy as P      # noqa: E402
import ca_settings as S   # noqa: E402
import ca_stream as ST    # noqa: E402

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


# ---------------------------------------------------------------------------
# 1. 信号量：缩容再扩容不能多放行
# ---------------------------------------------------------------------------

section("1. 可调信号量的容量换算")

_sem = P._ResizableSemaphore(2)
check("取满后不再放行", _sem.acquire(False) and _sem.acquire(False)
      and not _sem.acquire(False), None)

# 关键回归：2 → 1 → 2 之后，总在跑数不能超过 2。
_s = P._ResizableSemaphore(2)
_s.acquire(False)
_s.acquire(False)
_s.retune(1)                 # 缩容：不能撤回在跑的，只是不再放新人
check("缩容后不再放新人", not _s.acquire(False), _s.capacity)
_s.release()                 # 一个结束了
_s.retune(2)                 # 再扩回来
_granted = 0
while _s.acquire(False):
    _granted += 1
    if _granted > 6:         # 真坏了也别把套件挂住
        break
check("**2→1→2 之后最多只能再进 1 个**（旧实现会多放一个，打满上游 3 个名额）",
      _granted == 1, _granted)
check("容量属性如实反映当前配置", _s.capacity == 2, _s.capacity)

# 缩容到低于在跑数：结束时不把名额加回去（否则等于凭空放行）
_s2 = P._ResizableSemaphore(3)
_s2.acquire(False)
_s2.acquire(False)
_s2.acquire(False)
_s2.retune(1)
_s2.release()
_s2.release()
_s2.release()
check("缩容到 1 之后全部结束，也只能再进 1 个",
      _s2.acquire(False) and not _s2.acquire(False), _s2.capacity)

# 上限夹到上游名额数
_s3 = P._ResizableSemaphore(2)
_s3.retune(99)
check("容量上限夹到上游名额（3），不是面板的 8",
      _s3.capacity == P.CODEARTS_UPSTREAM_SLOTS == 3, _s3.capacity)

# 直接钉住 codearts_concurrency() 的夹取行为：面板写 8 也必须回 3。
_tmpc = tempfile.mkdtemp(prefix="cap-")
_savedc = P.ACCOUNTS_DIR
try:
    P.ACCOUNTS_DIR = _tmpc
    with open(os.path.join(_tmpc, "settings.json"), "w", encoding="utf-8") as _fh:
        json.dump({"codearts": {"concurrency": 8}}, _fh)
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    # 超范围的值按「坏值」处理，退回上一级默认（2）—— 关键是**绝不**变成 8。
    check("手改写 8 不会生效（4 以上必然撞 1041），退回默认 2",
          P.codearts_concurrency() == 2, P.codearts_concurrency())
finally:
    P.ACCOUNTS_DIR = _savedc
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})


# ---------------------------------------------------------------------------
# 2. 单账号冷却要等，不能直接拿去撞
# ---------------------------------------------------------------------------

section("2. 冷却中的账号不能被直接拿去用")


class _StubPool(P._CodeartsAccountPool):
    def __init__(self, keys, state_dir=None):
        P._CodeartsAccountPool.__init__(
            self, state_dir=state_dir or tempfile.mkdtemp(prefix="cool-"))
        self._keys = list(keys)

    def _usable(self):
        return [{"account": {"id": k}} for k in self._keys]


_pool = _StubPool(["solo"])
_pool.penalize("solo", 60)          # 唯一那个号被晾 60 秒


def _acquire_with_guard(pool, budget, model, guard=3.0):
    """在守护线程里跑 acquire，超时直接判失败。

    回退成「冷却也直接拿去用」时，旧实现会立刻返回成功（不会挂住）；但如果
    回退成「无限等解冻」，主线程就卡死了。这里两头都兜住。
    """
    box = {}

    def _run():
        box["out"] = pool.acquire(budget, model=model)

    import threading as _th
    th = _th.Thread(target=_run, daemon=True)
    t0 = time.time()
    th.start()
    th.join(guard)
    return box.get("out"), time.time() - t0


_out, _waited = _acquire_with_guard(_pool, 0.2, "glm-5.3")
_key = (_out or (None, None))[1]
check("**唯一账号在冷却时不会立刻被拿去用**（应等或如实返回没有）",
      _key is None, _key)
check("等待时间不超过本次 acquire 的预算",
      _waited < 1.5, round(_waited, 2))

# 冷却很快解冻时应该等它，而不是立刻失败
_pool2 = _StubPool(["solo"])
_pool2.penalize("solo", 0.15)
_t0 = time.time()
_sess2, _key2 = _pool2.acquire(1.0, model="glm-5.3")
check("短冷却会在预算内等到解冻再用", _key2 == "solo", (_key2, time.time() - _t0))
check("确实是等到解冻之后（不是立刻拿到）",
      time.time() - _t0 >= 0.1, round(time.time() - _t0, 2))

# 多个号里只要有一个没冷却，就正常用它
_pool3 = _StubPool(["cold", "warm"])
_pool3.penalize("cold", 60)
_sess3, _key3 = _pool3.acquire(0.1, model="glm-5.3")
check("有号可用时不被冷却号拖住", _key3 == "warm", _key3)


# ---------------------------------------------------------------------------
# 3. 预算估算：快速失败不该按 60 秒算
# ---------------------------------------------------------------------------

section("3. 重试预算的成本估算")

check("1041（并发会话满）是快速失败",
      ST.slow_failure(400, '{"error_code":"TM.00001041"}') is False, None)
check("429 TPM 限流是快速失败",
      ST.slow_failure(429, '{"error_code":"ModelArts.81114"}') is False, None)
check("参数错是快速失败",
      ST.slow_failure(400, '{"error_code":"InferHub.001001005.400"}') is False, None)
check("5xx 是慢失败（要等满首字节窗口）",
      ST.slow_failure(502, "bad gateway") is True, None)
check("APIG.0203 后端超时是慢失败",
      ST.slow_failure(504, '{"error_code":"APIG.0203"}') is True, None)
check("网络异常（没有状态码、只有异常）按慢失败算",
      ST.slow_failure(None, "", RuntimeError("conn reset")) is True, None)

# 关键回归：已经花了 20 秒之后，快速失败仍然允许重试
_budget = 75.0
_fast_cost = P.CODEARTS_FAST_RETRY_COST
_slow_cost = 60.0
check("已花 20s + 快速失败（2s）仍在预算内 —— 旧实现会判成装不下",
      20.0 + _fast_cost <= _budget, (20.0, _fast_cost, _budget))
check("已花 20s + 慢失败（60s）才该判成装不下",
      20.0 + _slow_cost > _budget, (20.0, _slow_cost, _budget))

# TPM 退避设计 4 次，旧实现实际只能用 2 次
_elapsed, _allowed = 0.0, 0
for _i, _delay in enumerate((5.0, 12.0, 25.0, 40.0)):
    _elapsed += _delay + _fast_cost
    if _elapsed + _fast_cost <= _budget:
        _allowed += 1
check("TPM 退避在预算内能用满 4 次（旧实现按 60s 估只剩 2 次）",
      _allowed >= 3, (_allowed, _elapsed))

check("非流式也有自己的总预算，且比流式的宽松",
      P.CODEARTS_TOTAL_BUDGET > P.CODEARTS_OPEN_BUDGET,
      (P.CODEARTS_TOTAL_BUDGET, P.CODEARTS_OPEN_BUDGET))
check("非流式总预算不超过客户端的 4 分钟超时",
      P.CODEARTS_TOTAL_BUDGET <= 240.0, P.CODEARTS_TOTAL_BUDGET)


# ---------------------------------------------------------------------------
# 4 / 5. 并发上限与环境变量
# ---------------------------------------------------------------------------

section("4. 并发上限与环境变量优先级")

_tmp = tempfile.mkdtemp(prefix="tune-")
_saved_dir = P.ACCOUNTS_DIR
_saved_env = {k: os.environ.get(k) for k in
              ("CODEARTS_CONCURRENCY", "CODEARTS_SESSION_PING")}
try:
    P.ACCOUNTS_DIR = _tmp
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})

    check("没有面板值与环境变量时用内置默认",
          S.codearts_config(_tmp)["concurrency"] == 2,
          S.codearts_config(_tmp)["concurrency"])

    os.environ["CODEARTS_CONCURRENCY"] = "3"
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    check("**环境变量在面板没设过时生效**（以前被默认值覆盖）",
          S.codearts_config(_tmp)["concurrency"] == 3,
          S.codearts_config(_tmp)["concurrency"])
    check("运行时读到的也是环境变量的值",
          P.codearts_concurrency() == 3, P.codearts_concurrency())

    # 面板值优先于环境变量
    S.set_codearts_config(_tmp, {"concurrency": 1})
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    check("面板值优先于环境变量",
          P.codearts_concurrency() == 1, P.codearts_concurrency())

    # 环境变量超范围时退回内置默认（而不是夹），这是「坏值一律不生效」
    # 的一贯口径 —— 但无论哪条路径，运行时值永远不超过上游名额数。
    os.environ["CODEARTS_CONCURRENCY"] = "99"
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    check("环境变量超范围时不生效",
          S.codearts_config(_tmp)["concurrency"] == 1,
          S.codearts_config(_tmp)["concurrency"])
    check("并发永远不超过上游的 3 个会话名额",
          P.codearts_concurrency() <= P.CODEARTS_UPSTREAM_SLOTS,
          P.codearts_concurrency())

    # 面板的取值范围同步收窄：4 以上直接拒
    try:
        S.validate_codearts_patch({"concurrency": 4})
        _rejected = False
    except ValueError:
        _rejected = True
    check("面板拒绝把并发设到 4 以上（上游只有 3 个名额）", _rejected, None)
finally:
    P.ACCOUNTS_DIR = _saved_dir
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    for _k, _v in _saved_env.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v


# ---------------------------------------------------------------------------
# 6. 错误分类不许用宽泛子串
# ---------------------------------------------------------------------------

section("6. 错误分类的边界")

check("说明里带「参数」不再判成 400（那是上游故障）",
      ST.fail_spec(502, "APIG.0203", "后端参数处理失败")[0] == 504,
      ST.fail_spec(502, "APIG.0203", "后端参数处理失败"))
check("明确的参数错误码仍是 400",
      ST.fail_spec(400, "InferHub.001001005.400", "param is invalid")[0] == 400,
      None)
_auth5xx = ST.fail_spec(502, "APIG.0201",
                        "authentication service temporarily unavailable")
check("5xx 说明里出现 authentication 不再判成凭据失效",
      _auth5xx[0] == 502 and _auth5xx[1] == "upstream_error", _auth5xx)
check("真正的凭据错误码仍然判凭据失效",
      ST.fail_spec(401, "APIG.0301", "")[1] == "credentials_error", None)
check("STS 续期票被用过也认",
      ST.fail_spec(400, "STS5.1806", "refresh token used")[1]
      == "credentials_error", None)


# ---------------------------------------------------------------------------
# 7. 优雅退出
# ---------------------------------------------------------------------------

section("7. SIGTERM 与在跑请求")

check("初始状态不在关闭中", P.shutting_down() is False, None)
check("初始在跑数为 0", P.inflight_requests() == 0, P.inflight_requests())

P.request_started()
P.request_started()
check("计数随请求增加", P.inflight_requests() == 2, P.inflight_requests())
P.request_finished()
check("计数随请求减少", P.inflight_requests() == 1, P.inflight_requests())

# wait_for_inflight 会等，但不会超过 grace
import threading as _threading
_t0 = time.time()
_left = P.wait_for_inflight(grace=0.3)
_elapsed = time.time() - _t0
check("有请求没结束时等到 grace 上限就返回（不会无限等）",
      0.25 <= _elapsed < 2.0, round(_elapsed, 2))
check("返回仍未结束的条数", _left == 1, _left)

_worker_done = []


def _finish_later():
    time.sleep(0.15)
    P.request_finished()
    _worker_done.append(True)


_threading.Thread(target=_finish_later, daemon=True).start()
_t0 = time.time()
_left2 = P.wait_for_inflight(grace=3.0)
_elapsed2 = time.time() - _t0
check("请求结束后立刻返回，不用等满 grace",
      _left2 == 0 and _elapsed2 < 1.5, (_left2, round(_elapsed2, 2)))
check("确实是等请求结束才返回", bool(_worker_done), _worker_done)

P.begin_shutdown()
check("关闭标志置位后 shutting_down() 为真", P.shutting_down() is True, None)
# 复位，别影响后面的用例（同进程内共享状态）
P._SHUTTING_DOWN["flag"] = False
check("复位干净", P.shutting_down() is False, None)

check("SIGTERM 处理器可以安装", callable(P.install_sigterm_handler), None)
_src = io.open(P.__file__, encoding="utf-8").read()
check("serve 循环真的装了 SIGTERM 处理器",
      "install_sigterm_handler(server" in _src, None)
check("退出前会把登记表里的会话补发 idle",
      "_drain_sessions" in _src and "reap_codearts_sessions()" in _src, None)
check("聊天入口在关闭中回 503，而不是直接断连",
      "if shutting_down():" in _src, None)


# --- 信号处理器不再堵主线程（2026-10-23）---------------------------------
#
# 旧实现：处理器自己在主线程里 wait_for_inflight(25s)，然后才 server.shutdown()。
# 那 25 秒里 accept 循环不跑，注释承诺的「新连接拿 503」没人应答，连接堆在
# backlog 里、进程退出时被 RST；第二次 Ctrl+C 被 shutting_down() 直接吞掉。
section("7b. SIGTERM 处理器本身不阻塞")

_with_server = type("S", (), {"shutdown": lambda self: _events.append("shutdown")})()
_events = []
P.SHUTDOWN_GRACE_SECONDS, _saved_grace = 0.5, P.SHUTDOWN_GRACE_SECONDS
P._SHUTTING_DOWN["flag"] = False
P._DRAIN_THREAD["thread"] = None
_worker = P.install_sigterm_handler(
    _with_server, on_shutdown=lambda: _events.append("cleanup"))

_t0 = time.time()
_worker(signal.SIGTERM, None)
_elapsed = time.time() - _t0
check("处理器立刻返回（不在主线程里等收尾）", _elapsed < 0.1, round(_elapsed, 4))
check("处理器置了关闭标志", P.shutting_down() is True, None)
check("处理器起了收尾线程", P._DRAIN_THREAD["thread"] is not None, None)

_deadline = time.time() + 5
while time.time() < _deadline and len(_events) < 2:
    time.sleep(0.02)
time.sleep(0.05)
check("收尾线程先停 accept、再补发 idle",
      _events[:2] == ["shutdown", "cleanup"], _events)

# 第二个信号必须立刻走人（不能等 grace 走完）。os._exit 在子进程里验，免得
# 把测试进程杀了。
_child = subprocess.run(
    [sys.executable, "-c", (
        "import os, signal, sys, tempfile\n"
        "w = tempfile.mkdtemp(prefix='sig2-')\n"
        "os.environ['WB_PROXY_USAGE_DIR'] = os.path.join(w, 'usage')\n"
        "os.environ['HOME'] = w\n"
        "os.environ['USERPROFILE'] = w\n"
        "sys.path.insert(0, %r)\n"
        "import ca_proxy as P\n"
        "P.SHUTDOWN_GRACE_SECONDS = 30.0\n"
        "class S:\n"
        "    def shutdown(self): pass\n"
        "h = P.install_sigterm_handler(S(), on_shutdown=lambda: None)\n"
        "h(signal.SIGTERM, None)\n"
        "h(signal.SIGTERM, None)\n"
        "print('second signal returned - os._exit did not fire')\n"
    ) % os.path.dirname(os.path.abspath(P.__file__))],
    capture_output=True, text=True, timeout=30)
check("第二个信号立刻退出（exit=1，不是等满 grace）",
      _child.returncode == 1, (_child.returncode, _child.stderr[-200:]))

# 复位：后面的用例还在同一个进程里跑。
P._SHUTTING_DOWN["flag"] = False
P.SHUTDOWN_GRACE_SECONDS = _saved_grace
P._DRAIN_THREAD["thread"] = None


# ---------------------------------------------------------------------------
# 8. 本地拒绝：Retry-After + 记账
# ---------------------------------------------------------------------------

section("8. 本地拒绝的可观测性")

_src = io.open(P.__file__, encoding="utf-8").read()
check("_error 会给 429/503 补 Retry-After",
      'if retry_after is None and code in (429, 503):' in _src, None)
check("Retry-After 真的写进响应头",
      'self.send_header("Retry-After", str(self._retry_after))' in _src, None)
check("排不上队的 503 也记账（以前这条分支不记）",
      '"gateway is at its concurrent chat limit "' in _src
      and 'record_error(payload.get("model") or "unknown", 503, message' in _src,
      None)
check("没有可用账号的 503 也记账（记账与响应同源）",
      'record_error(model, 503, msg,' in _src, None)


# ---------------------------------------------------------------------------
# 9 / 10. 首帧前不发 200；客户端取消要记账
# ---------------------------------------------------------------------------

section("9. 流式入口的首帧承诺与取消记账")

check("Responses 入口把 200 推迟到第一帧",
      "def send_headers():" in _src
      and "if not headers_sent:" in _src, None)
check("首帧前失败回真正的错误码（可重试 / 可换号）",
      "return self._error(status, \"codearts error: %s\" % message, err_type)"
      in _src, None)
check("客户端取消落一行 client_aborted（不是干脆不记）",
      "def _record_aborted" in _src
      and 'outcome="client_aborted"' in _src, None)
check("泛异常也记账，不再让失败从统计里消失",
      '("stream aborted: %s" % exc)[:200]' in _src, None)


# ---------------------------------------------------------------------------
# 11. busy 心跳不再拖住请求
# ---------------------------------------------------------------------------

section("11. busy 心跳的超时与登记")

check("busy 心跳超时降到 2 秒量级（挡在请求发出之前，不能等 6 秒）",
      P.CODEARTS_BUSY_TIMEOUT <= 3.0, P.CODEARTS_BUSY_TIMEOUT)

_calls = []
_saved_hb = C.heartbeat
_saved_acct = P.ACCOUNTS_DIR
_acct_tmp = tempfile.mkdtemp(prefix="busy-")
P.ACCOUNTS_DIR = _acct_tmp
try:
    C.heartbeat = lambda *a, **k: (False, "TimeoutError: timed out")
    _sid, _ok, _detail = P.codearts_session_busy(("AK", "SK", "TK"), "acct-a")
    check("busy 超时如实返回失败", _ok is False, (_ok, _detail))
    check("**超时的那条也进登记表**（上游可能已经开了会话，重启要能补 idle）",
          _sid in P._sessions_read(), sorted(P._sessions_read()))

    C.heartbeat = lambda *a, **k: (False, "HTTP 400 bad request")
    _sid2, _ok2, _d2 = P.codearts_session_busy(("AK", "SK", "TK"), "acct-a")
    check("明确被拒（4xx）的不登记（拿它 idle 只会换 404）",
          _sid2 not in P._sessions_read(), sorted(P._sessions_read()))
finally:
    C.heartbeat = _saved_hb
    P.ACCOUNTS_DIR = _saved_acct


# ---------------------------------------------------------------------------
# 12. WorkBuddy 上游常量已删除
# ---------------------------------------------------------------------------

section("12. WorkBuddy 残留")

for _name in ("UPSTREAM", "CHAT_PATH", "MODELS_PATH"):
    check("ca_proxy 不再有 WorkBuddy 的 %s 常量" % _name,
          not hasattr(P, _name), getattr(P, _name, "<absent>"))


# ---------------------------------------------------------------------------
# 13. 面板 idle 设置对流式路径生效
# ---------------------------------------------------------------------------

section("13. 流式静默超时接入面板")

_tmp2 = tempfile.mkdtemp(prefix="idle-")
_saved_dir2 = P.ACCOUNTS_DIR
try:
    P.ACCOUNTS_DIR = _tmp2
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    _default_idle = P._codearts_stream_idle()
    check("默认沿用模块常量（15 s）",
          _default_idle == C.STREAM_IDLE_TIMEOUT, _default_idle)

    S.set_codearts_config(_tmp2, {"stream_idle": 4})
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    check("面板改了 stream_idle，流式读立刻用新值",
          P._codearts_stream_idle() == 4.0, P._codearts_stream_idle())

    S.set_codearts_config(_tmp2, {"stream_max_idle": 0})
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})
    check("面板可以把静默次数上限设成 0（关掉看门狗）",
          P._codearts_stream_max_idle() == 0, P._codearts_stream_max_idle())

    # max_idle=0 时 iter_sse 仍有一道物理硬上限：**真跑一遍**，用最小的
    # 时间尺度验证「静默会收敛成 UpstreamBroken，而不是永远挂着」。
    # 桩：socket 一直在但永远读不到数据（「上游静默」），select 永远返回
    # 不可读 —— 这正是 max_idle 要处理的那种情况。
    class _SilentSock:
        def fileno(self):
            return 3

        def pending(self):
            return 0

        def gettimeout(self):
            return 15.0

        def settimeout(self, _v):
            pass

    class _SilentResp:
        """形状要对上 _stream_socket：resp.fp.raw._sock 才是真 socket。"""

        def __init__(self):
            _raw = type("R", (), {"_sock": _SilentSock()})()
            self.fp = type("F", (), {"raw": _raw})()

        def read1(self, _n):
            raise AssertionError("静默路径不该真的去读")

    _saved_wait2 = C._wait_readable
    # 签名是 (sock, timeout, fp=None, resp=None)：多出来的 resp 用来按 chunked
    # 分帧判断「缓冲里的字节是不是真载荷」，见 _test_stream_retry 的 [5b]。
    C._wait_readable = lambda sock, timeout, fp=None, resp=None: False   # 一直不可读
    try:
        _seen_ping = 0
        _broke = None
        _t0 = time.time()
        try:
            for _line in C.iter_sse(_SilentResp(), idle_timeout=0.01,
                                    max_idle=0, stats={}):
                if _line is C.KEEPALIVE:
                    _seen_ping += 1
                # 硬上限 = IDLE_HARD_CEILING / idle_timeout 次空等，
                # 这里留足余量（真的无限挂时会先撞下面的时间闸）。
                if _seen_ping > 200000 or time.time() - _t0 > 20:
                    break
        except C.UpstreamBroken:
            _broke = True
        check("**max_idle=0 仍会在硬上限内收敛成断流**（不会无限挂住名额）",
              _broke is True, (_broke, _seen_ping))
        check("中间确实在发心跳（不是一直阻塞读）", _seen_ping > 0, _seen_ping)
        check("收敛速度受 IDLE_HARD_CEILING 约束，不是无限等",
              time.time() - _t0 < 10, round(time.time() - _t0, 2))
    finally:
        C._wait_readable = _saved_wait2

    _lease = P._CodeartsLease(None, "lbl", time.time(), "k",
                              idle_timeout=4.0, max_idle=0)
    check("租约把面板值带进读循环",
          _lease.idle_timeout == 4.0 and _lease.max_idle == 0,
          (_lease.idle_timeout, _lease.max_idle))
finally:
    P.ACCOUNTS_DIR = _saved_dir2
    P._CODEARTS_TUNING.update({"at": 0.0, "cfg": None})


# ---------------------------------------------------------------------------
# 14. 租约收尾顺序
# ---------------------------------------------------------------------------

section("14. 租约的收尾顺序")

_order = []
_saved_release = P._CODEARTS_POOL.release
_saved_idle = P.codearts_session_idle
try:
    P._CODEARTS_POOL.release = lambda key: _order.append("release")
    P.codearts_session_idle = lambda cred, sid, timeout=6: (
        _order.append("idle"), (True, "ok"))[1]
    _l = P._CodeartsLease(type("R", (), {"close": lambda self: _order.append("close")})(),
                          "lbl", time.time(), "k",
                          session_id="sid", session_cred=("AK", "SK", "TK"))
    _l.close()
    check("**先 idle、再还本地名额**（反过来会与新人抢上游名额）",
          _order == ["close", "idle", "release"], _order)
    _l.close()
    check("close() 幂等，不重复 idle / 还名额",
          _order.count("idle") == 1 and _order.count("release") == 1, _order)

    _order.clear()
    _l2 = P._CodeartsLease(type("R", (), {"close": lambda self: _order.append("close")})(),
                           "lbl", time.time(), "k",
                           session_id="sid2", session_cred=("AK", "SK", "TK"))
    _l2.close_upstream()
    check("close_upstream 只关连接，不动名额与会话",
          _order == ["close"], _order)
    _l2.release_slot()
    check("release_slot 之后才有 idle 与名额归还",
          _order == ["close", "idle", "release"], _order)
finally:
    P._CODEARTS_POOL.release = _saved_release
    P.codearts_session_idle = _saved_idle

_src = io.open(P.__file__, encoding="utf-8").read()
check("Chat 流式在 [DONE] 之后才 release_slot",
      'self.wfile.write(b"data: [DONE]\\n\\n")' in _src
      and "done_lease.release_slot()" in _src, None)


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

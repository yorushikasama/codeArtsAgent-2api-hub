"""剩余用量估算：账号必须真的被喂进去，且 uid 用 label 而不是 account id。

2026-10-26 线上故障：面板「剩余用量估算」长期显示「暂无数据」，两个独立的
原因叠在一起。

1. ``_remaining_payload(accounts=...)`` 的默认值是空列表，而
   ``remaining_usage()`` 在 WorkBuddy 账号池删除后就没有调用方再传账号 ——
   于是每一行都被跳过（用量分段里有数据，rows 恒为 0）。
2. 就算补上传账号，``uid`` 也必须取**账号 label**（``hid_bgatv9rp4x32nge``
   这种）：用量缓冲与撞线事件的键来自 ``record_usage(account=...)``，调用方
   传的一直是 label。拿华为云 account id（``01a11965c88b…``）当 uid 会让
   ``realm_of.get(uid)`` 全部落空，一行都不产出。

这个套件把两件事都钉住：没有账号时确实是空（默认值的真实语义），有账号时
必须按 label 匹配出真实行。

    python tests/_test_remaining_usage.py
"""
import io
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import ca_proxy as P  # noqa: E402
import ca_usage as U  # noqa: E402

PASS = 0
FAIL = 0


def check(name, ok, detail=None):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s  %s" % (name, detail if detail is not None else ""))


TMP = tempfile.mkdtemp(prefix="remaining-acct-")
ACCOUNTS = os.path.join(TMP, "accounts")
SESSION_DIR = os.path.join(ACCOUNTS, "codearts")
os.makedirs(SESSION_DIR, exist_ok=True)

LABEL = "hid_testaccount01"
ACCOUNT_ID = "01a11965deadbeef"

# 一个最小但形状正确的码道会话文件：load_sessions 只要求 accessKey，
# _remaining_accounts 再挑 account.label / account.id。
with io.open(os.path.join(SESSION_DIR, ACCOUNT_ID + ".json"), "w",
             encoding="utf-8") as fh:
    json.dump({
        "accessKey": "AK", "secretKey": "SK", "securitytoken": "ST",
        "expires_at": "2099-01-01T00:00:00.000Z",
        "account": {"id": ACCOUNT_ID, "label": LABEL},
        "refresh_token": "",
    }, fh)


# --------------------------------------------------------------------------
# 1. _remaining_accounts()：uid 必须是 label
# --------------------------------------------------------------------------
_saved_dir = P.ACCOUNTS_DIR
try:
    P.ACCOUNTS_DIR = ACCOUNTS
    accs = P._remaining_accounts()
    check("_remaining_accounts 读到 1 个账号", len(accs) == 1, len(accs))
    check("uid 取 label（不是华为云 account id）",
          len(accs) == 1 and accs[0].uid == LABEL,
          accs[0].uid if accs else None)
    check("uid 不等于 account id",
          len(accs) == 1 and accs[0].uid != ACCOUNT_ID, None)
    check("realm 跟随 CURRENT_REALM",
          len(accs) == 1 and accs[0].realm == P.CURRENT_REALM,
          accs[0].realm if accs else None)
    check("enabled 恒为真", len(accs) == 1 and accs[0].enabled is True, None)
    check("model_caps 是空字典（撞线走事件日志）",
          len(accs) == 1 and accs[0].model_caps == {}, None)
finally:
    P.ACCOUNTS_DIR = _saved_dir

# --------------------------------------------------------------------------
# 2. 默认值的真实语义：不传 accounts 就一行都不产出
#    这条既是回归锚点，也解释了故障为什么静默（不报错，只是空）
# --------------------------------------------------------------------------
_saved_now = U._remaining_state
try:
    # 造一个带用量的状态：uid == LABEL 才对得上。缓冲结构照
    # ca_usage 的真实形状（at / cum / head / base，见 _remaining_touch）。
    now = time.time()
    fake_usage = {(LABEL, "glm-5.3"): {"at": [now - 60, now],
                                       "cum": [0.0, 1234.0],
                                       "head": 0, "base": 0.0}}
    U._remaining_state["usage"] = fake_usage
    U._remaining_state["events"] = []

    # 直接用 _remaining_payload_locked（不触发 _remaining_refresh 重扫日志：
    # 那会用真实日志覆盖我们伪造的缓冲，测试就失去意义了）。
    realm_of = {LABEL: P.CURRENT_REALM}
    daily = {}

    payload_no_accounts = U._remaining_payload_locked(
        U._remaining_state, now, [], realm_of, daily)
    check("不传账号 -> rows 为空（故障就是这样静默发生的）",
          not payload_no_accounts.get("rows"), payload_no_accounts.get("rows"))

    account = P._RemainingAccount(LABEL, nickname=LABEL,
                                  realm=P.CURRENT_REALM)
    payload_with = U._remaining_payload_locked(
        U._remaining_state, now, [account], realm_of, daily)
    rows = payload_with.get("rows") or []
    check("传了 label 匹配的账号 -> 至少产出一行", len(rows) >= 1, len(rows))
    if rows:
        row = rows[0]
        check("行里带真实 uid", row.get("uid") == LABEL, row.get("uid"))
        check("行里带模型名", row.get("model") == "glm-5.3",
              row.get("model"))
        check("used 是窗口内用量（不是 0）",
              (row.get("used") or 0) > 0, row.get("used"))

    # uid 用 account id 时必须匹配不上 —— 这正是第二层故障
    wrong = P._RemainingAccount(ACCOUNT_ID, nickname="x",
                               realm=P.CURRENT_REALM)
    payload_wrong = U._remaining_payload_locked(
        U._remaining_state, now, [wrong],
        {ACCOUNT_ID: P.CURRENT_REALM}, daily)
    check("uid 误用 account id -> rows 为空（第二层故障的锚点）",
          not payload_wrong.get("rows"), payload_wrong.get("rows"))
finally:
    U._remaining_state = _saved_now

# --------------------------------------------------------------------------
# 3. remaining_usage() 必须真的把账号传下去（源码级约束）
# --------------------------------------------------------------------------
import inspect  # noqa: E402
src = inspect.getsource(P.remaining_usage)
check("remaining_usage 调用 _remaining_payload 时传了 accounts",
      "_remaining_payload(now, _remaining_accounts())" in src,
      [l.strip() for l in src.splitlines() if "_remaining_payload(" in l])

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

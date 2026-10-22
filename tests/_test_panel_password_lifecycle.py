# -*- coding: utf-8 -*-
"""面板密码的生命周期：改密码必须活过重启。

2026-10-21 的线上事故：systemd 每次启动都带 ``--panel-password``（值来自
.credentials），而代码是无条件覆盖 → 用户在面板里改的密码被下一次重启悄悄
还原。用户看到的是「我改过密码，现在登不上 / 我改错了」。

这些断言钉住三件事：
1. 面板改的密码不会被陈旧的启动参数覆盖；
2. 运维真想重置时，force 能强推；
3. 面板改密码会顺手同步 .credentials，让「重启」变成无操作。
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_settings as S  # noqa: E402

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


def fresh_dir():
    return tempfile.mkdtemp(prefix="pw-test-")


def mtime(accounts_dir):
    return os.stat(S.settings_path(accounts_dir)).st_mtime_ns


section("1. 存与验")
d = fresh_dir()
S.set_panel_password(d, "first-pass", source="launcher")
check("设完就能验过", S.verify_panel_password(d, "first-pass"))
check("旧密码失效", not S.verify_panel_password(d, "admin"))
check("来源记成 launcher", S.panel_password_source(d) == "launcher",
      S.panel_password_source(d))
check("不是默认密码", S.panel_password_is_default(d) is False)
check("存档里没有明文密码",
      "first-pass" not in open(S.settings_path(d), encoding="utf-8").read())

section("2. 启动参数：同样的值不该重写文件")
before = mtime(d)
time.sleep(0.01)
check("同一个密码 → same", S.apply_launcher_password(d, "first-pass") == "same")
check("same 不碰 settings.json", mtime(d) == before)

section("3. 面板改过之后，陈旧的启动参数不能覆盖")
S.set_panel_password(d, "second-pass", source="panel")
check("面板来源", S.panel_password_source(d) == "panel")
check("旧启动参数被拒 → kept",
      S.apply_launcher_password(d, "first-pass") == "kept")
check("面板密码仍然有效", S.verify_panel_password(d, "second-pass"))
check("旧启动参数没有生效", not S.verify_panel_password(d, "first-pass"))

section("4. 忘记密码时，force 是唯一的重置通道")
check("force → applied",
      S.apply_launcher_password(d, "reset-me", force=True) == "applied")
check("重置后的密码有效", S.verify_panel_password(d, "reset-me"))
check("来源回到 launcher", S.panel_password_source(d) == "launcher")

section("5. 首次部署（没有任何存档）")
d2 = fresh_dir()
check("直接 applied", S.apply_launcher_password(d2, "boot-pass") == "applied")
check("能验过", S.verify_panel_password(d2, "boot-pass"))

section("6. 恢复默认密码")
S.set_panel_password(d, S.DEFAULT_PANEL_PASSWORD, source="panel")
check("标记为默认", S.panel_password_is_default(d) is True)
check("来源清空", S.panel_password_source(d) == "", S.panel_password_source(d))
check("默认密码本身可登录",
      S.verify_panel_password(d, S.DEFAULT_PANEL_PASSWORD))

section("7. 同步 .credentials")
env_dir = fresh_dir()
env = os.path.join(env_dir, ".credentials")
with open(env, "w", encoding="utf-8") as fh:
    fh.write("API_KEY=sk-hub-abc\n"
             "# 注释要原样保留\n"
             "PANEL_PASSWORD=old-pass\n"
             "OTHER=1\n")
os.chmod(env, 0o600)
check("同步成功", S.sync_env_password(env, "new-pass") is True)
text = open(env, encoding="utf-8").read()
check("PANEL_PASSWORD 换成新值", "PANEL_PASSWORD=new-pass" in text, text)
check("其它行原样保留",
      "API_KEY=sk-hub-abc" in text and "OTHER=1" in text and "# 注释要原样保留" in text,
      text)
check("旧值已消失", "PANEL_PASSWORD=old-pass" not in text)
# chmod 在 Windows 上只能拨只读位，stat 一律报 0o666 —— 这条只在 POSIX 上有意义
if os.name == "posix":
    check("权限仍是 600", (os.stat(env).st_mode & 0o777) == 0o600,
          oct(os.stat(env).st_mode & 0o777))
else:
    print("  [SKIP] 权限检查（Windows 的 chmod 表达不了 600）")
check("没有留下 .tmp", not os.path.exists(env + ".tmp"))

# 没有 PANEL_PASSWORD 那一行时追加，而不是静默什么都不做
env2 = os.path.join(fresh_dir(), ".credentials")
with open(env2, "w", encoding="utf-8") as fh:
    fh.write("API_KEY=sk-hub-abc")            # 故意不带换行
check("缺键时追加成功", S.sync_env_password(env2, "added") is True)
text2 = open(env2, encoding="utf-8").read()
check("追加后两行都在", "API_KEY=sk-hub-abc" in text2 and "PANEL_PASSWORD=added" in text2,
      repr(text2))

# 目标不可写：返回 False，不抛异常（改密码不能因为同步失败而失败）
check("不可写时返回 False 而不是抛",
      S.sync_env_password("/nonexistent-dir-xyz/.credentials", "x") is False)

section("8. 同步 + 重启 = 无操作（事故场景回归）")
d3 = fresh_dir()
env3 = os.path.join(fresh_dir(), ".credentials")
with open(env3, "w", encoding="utf-8") as fh:
    fh.write("PANEL_PASSWORD=deploy-pass\n")
# 首次部署
check("首启应用 .credentials", S.apply_launcher_password(d3, "deploy-pass") == "applied")
# 用户在面板改成 my-new-pass（接口里就是这么两步：set(source=panel) + sync）
S.set_panel_password(d3, "my-new-pass", source="panel")
check("同步 .credentials 成功", S.sync_env_password(env3, "my-new-pass") is True)
# 服务重启：启动参数现在读到的就是 my-new-pass
check("重启后是 same，不覆盖", S.apply_launcher_password(d3, "my-new-pass") == "same")
check("重启后旧密码仍然无效", not S.verify_panel_password(d3, "deploy-pass"))
check("重启后新密码仍然有效", S.verify_panel_password(d3, "my-new-pass"))

# 同步失败（.credentials 只读 / 不存在）时，重启也必须是面板的密码赢
d4 = fresh_dir()
S.set_panel_password(d4, "deploy-pass", source="launcher")
S.set_panel_password(d4, "panel-only", source="panel")     # 同步失败，env 还是旧值
check("同步失败 → kept",
      S.apply_launcher_password(d4, "deploy-pass") == "kept")
check("同步失败也不丢面板密码", S.verify_panel_password(d4, "panel-only"))

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

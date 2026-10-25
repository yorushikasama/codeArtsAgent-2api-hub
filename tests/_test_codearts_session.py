# -*- coding: utf-8 -*-
"""码道会话链路：会话归一 / 会话存储 / 登录状态机 / 回调页与重定向白名单 / 自动续期

不联网。2026-10-24 自 _test_codearts.py 按域拆出；共享夹具在
_codearts_fixtures.py。跑法：python tests/_test_codearts_session.py
"""
import calendar
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _codearts_fixtures import (  # noqa: E402
    PROFILE, RESPONSE, SEEN, _fake_jwt, _key, _pkce,
    _stub_exchange)
from _isolated_dirs import isolated_data_dirs  # noqa: E402
isolated_data_dirs("wb-codearts-codearts-session-")

import ca_proxy as P  # noqa: E402
import ca_stream as S2  # noqa: E402
from ca_proxy import Handler  # noqa: E402
import ca_codearts as C  # noqa: E402

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
# 5. 响应归一
# ---------------------------------------------------------------------------

section("5. 会话归一")


_session = C.session_from_iam_response(RESPONSE, _key, _pkce)
check("accessKey 取自 credentials.access_key_id",
      _session["accessKey"] == "HSTAXPGE3LNH83GEFV7K")
check("securitytoken 取自 credentials.security_token",
      _session["securitytoken"] == "TOKEN")
check("expires_at 取自 credentials.expiration",
      _session["expires_at"] == "2026-10-17T04:40:18.715Z")
check("accessToken 是空串（这条链路本来就没有 IAM token）",
      _session["accessToken"] == "")
check("domainId 取自 refresh_token 的 account_id",
      _session["domainId"] == "01a11965c88b7ca39df46acd430a59e4")
check("账号 id 取自 principal_id",
      _session["account"]["id"] == "01a11965c88b798093fd88b7189b8da7")
check("账号标签取自 principal_urn 尾段",
      _session["account"]["label"] == "hid_bgatv9rp4x32nge",
      _session["account"]["label"])
check("DPoP 私钥被存进 loginContext",
      _session["loginContext"]["dpopKeyPair"]["privateKeyJwk"]["d"]
      == _key.private_jwk["d"])
check("PKCE 被存进 loginContext",
      _session["loginContext"]["pkcePair"]["codeVerifier"] == _pkce["codeVerifier"])

_sum = C.summarize(_session, now=C.parse_iso8601("2026-10-17T03:40:18.715Z"))
check("摘要算出剩余 3600 秒", _sum["sts_remaining_seconds"] == 3600, _sum["sts_remaining_seconds"])
check("摘要判定未过期", _sum["sts_expired"] is False)
check("摘要判定可续期", _sum["renewable"] is True)
check("摘要模式为 new_iam_login", _sum["mode"] == "new_iam_login")

_expired = C.summarize(_session, now=C.parse_iso8601("2026-10-17T05:40:18.715Z"))
check("过期后摘要标记 sts_expired", _expired["sts_expired"] is True)

try:
    C.session_from_iam_response({"refresh_token": ""}, _key, _pkce)
    check("缺少 credentials 时抛错", False)
except C.CodeArtsError:
    check("缺少 credentials 时抛错", True)


# ---------------------------------------------------------------------------
# 6. 存储
# ---------------------------------------------------------------------------

section("6. 会话存储")

_root = tempfile.mkdtemp(prefix="wb-codearts-")
check("首次读取返回空列表", C.load_sessions(_root) == [])

_saved = C.save_session(_root, _session)
check("落在 accounts/codearts/ 子目录",
      os.path.relpath(_saved, _root).startswith(C.SESSION_SUBDIR + os.sep),
      os.path.relpath(_saved, _root))
check("读回一条", len(C.load_sessions(_root)) == 1)

# 关键：AccountPool 只扫顶层 *.json，绝不能把码道会话当成坏账号
check("池目录顶层没有 json（不会被 AccountPool 误读）",
      [n for n in os.listdir(_root) if n.endswith(".json")] == [])

# 文件名要防穿越
_bad = C.session_path(_root, "../../etc/passwd")
check("账号 id 里的路径分隔符被清洗",
      os.path.dirname(os.path.abspath(_bad))
      == os.path.abspath(os.path.join(_root, C.SESSION_SUBDIR)),
      _bad)

# 坏文件跳过，不连累其他账号
with open(os.path.join(os.path.dirname(_saved), "broken.json"), "w", encoding="utf-8") as fh:
    fh.write("{ not json")
with open(os.path.join(os.path.dirname(_saved), "empty.json"), "w", encoding="utf-8") as fh:
    fh.write('{"account": {"id": "x"}}')
check("坏文件 / 无凭据文件被跳过", len(C.load_sessions(_root)) == 1)

check("删除命中", C.delete_session(_root, _session["account"]["id"]) is True)
check("删除后为空", C.load_sessions(_root) == [])
check("删不存在的返回 False", C.delete_session(_root, "nope") is False)


# ---------------------------------------------------------------------------
# 7. 登录状态机
# ---------------------------------------------------------------------------

section("7. 登录状态机")

_root2 = tempfile.mkdtemp(prefix="wb-codearts-login-")
_real_exchange = C.exchange_code
C.exchange_code = _stub_exchange
try:
    mgr = C.LoginManager(_root2)

    check("无 pending 时 poll 返回 unknown",
          mgr.poll("nope")["status"] == "unknown")

    started = mgr.start(8787)
    check("start 返回 state 与 authUrl",
          bool(started["state"]) and started["authUrl"].startswith("https://"))
    check("authUrl 里带的是真实监听端口",
          "port=8787" in started["authUrl"], started["authUrl"][:120])
    check("start 后状态是 pending", mgr.poll(started["state"])["status"] == "pending")

    # 没有 pending 时收到 code（比如旧链接）不能崩，要给出人话
    _before = len(C.load_sessions(_root2))
    kind, detail = mgr.accept_callback(code="abc")
    check("有 pending 时收 code 换 token 成功", kind == "ok", (kind, detail))
    check("交换确实被调用一次", SEEN["exchanges"] == 1)
    check("端口透传给换取函数", SEEN["port"] == 8787)
    check("code 透传", SEEN["code"] == "abc")
    check("会话已落盘", len(C.load_sessions(_root2)) == _before + 1)
    check("poll 变成 ok", mgr.poll(started["state"])["status"] == "ok")
    check("poll 带回摘要",
          (mgr.poll(started["state"]).get("summary") or {}).get("account")
          == "hid_bgatv9rp4x32nge")

    # 已被消费的槽位不该再吃第二次回调
    kind2, _ = mgr.accept_callback(code="abc")
    check("ok 之后再来回调返回 error", kind2 == "error")

    # secret 分支：必须让浏览器继续跳，而不是当成成功
    s2 = mgr.start(8787)
    kind3, _ = mgr.accept_callback(secret="s3cr3t")
    check("secret 回调返回 redirect", kind3 == "redirect")
    check("secret 之后仍在等待 code", mgr.poll(s2["state"])["status"] == "pending")

    # 新登录顶掉旧的：回调永远只有唯一候选
    s3 = mgr.start(8787)
    check("旧 state 被标记 superseded",
          mgr.poll(s2["state"])["status"] == "superseded",
          mgr.poll(s2["state"])["status"])
    check("新 state 仍是 pending", mgr.poll(s3["state"])["status"] == "pending")

    # 换 token 失败要把原因带回前端，而不是静默 pending
    SEEN["fail"] = "refresh token 已被使用"
    s4 = mgr.start(8787)
    kind4, detail4 = mgr.accept_callback(code="bad")
    check("换失败时渲染错误页", kind4 == "error")
    check("错误原因透传", "已被使用" in (detail4 or ""), detail4)
    check("poll 反映失败",
          mgr.poll(s4["state"])["status"] == "error"
          and "已被使用" in mgr.poll(s4["state"])["message"])
    SEEN["fail"] = None

    # TTL
    s5 = mgr.start(8787)
    mgr._pending[s5["state"]]["created"] = time.time() - C.LOGIN_TTL_SECONDS - 1
    check("超时后 poll 返回 expired", mgr.poll(s5["state"])["status"] == "expired")
    mgr._pending[s5["state"]]["created"] = time.time() - C.LOGIN_TTL_SECONDS - 1
    mgr.sweep()
    check("sweep 清掉了超时槽位", s5["state"] not in mgr._pending)

    # 取消
    s6 = mgr.start(8787)
    check("cancel 命中返回 True", mgr.cancel(s6["state"]) is True)
    check("cancel 后 poll 变 unknown", mgr.poll(s6["state"])["status"] == "unknown")

    # 空管理器收到回调不能抛
    empty = C.LoginManager(_root2)
    kind7, detail7 = empty.accept_callback(code="x")
    check("无 pending 的回调返回 error 而非抛异常", kind7 == "error")
    check("并且给出可读原因", "没有正在等待" in detail7, detail7)

finally:
    C.exchange_code = _real_exchange


# ---------------------------------------------------------------------------
# 8. 回调页与重定向白名单
# ---------------------------------------------------------------------------

section("8. 回调页与重定向白名单")

_ok_page = C.callback_page(True, "登录成功", "hid_demo 已加入")
check("成功页含成功标题", "登录成功" in _ok_page)
check("成功页提示可关闭窗口", "关闭此页面" in _ok_page)
check("成功页是完整 HTML", _ok_page.startswith("<!doctype html>"))
_bad_page = C.callback_page(False, "登录失败", "refresh token 无效")
check("失败页含失败原因", "refresh token 无效" in _bad_page)
check("失败页提示重试", "重试" in _bad_page)
check("页面可被浏览器正确解码（含中文字节）",
      _ok_page.encode("utf-8").decode("utf-8") == _ok_page)

from ca_proxy import Handler  # noqa: E402  (需要完整模块才能取到静态方法)

_allow = Handler._codearts_redirect_ok
check("放行华为云地址", _allow("https://codearts.huaweicloud.com/portal/login?x=1"))
check("放行子域", _allow("https://snap-access.cn-north-4.myhuaweicloud.com:443/x"))
check("放行本机", _allow("http://127.0.0.1:8787/oauth/callback"))
check("拒绝外部站点", not _allow("https://evil.example.com/steal"))
check("拒绝被当作子域名的钓鱼串",
      not _allow("https://huaweicloud.com.evil.com/x"))
check("拒绝非 http(s) 协议", not _allow("javascript:alert(1)"))
check("拒绝空地址", not _allow(""))
check("拒绝 file 协议", not _allow("file:///C:/Windows/win.ini"))


# ---------------------------------------------------------------------------
# 自动续期：身份保留 + 过期判定
# ---------------------------------------------------------------------------

print()
print("== 自动续期 ==")

_root3 = tempfile.mkdtemp(prefix="wb-codearts-renew-")
C.save_session(_root3, _session)
_REFRESHED_NO_PROFILE = {
    "credentials": {
        "access_key_id": "HSTANEWKEY0000000000",
        "secret_access_key": "SECRET2",
        "security_token": "TOKEN2",
        "expiration": "2099-01-01T00:00:00.000Z",
    },
    # 刻意不带 user_profile：服务端真实出现过这种响应，不能因此丢账号身份。
    "refresh_token": _fake_jwt({}),
}
_real_refresh = C.refresh
_refresh_calls = []


def _stub_refresh(key, pkce, token):
    _refresh_calls.append(token)
    return _REFRESHED_NO_PROFILE


C.refresh = _stub_refresh
try:
    _renewed = C.refresh_session(_root3, _session["account"]["id"])
finally:
    C.refresh = _real_refresh

check("续期响应缺 user_profile 时保留原账号 id",
      _renewed["account"]["id"] == _session["account"]["id"],
      _renewed.get("account"))
check("账号标签也保留",
      _renewed["account"]["label"] == _session["account"]["label"],
      _renewed.get("account"))
check("domainId 不被清空", _renewed["domainId"] == _session["domainId"],
      _renewed.get("domainId"))
with open(C.session_path(_root3, _session["account"]["id"]), encoding="utf-8") as _fh:
    _saved_renewed = json.load(_fh)
check("新凭证落盘到原账号文件", _saved_renewed["accessKey"] == "HSTANEWKEY0000000000")
check("不会额外写出 unknown.json",
      not os.path.exists(os.path.join(C.session_dir(_root3), "unknown.json")))

_now_fresh = dict(_session, expires_at="2099-01-01T00:00:00.000Z")
_calls_before = len(_refresh_calls)
C.refresh = _stub_refresh
try:
    _same = C.ensure_fresh_session(_root3, _now_fresh)
finally:
    C.refresh = _real_refresh
check("STS 还很新时不续期", _same is _now_fresh and len(_refresh_calls) == _calls_before)

_expired = dict(_session, expires_at="2020-01-01T00:00:00.000Z")
C.save_session(_root3, _expired)
C.refresh = _stub_refresh
try:
    _auto = C.ensure_fresh_session(_root3, _expired)
finally:
    C.refresh = _real_refresh
check("过期会话续期后拿到新 AK", _auto["accessKey"] == "HSTANEWKEY0000000000",
      _auto.get("accessKey"))

_old_login = dict(_expired, refresh_token="")
check("没有 refresh_token 的会话不会被误判为可续期",
      C.ensure_fresh_session(_root3, _old_login) is _old_login)

shutil.rmtree(_root3, ignore_errors=True)



print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

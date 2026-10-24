"""码道 CodeArts（华为云）授权链路的确定性测试。

不联网。所有服务端交互都用打桩函数替换，但**密码学部分是真算的**——
里面钉了几个真实样本做金标准：

1. P-256 已知向量（d=1 → G，2G 坐标，RFC 6979 A.2.5 的 r）。
2. JWK thumbprint 对着服务端在真实 refresh_token 里写下的 `cnf.jkt`
   （`9um3t6uGoxSBURtpFD0aLLJhrNduFQekMsgZyJj3gxg`）。这一条把曲线运算、
   JWK 规范化、base64url 三件事同时钉死 —— 三者任一有偏差都对不上。
3. DPoP proof 用公钥独立验签，而不是复用自己的签名函数。
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
# 1. 曲线与签名
# ---------------------------------------------------------------------------

section("1. P-256 曲线运算")

G = (C._GX, C._GY)

check("d=1 的公钥就是 G", (C.EcKey(1).x, C.EcKey(1).y) == G)

_2g = C.EcKey(2)
check("2G.x 对已知向量",
      _2g.x == 0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978,
      hex(_2g.x))
check("2G.y 对已知向量",
      _2g.y == 0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1,
      hex(_2g.y))

# 阶检验：n*G 必须是无穷远点，否则整条链的模运算都建在错的地基上
check("nG 落在无穷远点", C._to_affine(C._scalar_mul(C._N, G)) is None)

# RFC 6979 A.2.5（P-256 + SHA-256, message="sample"）的固定 k 与 r
_rfc_d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
_rfc_k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
_sig = C.EcKey(_rfc_d).sign(b"sample", k=_rfc_k)
check("RFC 6979 r 对已知向量",
      int.from_bytes(_sig[:32], "big") ==
      0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716)
check("签名为 64 字节 raw r||s（不是 DER 的 70/71 字节）", len(_sig) == 64, len(_sig))
check("s 已压到低半区（s <= n/2）",
      int.from_bytes(_sig[32:], "big") <= C._N // 2)


def _verify(public_x, public_y, message, signature):
    """独立验签，刻意不复用 EcKey.sign 的任何中间结果。"""
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (0 < r < C._N and 0 < s < C._N):
        return False
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, C._N)
    u1 = digest * w % C._N
    u2 = r * w % C._N
    point = C._to_affine(C._jac_add(C._scalar_mul(u1, G),
                                    C._scalar_mul(u2, (public_x, public_y))))
    return point is not None and point[0] % C._N == r


_key = C.generate_keypair()
_msg = b"hello codearts"
check("自签自验通过", _verify(_key.x, _key.y, _msg, _key.sign(_msg)))
check("改一个字节就验不过", not _verify(_key.x, _key.y, _msg + b"!", _key.sign(_msg)))

# 私钥往返：从 JWK 还原后公钥必须一字节不差
_restored = C.import_keypair(_key.private_jwk)
check("privateJwk 往返后公钥一致",
      (_restored.x, _restored.y) == (_key.x, _key.y))
check("publicJwk 只含 4 个字段（kty/crv/x/y，不含 d）",
      sorted(_key.public_jwk) == ["crv", "kty", "x", "y"], sorted(_key.public_jwk))


# ---------------------------------------------------------------------------
# 2. 金标准：thumbprint 必须等于服务端写下的 cnf.jkt
# ---------------------------------------------------------------------------

section("2. JWK thumbprint 对比真服务端的 cnf.jkt")

# 取自本机真实 refresh_token 的 DPoP 公钥（只用公开部分），
# 服务端在同一张 token 里写着 cnf.jkt = 下面这个值。
REAL_PUBLIC_JWK = {
    "kty": "EC",
    "x": "nBqBPgHGH3FENImZcuXzTlhBBv0qd4UDnJ4jqxz3F7c",
    "y": "mISSU_aVMJ3RBsJ_OCI0zEDmhLpl9WkVoxFP7e4vu1E",
    "crv": "P-256",
}
SERVER_JKT = "9um3t6uGoxSBURtpFD0aLLJhrNduFQekMsgZyJj3gxg"


class _PublicOnly:
    """thumbprint() 只读 public_jwk，这里给个最小替身，避免引入真私钥。"""

    CURVE = "P-256"
    public_jwk = REAL_PUBLIC_JWK


_thumb = C.EcKey.thumbprint(_PublicOnly())
check("thumbprint 与服务端 cnf.jkt 完全一致", _thumb == SERVER_JKT, _thumb)

# 公钥坐标本身还得真的落在曲线上，否则 thumbprint 就算对上也是巧合
_px = int.from_bytes(C._b64u_decode(REAL_PUBLIC_JWK["x"]), "big")
_py = int.from_bytes(C._b64u_decode(REAL_PUBLIC_JWK["y"]), "big")
check("真实公钥在曲线上",
      (_py * _py - (_px ** 3 + C._A * _px + C._B)) % C._P == 0)


# ---------------------------------------------------------------------------
# 3. PKCE 与授权 URL
# ---------------------------------------------------------------------------

section("3. PKCE 与授权 URL")

_pkce = C.generate_pkce()
check("codeChallenge == base64url(SHA256(verifier))",
      _pkce["codeChallenge"] ==
      C._b64u(hashlib.sha256(_pkce["codeVerifier"].encode()).digest()))
check("method 固定 SHA-256", _pkce["codeChallengeMethod"] == "SHA-256")
check("verifier 是 86 字符（64 字节 base64url 无填充）",
      len(_pkce["codeVerifier"]) == 86, len(_pkce["codeVerifier"]))

_url = C.authorize_url(8787, _pkce, "f" * 64)
_parts = urllib.parse.urlsplit(_url)
_q = urllib.parse.parse_qs(_parts.query)

check("授权页基址", _parts.scheme + "://" + _parts.netloc + _parts.path
      == "https://codearts.huaweicloud.com/portal/authorize")
check("client_id == codearts-agent", _q["client_id"] == ["codearts-agent"])
check("uri_scheme 与 client_id 同源（官方取 vscode.env.uriScheme）",
      _q["uri_scheme"] == _q["client_id"])
check("port 透传为字符串", _q["port"] == ["8787"])
check("code_challenge 透传", _q["code_challenge"] == [_pkce["codeChallenge"]])
check("plugin-name == snap_AIIDE", _q["plugin-name"] == ["snap_AIIDE"])
check("ticket_id 透传", _q["ticket_id"] == ["f" * 64])

_check = C.generate_pkce()
check("每次 PKCE 都不同", _check["codeVerifier"] != _pkce["codeVerifier"])
check("ticket_id 是 64 位 hex", len(C.new_ticket_id()) == 64
      and all(ch in "0123456789abcdef" for ch in C.new_ticket_id()))


# ---------------------------------------------------------------------------
# 4. DPoP proof
# ---------------------------------------------------------------------------

section("4. DPoP proof 结构与可验证性")

_token_url = C.IAM_STS + C.IAM_TOKEN_API
_proof = C.dpop_proof(_key, "POST", _token_url)
_parts3 = _proof.split(".")
check("紧凑序列化三段", len(_parts3) == 3)
check("签名 64 字节", len(C._b64u_decode(_parts3[2])) == 64)

_header = json.loads(C._b64u_decode(_parts3[0]))
_claims = json.loads(C._b64u_decode(_parts3[1]))

check("header.alg == ES256", _header["alg"] == "ES256")
check("header.typ == dpop+jwt", _header["typ"] == "dpop+jwt")
check("header 内嵌公钥 jwk", _header["jwk"]["kty"] == "EC"
      and _header["jwk"]["crv"] == "P-256")
check("内嵌 jwk 不带私钥 d", "d" not in _header["jwk"])
check("htm == POST", _claims["htm"] == "POST")
check("htu 是完整的 token 端点", _claims["htu"] == _token_url)
check("iat 是秒级时间戳", abs(_claims["iat"] - int(time.time())) <= 5, _claims["iat"])
check("jti 是 64 位 hex", len(_claims["jti"]) == 64)

# 用公钥独立验签：签名覆盖的确实是 "<b64u(header)>.<b64u(claims)>"
check("proof 签名可被独立验证",
      _verify(_key.x, _key.y, (_parts3[0] + "." + _parts3[1]).encode("ascii"),
              C._b64u_decode(_parts3[2])))

# 两个 proof 的 jti 必须不同，否则会被服务端判重放
check("两次 proof 的 jti 不同",
      json.loads(C._b64u_decode(C.dpop_proof(_key, "POST", _token_url).split(".")[1]))["jti"]
      != _claims["jti"])

# htu 必须跟着实际 URL 走：写死会导致换端点时静默失败
_other = C.dpop_proof(_key, "POST", "https://example.com/x")
check("htu 跟随传入 URL",
      json.loads(C._b64u_decode(_other.split(".")[1]))["htu"] == "https://example.com/x")


# ---------------------------------------------------------------------------
# 5. 响应归一
# ---------------------------------------------------------------------------

section("5. 会话归一")


def _fake_jwt(profile):
    def enc(obj):
        return C._b64u(json.dumps(obj, separators=(",", ":")).encode())
    return enc({"alg": "RS256", "typ": "JWT"}) + "." + enc({"user_profile": enc(profile)}) + ".sig"


PROFILE = {
    "account_id": "01a11965c88b7ca39df46acd430a59e4",
    "account_name": "hid_bgatv9rp4x32nge",
    "principal_id": "01a11965c88b798093fd88b7189b8da7",
    "principal_is_root_user": True,
    "principal_urn": "iam::01a11965c88b7ca39df46acd430a59e4:user:hid_bgatv9rp4x32nge",
}
RESPONSE = {
    "credentials": {
        "access_key_id": "HSTAXPGE3LNH83GEFV7K",
        "secret_access_key": "SECRET",
        "security_token": "TOKEN",
        "expiration": "2026-10-17T04:40:18.715Z",
    },
    "refresh_token": _fake_jwt(PROFILE),
}

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
SEEN = {"exchanges": 0, "fail": None}


def _stub_exchange(key, code, pkce, port):
    SEEN["exchanges"] += 1
    SEEN["port"] = port
    SEEN["code"] = code
    if SEEN["fail"]:
        raise C.CodeArtsError(SEEN["fail"], code="STS5.1806")
    return RESPONSE


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


# ---------------------------------------------------------------------------
# 模型清单：只剩内置一组（福利渠道已由官方下线）
# ---------------------------------------------------------------------------

print()
print("== 模型清单（内置）==")
check("内置目录在 PromptCenter 那台主机上",
      C.BUILTIN_MODELS_PATH == "/v1/model/builtin", C.BUILTIN_MODELS_PATH)

# 这几行曾经两次判错过，都是被**假信号**带偏的：
#   · 限时福利 4 个全 404/429 → 被判「不在推理入口注册」，其实是限流不是不支持
#   · glm-5.3 连续 400 且响应体为空 → 被判「真的不通」，其实它只收 stream=true
# 所以不只钉「谁在清单里」，还要把这两个判据本身钉住。
check("清单 9 个模型（12 减掉 3 个纯福利模型）",
      len(C.CHAT_MODELS) == 9
      and "deepseek-v4.1-flash" in C.CHAT_MODELS
      and "GLM-5.2" in C.CHAT_MODELS
      and "glm-5.3" in C.CHAT_MODELS
      and "kimi-k3" in C.CHAT_MODELS,
      C.CHAT_MODELS)
# kimi-k3 是 2026-10-23 才补的：上游内置目录里有、`display_enabled=true`，
# 但没进这张表 —— 表现不是「少一个可选模型」，而是请求被判成「不是码道模型」
# 掉进 WorkBuddy 池，只配码道账号的部署回 503，报错和模型名毫无关系。
check("kimi-k3 在可推理名单里（上游展示它，网关不能装作没有）",
      "kimi-k3" in C.CHAT_MODELS, C.CHAT_MODELS)
# 2026-10-23：福利渠道由官方下线（opengw gateway/config 回
# `[4000] invalid channel, group not found`）。那 3 个纯福利模型两条通道都
# 打不通，已从名单移除 —— 留着它们只会让清单广告一个必错的选项。
check("纯福利模型已从名单移除",
      not any(m in C.CHAT_MODELS for m in
              ("deepseek-v4-flash-0731", "glm-5.3-flash",
               "deepseek-v4-pro-0813")),
      [m for m in C.CHAT_MODELS if "deepseek" in m or m.startswith("glm")])
# deepseek-v4.1-flash 是例外：上游已把它内置化，不带 maas_type 实测 200 出字。
check("deepseek-v4.1-flash 留在名单里（已内置化）",
      "deepseek-v4.1-flash" in C.CHAT_MODELS, C.CHAT_MODELS)
check("glm-5.3 不再被标为不可路由（它只收流式，不是死的）",
      "glm-5.3" not in C.BUILTIN_UNROUTABLE, C.BUILTIN_UNROUTABLE)

# 请求体默认必须流式 —— glm-5.3 传非流式回 400 空响应体，看着像模型不存在
_body = C.chat_body("glm-5.3", [{"role": "user", "content": "hi"}])
check("chat_body 默认流式", _body["stream"] is True, _body)
check("chat_body 带模型名与消息", _body["model"] == "glm-5.3" and _body["messages"],
      _body)
check("chat_body 可显式关掉流式",
      C.chat_body("x", [], stream=False)["stream"] is False)
check("chat_body 的 max_tokens 默认 256", C.chat_body("x", [])["max_tokens"] == 256,
      C.chat_body("x", []))

# maas_type 曾是福利组的开关（2026-10-17 全套头对照实验得出）。福利渠道
# 下线后它不该再出现在任何请求里 —— 带上就是 `InferHub.4004.200 benefit
# not found`，deepseek-v4.1-flash 就是这么被误伤的（已内置化却仍被判成福利组）。
check("请求头不再带 maas_type",
      "maas_type" not in C.chat_headers("AK", "SK", "TOK", "0" * 64),
      C.chat_headers("AK", "SK", "TOK", "0" * 64))

# credit 是按 token 数分段的价格表，面板只要一个代表值
check("分段计费取第一档",
      C._credit_tier({"credit": [{"ratio_display": "0.7x", "input_price": "3.2",
                                  "output_price": "14.5"},
                                 {"ratio_display": "0.7x", "input_price": "4.8"}]})
      == ("0.7x", "3.2", "14.5"))
check("未定价的模型返回三个 None",
      C._credit_tier({"credit": []}) == (None, None, None))
check("credit 缺失也不炸", C._credit_tier({}) == (None, None, None))
check("credit 不是列表时不当成有价", C._credit_tier({"credit": {}}) == (None, None, None))

BUILTIN_SAMPLE = [
    {"model_id": "glm-5.2-sft-harmony", "model_name": "GLM-5.2-ArkTS-SPARK",
     "model_category": "文本生成", "model_desc": "鸿蒙代码增训", "provider": "zhipu",
     "supports_images": False,
     "credit": [{"ratio_display": "0.7x", "input_price": "8",
                 "output_price": "28"}]},
    {"model_id": "Qwen3-VL-235B", "model_name": "Qwen3-VL-235B",
     "model_category": "图片理解", "supports_images": True, "credit": []},
    {"model_id": "glm-5.3", "model_name": "GLM-5.3",
     "supports_images": False,
     "credit": [{"ratio_display": "0.79x"}]},
    {"model_id": "", "model_name": "没有 id 的条目"},
]
norm = C.normalize_builtin(BUILTIN_SAMPLE)
check("丢掉没有 id 的条目", len(norm) == 3, [m["id"] for m in norm])
# 界面上显示的是 model_name，发请求要发 model_id，两者常常不一样
check("展示名取 model_name 而非 model_id",
      norm[0]["name"] == "GLM-5.2-ArkTS-SPARK", norm[0])
check("请求名仍是 model_id", norm[0]["id"] == "glm-5.2-sft-harmony", norm[0])
check("标记为内置分组", norm[0]["group"] == C.GROUP_BUILTIN, norm[0])
check("倍率原样带出", norm[0]["creditRatio"] == "0.7x", norm[0])
check("输入输出价带出", norm[0]["inputPrice"] == "8" and norm[0]["outputPrice"] == "28",
      norm[0])
check("多模态标记取服务端而非猜",
      norm[1]["supportsImages"] is True and norm[0]["supportsImages"] is False,
      [norm[1]["supportsImages"], norm[0]["supportsImages"]])
check("未定价时倍率是 None 而不是 0",
      norm[1]["creditRatio"] is None, norm[1])
check("routable 由 BUILTIN_UNROUTABLE 决定",
      all(m["routable"] is True for m in norm), norm[2])
# 集合本身当前是空的：清单里 11 个模型实测全通。留个断言钉住「现在是空的」，
# 以后真出现不通的模型时这条会失败、提醒更新注释里的说明。
check("当前没有已知不通的内置模型", C.BUILTIN_UNROUTABLE == set(),
      C.BUILTIN_UNROUTABLE)
check("分类与描述带出",
      norm[0]["category"] == "文本生成" and norm[0]["provider"] == "zhipu", norm[0])
# 上下文窗口：上游 /v1/model/builtin 不给这两个值，改用实测表兜底
# （2026-10-20 从 AgentCenter 取得）。表里没有的模型仍然留 0 —— 不编数字。
_LIMITS = C.BUILTIN_MODEL_LIMITS
check("上下文窗口按实测表兜底",
      (norm[0]["maxInputTokens"], norm[0]["maxOutputTokens"])
      == _LIMITS.get(norm[0]["id"], (0, 0)), norm[0])
check("实测表里没有的模型留 0，不编造",
      all(m["maxInputTokens"] == 0 and m["maxOutputTokens"] == 0
          for m in norm if m["id"] not in _LIMITS),
      [m["id"] for m in norm if m["id"] not in _LIMITS])

# 默认采样参数同样来自 AgentCenter detail 的实测值（2026-10-22）。
# 有实测值的模型带 temperature / top_p；没测过的不能凭空补一个默认值。
_SAMPLING = C.BUILTIN_MODEL_SAMPLING
check("采样参数按实测表带出",
      (norm[0].get("temperature"), norm[0].get("top_p"))
      == _SAMPLING["glm-5.2-sft-harmony"], norm[0])
check("采样参数对每个模型各自取值",
      (norm[2].get("temperature"), norm[2].get("top_p"))
      == _SAMPLING["glm-5.3"], norm[2])
check("没有实测值的模型不带采样参数键",
      "temperature" not in norm[1] and "top_p" not in norm[1], norm[1])
check("未实测的多模态模型不猜采样参数",
      "Qwen3-VL-235B" not in _SAMPLING and "kimi-k2.6-vl" not in _SAMPLING,
      sorted(_SAMPLING))


THINK_CALLS = []


def with_catalog(builtin_exc=None, variants=None, variants_exc=None):
    """跑一次 model_catalog：内置取数与思考档位全部打桩。

    思考档位也必须打桩：它是清单构建里唯一一个「顺手多问一次」的接口，
    忘了桩就会真的发出网络请求 —— 这个测试文件的前提是**不联网**，
    真发出去的结果只是随机失败（实测 APIG.0613 IAM unavailable）。
    """
    saved = (C.builtin_models, C.thinking_variants)

    def _fake_variants(*a, **k):
        names = a[3] if len(a) > 3 else k.get("model_names")
        THINK_CALLS.append(list(names or []))
        return dict(variants or {})

    C.builtin_models = (lambda *a, **k: (_ for _ in ()).throw(builtin_exc)) \
        if builtin_exc else (lambda *a, **k: list(BUILTIN_SAMPLE))
    C.thinking_variants = (lambda *a, **k: (_ for _ in ()).throw(variants_exc)) \
        if variants_exc else _fake_variants
    try:
        return C.model_catalog("AK", "SK", "TOK")
    finally:
        C.builtin_models, C.thinking_variants = saved


# 上游思考档位接口的键是 **model_name**，不是 model_id：
# glm-5.2-sft-harmony 的展示名是 GLM-5.2-ArkTS-SPARK。这里按真实形状打桩，
# 只按 id 查的实现会把它的 high/max 丢掉、面板错显示「原生」。
THINK_VARIANTS = {
    "GLM-5.2-ArkTS-SPARK": {"strengths": ["high", "max"], "default": "high"},
    "GLM-5.2": {"strengths": ["high", "max"], "default": "high"},
    "GLM-5.3": {"strengths": [], "default": ""},
}

cat = with_catalog(variants=THINK_VARIANTS)
check("清单只来自内置目录", len(cat["models"]) == 3, len(cat["models"]))
check("取数无错时 errors 为空", cat["errors"] == {}, cat["errors"])
# 请求侧同样要发展示名：上游只按 model_name 匹配，发 id 的模型问不到档位。
check("档位接口按展示名请求",
      THINK_CALLS[-1] == ["GLM-5.2-ArkTS-SPARK", "Qwen3-VL-235B", "GLM-5.3"],
      THINK_CALLS[-1])
_think = [m for m in cat["groups"][C.GROUP_BUILTIN]
          if m["id"] == "glm-5.2-sft-harmony"][0]
check("思考档位贴到模型上", _think.get("thinkingStrengths") == ["high", "max"],
      _think.get("thinkingStrengths"))
check("思考默认档位带出", _think.get("thinkingDefault") == "high", _think)
check("档位接口按展示名返回时仍按 id 贴对",
      _think.get("thinkingStrengths") == ["high", "max"], _think)
check("THINKING_STRENGTHS 被填上",
      C.THINKING_STRENGTHS.get("glm-5.2-sft-harmony", {}).get("strengths")
      == ["high", "max"], C.THINKING_STRENGTHS)
check("THINKING_STRENGTHS 用 id 作键，不残留展示名",
      "GLM-5.2-ArkTS-SPARK" not in C.THINKING_STRENGTHS, C.THINKING_STRENGTHS)
check("没有档位的模型是空数组而不是缺字段",
      [m for m in cat["groups"][C.GROUP_BUILTIN]
       if m["id"] == "Qwen3-VL-235B"][0]["thinkingStrengths"] == [])
check("有档位但为空时也不编档位",
      [m for m in cat["groups"][C.GROUP_BUILTIN]
       if m["id"] == "glm-5.3"][0]["thinkingStrengths"] == [], cat["models"])

# 档位接口挂了：清单照旧返回，但要记一笔 —— 否则面板上全显示「原生」，
# 分不清是「本来没有档位」还是「这次没问到」。
cat_t = with_catalog(variants_exc=RuntimeError("APIG.0613"))
check("档位失败不影响清单", len(cat_t["models"]) == 3, len(cat_t["models"]))
check("档位失败记进 errors", "thinking" in cat_t["errors"], cat_t["errors"])

# 内置目录取不到：回空清单 + 原因，绝不抛异常（面板靠 errors 说明）。
empty = with_catalog(builtin_exc=RuntimeError("PromptCenter 挂了"))
check("内置取数挂了回空清单而不是抛异常", empty["models"] == [], empty["models"])
check("并说明原因",
      "PromptCenter 挂了" in empty["errors"].get(C.GROUP_BUILTIN, ""),
      empty["errors"])


# ---------------------------------------------------------------------------
# 接进 /v1/models 的形状适配
# ---------------------------------------------------------------------------
#
# model_entry 的 meta 契约里 contextWindow 是**带 supportedLengths 的 dict**，
# 而 ca_codearts 归一出来的是数字。第一版直接把归一结果喂进去，抛
# AttributeError: 'int' object has no attribute 'get'，又被外层 try 吞成
# 「清单里没有码道模型」—— 表现成功能没生效、且不报错。这几条钉住那个适配。

print()
print("== 接进 /v1/models 的形状适配 ==")

import ca_proxy as P  # noqa: E402  (需要它才能验 model_entry 契约)
import ca_stream as S2  # noqa: E402

_META = {
    "id": "deepseek-v4.1-flash", "name": "deepseek-v4.1-flash",
    "group": C.GROUP_BUILTIN, "contextWindow": 1000000,
    "maxInputTokens": 1000000, "maxOutputTokens": 384000,
    "supportsImages": False, "supportsReasoning": True,
    "supportsToolCall": True, "routable": True, "creditRatio": None,
    "temperature": 0.5, "top_p": 0.0,
}

adapt = P.codearts_model_meta(_META)
check("contextWindow 被转成带 supportedLengths 的 dict",
      isinstance(adapt.get("contextWindow"), dict)
      and adapt["contextWindow"].get("supportedLengths") == [1000000], adapt)
check("上下文长度同时给了 maxInputTokens",
      adapt.get("maxInputTokens") == 1000000, adapt)
check("maxOutputTokens 一并带出", adapt.get("maxOutputTokens") == 384000, adapt)
check("厂商标成 codearts", adapt.get("vendor") == "codearts", adapt)
check("默认采样参数进 meta",
      adapt.get("temperature") == 0.5 and adapt.get("top_p") == 0.0, adapt)

# 关键：把适配结果喂给 model_entry 不能炸
try:
    entry = P.model_entry(_META["id"], adapt)
    boom = None
except Exception as exc:                      # noqa: BLE001
    entry, boom = None, exc
check("model_entry 能吃下适配后的 meta（曾经抛 int.get）", boom is None, boom)
if entry:
    check("条目 id 正确", entry.get("id") == _META["id"], entry.get("id"))
    check("条目 object 是 model", entry.get("object") == "model")
    check("条目有 context_length", bool(entry.get("context_length")), entry)
    check("条目带出默认采样参数",
          entry.get("temperature") == 0.5 and entry.get("top_p") == 0.0, entry)

# 没有上下文信息的模型（内置那组服务端不给）也不能炸
bare = dict(_META, id="GLM-5.2", contextWindow=0, maxInputTokens=0,
            maxOutputTokens=0, group=C.GROUP_BUILTIN, supportsImages=True)
bare_adapt = P.codearts_model_meta(bare)
check("缺上下文信息时不编造 contextWindow",
      "contextWindow" not in bare_adapt, bare_adapt)
try:
    P.model_entry("GLM-5.2", bare_adapt)
    bare_boom = None
except Exception as exc:                      # noqa: BLE001
    bare_boom = exc
check("缺上下文信息时 model_entry 也不炸", bare_boom is None, bare_boom)

wrapped = P.codearts_model_entry(_META)
check("包装后 owned_by 是 codearts", wrapped.get("owned_by") == "codearts", wrapped)
check("包装后带出分组", wrapped.get("group") == C.GROUP_BUILTIN, wrapped)

check("分流判定认得码道模型", P.is_codearts_model("deepseek-v4.1-flash"))
check("分流判定认得内置那组", P.is_codearts_model("GLM-5.2"))
check("分流判定不误伤 WorkBuddy 模型", not P.is_codearts_model("hy4-preview-f"))
check("空模型名不误判", not P.is_codearts_model(""))
check("None 不误判", not P.is_codearts_model(None))


# ---------------------------------------------------------------------------
# 模型目录：过期但可续期的账号仍要能刷出清单
# ---------------------------------------------------------------------------
#
# 旧实现只留 STS 未过期的会话，闲置两小时后目录整体变空、看板「刷新榜单」
# 只会回「没有可用码道账号」。refresh_token 明明还能换新 STS，所以判据必须
# 是「未过期 **或** 可续期」。

print()
print("== 模型目录对可续期账号可用 ==")

_cat_dir = tempfile.mkdtemp(prefix="wb-codearts-catalog-")
C.save_session(_cat_dir, dict(_session, expires_at="2020-01-01T00:00:00.000Z"))
_saved_dir = P.ACCOUNTS_DIR
_saved_catalog = dict(P._CODEARTS_CATALOG)
_saved_ensure_cat = C.ensure_fresh_session
_saved_model_catalog = C.model_catalog


def _ensure_cat(accounts_dir, session, margin=None):
    return dict(session, accessKey="FRESHAK", secretKey="S",
                securitytoken="T", expires_at="2099-01-01T00:00:00.000Z")


def _model_catalog_cat(ak, sk, tok, timeout=None):
    return {"models": [{"id": "deepseek-v4.1-flash", "routable": True}],
            "errors": {}}


P.ACCOUNTS_DIR = _cat_dir
C.ensure_fresh_session = _ensure_cat
C.model_catalog = _model_catalog_cat
try:
    _cat_out = dict(P.codearts_catalog(force=True))
finally:
    P.ACCOUNTS_DIR = _saved_dir
    C.ensure_fresh_session = _saved_ensure_cat
    C.model_catalog = _saved_model_catalog
    P._CODEARTS_CATALOG.clear()
    P._CODEARTS_CATALOG.update(_saved_catalog)
    shutil.rmtree(_cat_dir, ignore_errors=True)

check("过期但可续期的会话仍能刷新出模型",
      [m.get("id") for m in _cat_out.get("models") or []]
      == ["deepseek-v4.1-flash"], _cat_out)


# ---------------------------------------------------------------------------
# 分流前提：只有真的配了码道账号，重名模型才归码道
# ---------------------------------------------------------------------------
#
# deepseek-v4.1-flash / glm-5.3 / glm-5.3-flash 两边都有。分流按「码道优先」，
# 但前提是部署真的配了码道账号：纯 WorkBuddy 部署里这些名字在 /v1/models
# 挂的是 WorkBuddy 条目，拐去码道只会让清单里列得出来的模型必然 503。

# ---------------------------------------------------------------------------
# /v1/models：只列码道（WorkBuddy 池已移除）
# ---------------------------------------------------------------------------
#
# 以前这里要验证「重名条目以码道为准」的合并规则。池删掉之后没有重名可合，
# 清单只可能来自码道目录 —— 于是要钉的是三件事：只出码道、没账号时回空表
# （不拿内置快照凑数）、别名照常展开。

print()
print("== /v1/models 只列码道 ==")


class _CatalogHandler(P.Handler):
    def __init__(self):
        self.captured = None

    def _authorized(self):
        return True

    def _request_realm(self):
        return "cn"

    def _json(self, code, obj):
        self.captured = (code, obj)


_CA_DS = {
    "id": "deepseek-v4.1-flash", "name": "deepseek-v4.1-flash",
    "group": C.GROUP_BUILTIN, "supportsImages": False,
    "supportsReasoning": True, "supportsToolCall": True,
    "creditRatio": "0.18x",
    "creditPricing": {"ratio": 0.05, "ratio_display": "0.18x",
                      "credits_per_mtok_output": 160.0, "time_slots": {}},
    "temperature": 0.5, "top_p": 0.0,
    "thinkingStrengths": [], "thinkingDefault": "",
}
_CA_GLM = dict(_CA_DS, id="glm-5.3", name="glm-5.3",
               creditRatio="0.79x",
               thinkingStrengths=["high", "max"], thinkingDefault="high")

_saved_list = (P.codearts_catalog, P.codearts_deployed, P.model_aliases,
               P.ca_modelsdev.refresh_async)
try:
    P.codearts_catalog = lambda: {"models": [dict(_CA_DS), dict(_CA_GLM)],
                                  "errors": {}}
    P.codearts_deployed = lambda: True
    P.model_aliases = lambda: {}
    P.ca_modelsdev.refresh_async = lambda *a, **k: None
    _list_handler = _CatalogHandler()
    _list_handler._get_v1_models()
    _list_code, _list_payload = _list_handler.captured
    _ids = [e["id"] for e in _list_payload["data"]]
    check("清单只出码道模型", sorted(_ids) == ["deepseek-v4.1-flash", "glm-5.3"],
          _ids)
    check("每条都标 owned_by=codearts",
          all(e.get("owned_by") == "codearts" for e in _list_payload["data"]),
          [e.get("owned_by") for e in _list_payload["data"]])
    check("codearts 段带出条数", _list_payload["codearts"]["count"] == 2,
          _list_payload.get("codearts"))
    check("不再有 WorkBuddy 目录来源字段",
          "catalog" not in _list_payload, sorted(_list_payload))

    # 别名：目标在本清单里才展开，且 ownership 跟着目标走。
    P.model_aliases = lambda: {"gpt-5-codex": "glm-5.3",
                               "claude-sonnet-4-5-20250929": "不存在的模型"}
    _alias_handler = _CatalogHandler()
    _alias_handler._get_v1_models()
    _alias_by_id = {e["id"]: e for e in _alias_handler.captured[1]["data"]}
    check("别名指向清单里的模型时展开成独立条目",
          "gpt-5-codex" in _alias_by_id
          and _alias_by_id["gpt-5-codex"].get("alias_of") == "glm-5.3",
          sorted(_alias_by_id))
    check("别名指向不存在的模型时不出现",
          "claude-sonnet-4-5-20250929" not in _alias_by_id, sorted(_alias_by_id))

    # 没有码道账号：回空清单并说明原因，绝不拿 WorkBuddy 快照兜底。
    P.codearts_deployed = lambda: False
    _empty_handler = _CatalogHandler()
    _empty_handler._get_v1_models()
    _empty_payload = _empty_handler.captured[1]
    check("没有码道账号时清单为空", _empty_payload["data"] == [],
          _empty_payload.get("data"))
    check("空清单要说明原因",
          _empty_payload["codearts"]["errors"].get("sessions") is not None,
          _empty_payload.get("codearts"))
finally:
    (P.codearts_catalog, P.codearts_deployed, P.model_aliases,
     P.ca_modelsdev.refresh_async) = _saved_list


# ---------------------------------------------------------------------------
# 模型封锁不能被码道分流绕过去
# ---------------------------------------------------------------------------
#
# /v1/responses 和 /v1/messages 都在分流前判「模型封禁 / 按 key 限模型」，
# 唯独 /v1/chat/completions 原来先分流走码道，封锁判断压根没机会执行 ——
# 面板里封掉的模型照样能通过码道调出去。三个入口必须一个口径。

print()
print("== 模型封锁不被码道分流绕过 ==")


class _FakeBanHandler(object):
    def __init__(self):
        self.path = "/v1/chat/completions"
        self.headers = {}
        self.reached = False

    def _error(self, code, message, err_type=None):
        return {"code": code, "message": message}

    def _banned_model_error(self, model):
        return "model is banned" if model == "deepseek-v4.1-flash" else ""

    def _key_model_error(self, model):
        return "model not allowed for this key" if model == "glm-5.3-flash" else ""

    def _handle_codearts_chat(self, payload):
        self.reached = True
        return {"code": 200}


_ban = _FakeBanHandler()
_banned_out = P.Handler._dispatch_chat_post(
    _ban, "/v1/chat/completions", {"model": "deepseek-v4.1-flash"})
check("封禁的码道模型在分流前就回 400",
      isinstance(_banned_out, dict) and _banned_out.get("code") == 400,
      _banned_out)
check("封禁的模型没走到码道", not _ban.reached, _ban.reached)

_ban2 = _FakeBanHandler()
_keyed_out = P.Handler._dispatch_chat_post(
    _ban2, "/v1/chat/completions", {"model": "glm-5.3-flash"})
check("按 key 限掉的码道模型在分流前就回 400",
      isinstance(_keyed_out, dict) and _keyed_out.get("code") == 400,
      _keyed_out)
check("按 key 限掉的模型没走到码道", not _ban2.reached, _ban2.reached)

_ban3 = _FakeBanHandler()
_ok_out = P.Handler._dispatch_chat_post(
    _ban3, "/v1/chat/completions", {"model": "GLM-5.2"})
check("没被封的码道模型照常走码道",
      _ban3.reached and isinstance(_ok_out, dict)
      and _ok_out.get("code") == 200, (_ban3.reached, _ok_out))


# ---------------------------------------------------------------------------
# /v1/responses：码道没有原生 Responses 端点，网关用翻译层桥接
# ---------------------------------------------------------------------------
#
# 逆向本地 CodeArts 客户端（vscode-codebot/out/extension.js）确认：它只发
# chat/completions 形状，没有 /v1/responses、previous_response_id 或 Responses
# 流事件。所以网关必须自己把 Responses 请求翻成 chat，再把码道的 SSE 还原成
# Responses 的 JSON / 事件流。这里钉住桥接的两条出口。

print()
print("== 码道 Responses 桥接 ==")


class _FakeResponsesHandler(P.Handler):
    def __init__(self):
        self.path = "/v1/responses"
        self.wfile = io.BytesIO()
        self.status = None
        self.payload = None

    def _client_disconnected(self):
        # 桩没有真实 socket；基类实现读 self.connection 会抛 AttributeError，
        # 被当成「客户端已断开」，码道链路于是在第一次尝试前就退出。
        return False

    def _json(self, code, obj):
        self.status = code
        self.payload = obj
        return code, obj

    def send_response(self, code):
        self.status = code

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass

    def _key_id(self):
        return "test-key"

    def _anthropic_error(self, code, message, err_type=None):
        self.status = code
        self.payload = {"type": "error",
                        "error": {"type": err_type or "api_error",
                                  "message": message}}
        return code, self.payload


_CHAT_RAW = (
    'data: {"choices":[{"delta":{"content":"你"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"好"},"finish_reason":"stop"}]}\n\n'
    "data: [DONE]\n\n"
)


def _stub_codearts(payload, want_stream=None, error_factory=None, anthropic=False):
    return None, {
        "model": payload.get("model"),
        "content": "你好",
        "reasoning": "",
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
        "raw": _CHAT_RAW,
        "want_stream": bool(want_stream),
    }


class _StubLease:
    """测试替身：把一段现成 SSE 文本伪装成「实时行流」。

    2026-10-22 起真流式走 ca_codearts.open_chat + iter_sse，不再经过
    _codearts_chat_result，所以流式用例必须在这个新接缝上打桩，否则会真的
    去连上游（一次跑三分钟，看着像挂死）。
    """

    account_label = "stub"

    def __init__(self, text):
        self._text = text
        self.started_at = __import__("time").time()

    def lines(self, abort_check=None):
        for line in self._text.splitlines(keepends=True):
            yield line

    def byte_lines(self, abort_check=None, stats=None):
        # 签名要与真租约一致：线上调用会带一个 stats 字典回来填断流归因
        # （silent_s / bytes / pings），这里只接住、不填。
        for line in self.lines(abort_check):
            yield line.encode("utf-8")

    def close(self):
        pass


def _stub_open_lease(payload, model, messages, max_tokens, fail=None,
                     anthropic=False):
    return None, _StubLease(_CHAT_RAW)


# 一个最小的合法回合：单 system / 空列表会被网关在请求阶段拦下。
_USER = {"role": "user", "content": "hi"}

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._responses_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]},
                       False, set(), {"tools": []}, None)
check("非流式回 response 对象",
      isinstance(_h.payload, dict) and _h.payload.get("object") == "response",
      _h.payload)
check("非流式正文进 output_text", _h.payload.get("output_text") == "你好",
      _h.payload)
check("非流式保留 usage",
      (_h.payload.get("usage") or {}).get("input_tokens") == 3, _h.payload)

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._codearts_open_lease = _stub_open_lease
_h._responses_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]},
                       True, set(), {"tools": []}, None)
_sse = _h.wfile.getvalue().decode("utf-8")
check("流式发 Responses 事件（不是 chat.completion.chunk）",
      "response.output_text.delta" in _sse
      and "chat.completion.chunk" not in _sse, _sse[:300])
check("流式事件带 sequence_number", '"sequence_number"' in _sse)
check("流式以 response.completed 收尾",
      "response.completed" in _sse and "你好" in _sse, _sse[-400:])

# 入口分流：码道模型必须在这里就拐走，不能再落到 WorkBuddy 账号池
# （修复前的病灶：/v1/responses 只认 WorkBuddy 的 open_upstream，
# 码道模型在 /v1/models 里看得见，走 Responses 却永远 503）。
_h = _FakeResponsesHandler()
_h.headers = {}
_h.key_entry = None
_h._codearts_chat_result = _stub_codearts
_h._request_realm = lambda explicit=None: "cn"
# 账号池删除后没有「第二套上游」可落：码道模型必须交给码道翻译层，
# 其余名字一律 404。以前这里桩掉 open_upstream 来证明「没落进池子」，
# 现在池子根本不存在，改桩分发点。
_hit = {"codearts": False}
_saved_dispatch = _h._responses_codearts


def _spy_dispatch(*args, **kwargs):
    _hit["codearts"] = True
    return _saved_dispatch(*args, **kwargs)


_h._responses_codearts = _spy_dispatch
_h._handle_responses({"model": "deepseek-v4.1-flash", "input": "hi"})

check("Responses 把码道模型交给码道翻译层", _hit["codearts"], _hit)
check("Responses 入口能返回码道正文",
      (_h.payload or {}).get("output_text") == "你好", _h.payload)

_h404 = _FakeResponsesHandler()
_h404.headers = {}
_h404.key_entry = None
_h404._handle_responses({"model": "no-such-model", "input": "hi"})
check("Responses 对非码道模型回 404",
      _h404.status == 404, (_h404.status, _h404.payload))


# ---------------------------------------------------------------------------
# Anthropic Messages：同一个缺口，开关打开后码道模型也不能掉进空池
# ---------------------------------------------------------------------------

print()
print("== 码道 Messages 桥接 ==")

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._messages_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]}, False)
_msg_blocks = (_h.payload or {}).get("content") or []
check("Messages 非流式回 Anthropic message",
      (_h.payload or {}).get("type") == "message", _h.payload)
check("Messages 非流式正文进 text block",
      any(b.get("type") == "text" and b.get("text") == "你好"
          for b in _msg_blocks), _h.payload)
check("Messages 非流式保留 usage",
      (_h.payload.get("usage") or {}).get("input_tokens") == 3, _h.payload)
check("Messages 非流式回填 model",
      _h.payload.get("model") == "deepseek-v4.1-flash", _h.payload)

# 单 system / 空消息列表：上游回 ModelArts.81001.400，报错点离原因太远，
# 网关在请求阶段就拦下（2026-10-23）。
_SYSTEM_ONLY = {"model": "deepseek-v4.1-flash",
                "messages": [{"role": "system", "content": "you are terse"}]}
_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._responses_codearts(dict(_SYSTEM_ONLY), False, set(), {"tools": []}, None)
check("Responses 只有 system 时回 400，文案点名 81001",
      _h.status == 400 and "81001" in str((_h.payload or {}).get("error", {}).get("message")),
      (_h.status, _h.payload))

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._messages_codearts(dict(_SYSTEM_ONLY), False)
check("Messages 只有 system 时回 Anthropic 信封的 400",
      _h.status == 400
      and (_h.payload or {}).get("type") == "error"
      and (_h.payload or {}).get("error", {}).get("type") == "invalid_request_error",
      (_h.status, _h.payload))

_h = _FakeResponsesHandler()
_h._codearts_chat_result = _stub_codearts
_h._codearts_open_lease = _stub_open_lease
_h._messages_codearts({"model": "deepseek-v4.1-flash", "messages": [_USER]}, True)
_sse = _h.wfile.getvalue().decode("utf-8")
check("Messages 流式事件齐全",
      "event: message_start" in _sse
      and "text_delta" in _sse
      and "event: message_stop" in _sse, _sse[:400])

_h = _FakeResponsesHandler()
_h.headers = {}
_h.key_entry = None
_h._codearts_chat_result = _stub_codearts
_h._request_realm = lambda explicit=None: "cn"
_hit = {"codearts": False}
_saved_msg_dispatch = _h._messages_codearts


def _spy_msg_dispatch(*args, **kwargs):
    _hit["codearts"] = True
    return _saved_msg_dispatch(*args, **kwargs)


_h._messages_codearts = _spy_msg_dispatch
_h._handle_messages({"model": "deepseek-v4.1-flash",
                     "messages": [{"role": "user", "content": "hi"}],
                     "max_tokens": 16})
check("Messages 把码道模型交给码道翻译层", _hit["codearts"], _hit)
check("Messages 入口能返回码道正文",
      any(b.get("type") == "text" and b.get("text") == "你好"
          for b in (_h.payload or {}).get("content") or []), _h.payload)

_h404 = _FakeResponsesHandler()
_h404.headers = {}
_h404.key_entry = None
_h404._handle_messages({"model": "no-such-model",
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 16})
check("Messages 对非码道模型回 404",
      _h404.status == 404, (_h404.status, _h404.payload))


# ---------------------------------------------------------------------------
print()
print("== _error 必须返回哨兵（不回 None） ==")
#
# 2026-10-21 线上事故：_error 发完响应隐式返回 None，而调用方靠
# `if error is not None` 判「是否已回过响应」。于是每条失败请求在回完 502
# 之后又被当成成功继续走 result["model"]，日志里留下一段
# TypeError: 'NoneType' object is not subscriptable，真实错误被埋掉。

_h2 = _FakeResponsesHandler()
_h2.headers = {}
_h2._handle_expect_continue = lambda: None
_h2._discard_body = lambda: None
_r = P.Handler._error(_h2, 502, "boom", "upstream_error")
check("_error 回的不是 None", _r is not None, repr(_r))
check("_error 回的是 RESPONDED", _r is P.RESPONDED, repr(_r))
_r2 = P.Handler._anthropic_error(_h2, 400, "nope", "invalid_request_error")
check("_anthropic_error 回的是 RESPONDED", _r2 is P.RESPONDED, repr(_r2))


def _stub_fail(payload, want_stream=None, error_factory=None):
    """模拟「已回过响应」的形态：返回 (RESPONDED, None)。"""
    return P.RESPONDED, None


_h3 = _FakeResponsesHandler()
_h3._codearts_chat_result = _stub_fail
# 以前这一行会抛 TypeError；现在应安静返回、不碰 result
_out = P.Handler._handle_codearts_chat(
    _h3, {"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}]})
check("已回过响应的路径不再解引用 result",
      _out is P.RESPONDED, repr(_out))


# ---------------------------------------------------------------------------
# 发给码道的消息：角色名归一，正文不动
# ---------------------------------------------------------------------------

print()
print("== 码道链路的角色归一 ==")

_seen = {}


def _fake_chat(ak, sk, tok, model, messages, max_tokens=None, stream=True,
               extra=None, timeout=None, tools=None, tool_choice=None,
               abort_check=None, aborted=None, session_id=None,
               header_timeout=None, idle_timeout=None, session_retry=None):
    # 桩要跟上真实签名：tools / tool_choice（2026-10-21 透传）、
    # abort_check（2026-10-22 客户端断开感知）。漏一个关键字参数就是
    # TypeError，测出来像「角色归一坏了」，其实是桩老了。
    _seen["model"] = model
    _seen["messages"] = messages
    _seen["max_tokens"] = max_tokens
    _seen["stream"] = stream
    _seen["extra"] = extra
    _seen["tools"] = tools
    _seen["tool_choice"] = tool_choice
    _seen["abort_check"] = abort_check
    _seen["session_id"] = session_id
    _seen["session_retry"] = session_retry
    return 200, (
        'data: {"choices":[{"delta":{"content":"ok"}}]}\n\n'
        'data: {"usage":{"prompt_tokens":1,"completion_tokens":1,'
        '"total_tokens":2}}\n\ndata: [DONE]\n\n')


class _FakePool:
    """测试替身：固定给同一个会话，不碰真实账号目录。

    码道路径每轮都向 _CODEARTS_POOL 要号（多账号负载/故障转移）——
    桩要打在这条接缝上，否则会真读磁盘、拿不到账号就直接 503。
    """

    def __init__(self, sess):
        self.sess = sess
        self.released = 0
        self.penalties = []

    def acquire(self, timeout=None, session_key=None, model=None):
        self.last_session_key = session_key
        self.last_model = model
        return self.sess, "a"

    def remember(self, session_key, key, now=None):
        self.last_remember = (session_key, key)

    def release(self, key):
        self.released += 1

    def penalize(self, key, seconds):
        self.penalties.append((key, seconds))

    def _usable(self):
        return [self.sess]

    def snapshot(self):
        return {"a": {"in_flight": 0, "cooling_s": 0.0}}


_saved_pool = P._CODEARTS_POOL
_saved_chat, _saved_hb = C.chat_for_model, C.heartbeat
_saved_record = P.record_usage
C.heartbeat = lambda *a, **k: (True, "ok")
P._CODEARTS_POOL = _FakePool({
    "accessKey": "AK", "secretKey": "SK", "securitytoken": "TK",
    "account": {"id": "a", "label": "a"},
    "expires_at": "2099-01-01T00:00:00.000Z"})
C.chat_for_model = _fake_chat
P.record_usage = lambda *a, **k: None
try:
    _err, _res = P.Handler._codearts_chat_result(
        _FakeResponsesHandler(),
        {"model": "deepseek-v4.1-flash",
         "messages": [
             {"role": "developer", "content": "you are a coding agent"},
             {"role": "user", "content": [{"type": "text", "text": "yo"}]},
         ]},
        want_stream=False)
finally:
    P._CODEARTS_POOL = _saved_pool
    C.chat_for_model = _saved_chat
    C.heartbeat = _saved_hb
    P.record_usage = _saved_record

_sent = _seen.get("messages") or []
check("developer 角色发出去前归一成 system",
      bool(_sent) and _sent[0].get("role") == "system", _sent)
check("多模态的 content 分片保持原样",
      len(_sent) > 1 and isinstance(_sent[1].get("content"), list), _sent)
check("上游按流式请求（码道只收流式）", _seen.get("stream") is True, _seen)


# ---------------------------------------------------------------------------
print()
print("== 码道路径的思考参数透传 ==")

_mapping = [
    ({}, None, "不带参数 -> 不透传（沿用上游默认）"),
    # 上游不接受关思考（会回 81001 参数错），所以这种请求被丢弃而不是透传。
    ({"thinking": {"type": "disabled"}}, None, "disabled 被丢弃（上游不支持关）"),
    ({"thinking": {"type": "enabled", "budget_tokens": 8192}},
     {"thinking": {"type": "enabled", "budget_tokens": 8192}}, "budget 原样透传"),
    ({"reasoning_effort": "none"}, None, "effort=none 同上，不发"),
    ({"thinking": "disabled"}, None, "字符串 disabled 也丢弃"),
    ({"reasoningEffort": "low"},
     {"thinking": {"type": "enabled"}, "reasoning_effort": "low"}, "camelCase effort"),
]
for payload, expect, label in _mapping:
    got = C.thinking_extra_from(payload)
    check(label, got == expect, "得到 %r，期望 %r" % (got, expect))


def _run_with(payload):
    """跑一次码道聚合，返回 fake 收到的 extra。"""
    _seen.clear()
    saved_chat, saved_rec = C.chat_for_model, P.record_usage
    saved_hb = C.heartbeat
    C.heartbeat = lambda *a, **k: (True, "ok")
    saved_pool = P._CODEARTS_POOL
    P._CODEARTS_POOL = _FakePool({
        "accessKey": "AK", "secretKey": "SK", "securitytoken": "TK",
        "account": {"id": "a", "label": "a"},
        "expires_at": "2099-01-01T00:00:00.000Z"})
    C.chat_for_model = _fake_chat
    P.record_usage = lambda *a, **k: None
    try:
        body = {"model": "glm-5.3",
                "messages": [{"role": "user", "content": "hi"}]}
        body.update(payload)
        P.Handler._codearts_chat_result(_FakeResponsesHandler(), body,
                                        want_stream=False)
        return _seen.get("extra")
    finally:
        P._CODEARTS_POOL = saved_pool
        C.chat_for_model = saved_chat
        C.heartbeat = saved_hb
        P.record_usage = saved_rec


# 模型名归一：大写变体进、上游真名出（统计/限额/降级链共用同一个桶）
_seen.clear()
_run_with({"model": "GLM-5.3", "max_tokens": 100})
check("客户端写 GLM-5.3，打到上游与用量记录的都是 glm-5.3",
      _seen.get("model") == "glm-5.3", _seen.get("model"))
_seen.clear()
_run_with({"model": "totally-unknown-model"})
check("认不出的模型名原样放行（不编近似名）",
      _seen.get("model") == "totally-unknown-model", _seen.get("model"))

check("开思考的请求，extra 传到上游",
      _run_with({"thinking": {"type": "enabled", "budget_tokens": 4096}})
      == {"thinking": {"type": "enabled", "budget_tokens": 4096},
          "user_prompt": "hi"},
      "extra 没传到 chat_for_model")
check("关思考的请求不再发给上游（避免 81001）",
      _run_with({"thinking": {"type": "disabled"}}) == {"user_prompt": "hi"},
      "disabled 不该被透传")
check("没要求时 extra 只剩官方镜像的 user_prompt（2026-10-24 起）",
      _run_with({}) == {"user_prompt": "hi"},
      "默认请求不该带 thinking")


# ---------------------------------------------------------------------------
print()
print("== max_tokens 夹紧（客户端固定发 128000 的回归） ==")
#
# 2026-10-21 线上事故：ZCode 对所有模型固定发 max_tokens=128000，而 glm-5.3 的
# 输出上限是 65536。上游不回「值太大」，而是回
# InferHub.001001005.400 The request param is invalid —— 一句话把整个请求打死，
# 且这个码不在 ca_stream.retryable 里，重试多少次都是同样的 502。
# 现象：用户侧「glm-5.3 一直失败」，而同账号的 GLM-5.2 正常。

# ---------------------------------------------------------------------------
print()
print("== 积分静态兜底（服务重启后 credit 全 0 的回归） ==")
#
# 2026-10-22 线上事故：面板上每条请求的积分都是 0.00。原因是 CREDIT_TIERS 是
# 进程内的运行时状态，只在有人请求模型目录时才被填充 —— 服务重启后、第一次
# 拉 /v1/models 之前，credit_for_usage 查不到档位就返回 None，记录里留着 0。
# 实测：重启后那批请求全 0；手动打一次 /v1/models 再发请求，立刻变成 0.0428。
# 修法是把上游实测到的几档固化进 CREDIT_TIERS_STATIC 作为兜底。

check("静态表覆盖 glm-5.3", "glm-5.3" in C.CREDIT_TIERS_STATIC)
check("静态表的 ratio 与上游一致", 
      C.CREDIT_TIERS_STATIC["glm-5.3"]["ratio"] == 0.0443,
      C.CREDIT_TIERS_STATIC["glm-5.3"]["ratio"])
check("运行时表为空时，积分仍能算出来（不再返回 None）",
      C.credit_for_usage("glm-5.3", 153, 0, 31) is not None,
      C.credit_for_usage("glm-5.3", 153, 0, 31))
_c = C.credit_for_usage("glm-5.3", 13, 0, 64)
check("算出来的量级对（13 入 / 64 出 ≈ 0.04 积分）",
      _c is not None and 0.03 < _c < 0.06, _c)
check("未定价模型仍然返回 None（不编倍率）",
      C.credit_for_usage("Qwen3-VL-235B", 100, 0, 100) is None,
      C.credit_for_usage("Qwen3-VL-235B", 100, 0, 100))
check("openpangu-2.0-pro 仍是两段计价",
      len(C.CREDIT_TIERS_STATIC["openpangu-2.0-pro"]["tiers"]) == 2,
      C.CREDIT_TIERS_STATIC["openpangu-2.0-pro"]["tiers"])
# 运行时表优先：上游调价时不能被静态表盖过
_saved = dict(C.CREDIT_TIERS)
try:
    C.CREDIT_TIERS["glm-5.3"] = {"ratio": 0.5, "tiers": [
        {"input_from": 0, "input_to": -1, "ratio": 0.5,
         "input_price": 100.0, "cache_price": 0.0, "output_price": 0.0}]}
    check("运行时档位优先于静态兜底",
          C.credit_tier_for("glm-5.3")["ratio"] == 0.5,
          C.credit_tier_for("glm-5.3")["ratio"])
finally:
    C.CREDIT_TIERS.clear()
    C.CREDIT_TIERS.update(_saved)

check("128000 被夹到 glm-5.3 的 65536（模型最大输出）",
      C.clamp_max_tokens("glm-5.3", 128000) == (65536, True),
      C.clamp_max_tokens("glm-5.3", 128000))
check("正好等于模型上限的值不动（65536 是能力，不是错值）",
      C.clamp_max_tokens("glm-5.3", 65536) == (65536, False),
      C.clamp_max_tokens("glm-5.3", 65536))
# kimi-k3 的 65536 是实测出来的：65536 → 200，81920 / 100000 / 131072 /
# 262144 → 全是 001001005。没有这条会退化成「ZCode 发 128000 一律 400」。
check("kimi-k3 的 128000 也夹到 65536",
      C.clamp_max_tokens("kimi-k3", 128000) == (65536, True),
      C.clamp_max_tokens("kimi-k3", 128000))
check("kimi-k3 输入窗口 = kernel 真值 1044480（2026-10-24 从官方 kernel 日志补全；"
      "AgentCenter 真值刷新上线后此表会自动跟活数据走）",
      C.BUILTIN_MODEL_LIMITS["kimi-k3"][0] == 1044480,
      C.BUILTIN_MODEL_LIMITS["kimi-k3"])
check("表里没有的模型不夹（别用猜的数改坏本来能过的请求）",
      C.clamp_max_tokens("kimi-k2.6-vl", 128000) == (128000, False),
      C.clamp_max_tokens("kimi-k2.6-vl", 128000))
check("chat_body 里的 max_tokens 已夹到模型上限",
      C.chat_body("glm-5.3", [], max_tokens=128000)["max_tokens"] == 65536,
      C.chat_body("glm-5.3", [], max_tokens=128000))
check("chat_body 对无模型上限的模型保持原值",
      C.chat_body("kimi-k2.6-vl", [], max_tokens=128000)["max_tokens"] == 128000,
      C.chat_body("kimi-k2.6-vl", [], max_tokens=128000))


# ---------------------------------------------------------------------------
print()
print("== 工具调用透传与聚合 ==")
#
# 同一个事故的第二半：chat_body 过去只组 model/messages/max_tokens/stream，
# tools 整个被丢掉。IDE 客户端（ZCode 一次发 39 个工具）于是完全不知道有哪些
# 工具可用，只能把调用写成 `<tool_call>…</tool_call>` 纯文本发回来 ——
# 上游明明原生支持 function calling（会回 delta.tool_calls + finish_reason
# tool_calls），聚合层却只收 content / reasoning_content，把 tool_calls 丢了。

_TOOLS = [{"type": "function", "function": {"name": "get_date",
                                          "description": "d",
                                          "parameters": {"type": "object"}}}]
_body = C.chat_body("glm-5.3", [], max_tokens=256, tools=_TOOLS,
                    tool_choice="auto")
check("chat_body 带上了 tools", _body.get("tools") == _TOOLS, _body)
check("chat_body 带上了 tool_choice", _body.get("tool_choice") == "auto", _body)
check("没有 tools 时不塞空字段",
      "tools" not in C.chat_body("glm-5.3", [], max_tokens=256),
      C.chat_body("glm-5.3", [], max_tokens=256))

# --- 扁平（Responses）形状必须包成码道认的 function 包裹 ---
#
# 线上实测：Responses 入口把 Codex 的扁平声明原样转给码道，上游回
# `InferHub.001001015.400 Tool function cannot empty` —— 它按 tool["function"]
# 取名字，取到空就拒掉整个请求。而 WorkBuddy 上游恰恰要扁平（见
# _test_custom_tools 的 "ordinary function tool untouched"），所以这层转换
# 只能留在码道自己的模块里，不能改通用转换函数。

_FLAT = [{"type": "function", "name": "get_date", "description": "d",
          "parameters": {"type": "object", "properties": {}}, "strict": True}]
_shaped = C.normalize_tools(_FLAT)
check("扁平声明被包进 function",
      _shaped and _shaped[0].get("function", {}).get("name") == "get_date",
      _shaped)
check("name/description/parameters/strict 都搬进去了",
      _shaped and _shaped[0]["function"].get("parameters") == {"type": "object", "properties": {}}
      and _shaped[0]["function"].get("strict") is True, _shaped)
check("已经是包裹形状的不重复包一层",
      C.normalize_tools(_TOOLS) == _TOOLS, C.normalize_tools(_TOOLS))
check("码道没有执行器的声明（custom/web_search）被丢掉",
      C.normalize_tools([{"type": "custom", "name": "apply_patch"},
                         {"type": "web_search"}]) == [],
      C.normalize_tools([{"type": "custom", "name": "apply_patch"},
                         {"type": "web_search"}]))
check("chat_body 里走的就是包裹形状",
      (C.chat_body("glm-5.3", [], max_tokens=256, tools=_FLAT)
       .get("tools") or [{}])[0].get("function", {}).get("name") == "get_date",
      C.chat_body("glm-5.3", [], max_tokens=256, tools=_FLAT).get("tools"))

# 上游真实返回的形状（2026-10-21 线上实测抓的帧）
_SSE_TOOL = (
    'data: {"choices":[{"delta":{"role":"assistant",'
    '"reasoning_content":"let me call it"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"","tool_calls":[{"id":"call_1",'
    '"index":0,"type":"function","function":{"name":"get_date",'
    '"arguments":"{\\"day\\":"}}]}}]}\n\n'
    'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
    '"function":{"arguments":"3}"}}]}}],"usage":'
    '{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}\n\n'
    'data: [DONE]\n\n'
)
_c, _r, _u, _e, _tc = S2.collect_sse(_SSE_TOOL)
check("tool_calls 被聚合出来", len(_tc) == 1, _tc)
check("工具名正确", _tc and _tc[0]["function"]["name"] == "get_date", _tc)
check("id 正确", _tc and _tc[0]["id"] == "call_1", _tc)
check("分片的 arguments 被拼接",
      _tc and _tc[0]["function"]["arguments"] == '{"day":3}',
      _tc[0]["function"]["arguments"] if _tc else None)
check("usage 照样收到", _u.get("total_tokens") == 15, _u)
check("无 tool 调用时返回空列表", S2.collect_sse(
    'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')[4] == [], "应为空")


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 体验版积分：credit_package 的解析口径
# （接口是 snap-access /snap-manager/v1/statistics/plugin，客户端「总已用积分」
#   那一栏用的同一个；2026-10-21 实测响应结构如下）
print()
print("== 体验版积分解析 ==")

_CREDIT_PAYLOAD = {
    "metrics": [
        {"name": "usageTotalPackageCredit", "package_credit_amount": 11500.0,
         "package_credit_used": 4817.0, "package_credit_remain": 6683.0},
        {"name": "usageBasicPackageCredit", "package_credit_amount": 500.0,
         "package_credit_used": 0.0, "package_credit_remain": 500.0},
        {"name": "usageBonusPackageCredit", "package_credit_amount": 11000.0,
         "package_credit_used": 4817.0, "package_credit_remain": 6183.0},
    ],
    "package": {"package_name_cn": "体验版",
                "spec_code": "codearts.agent.individual.trial", "status": "normal"},
    "start_date": "2026-10-15", "end_date": "2026-11-16",
}

_saved_http = C._http
C._http = lambda *a, **k: dict(_CREDIT_PAYLOAD)
try:
    cp = C.credit_package("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("积分总量", cp["total"] == 11500.0, cp)
check("积分已用", cp["used"] == 4817.0, cp)
check("积分剩余", cp["remaining"] == 6683.0, cp)
check("积分百分比", cp["percent"] == 41.89, cp)
check("积分套餐名", cp["package_name"] == "体验版", cp)
check("积分到期日", cp["end_date"] == "2026-11-16", cp)
check("基础包分项", cp["basic"]["total"] == 500.0, cp["basic"])
check("赠送包分项", cp["bonus"]["used"] == 4817.0, cp["bonus"])

# 没有 usageTotalPackageCredit 时返回 None（不是造一堆 0 出来）
C._http = lambda *a, **k: {"metrics": [], "package": {}}
try:
    none_cp = C.credit_package("AK", "SK", "TOK")
finally:
    C._http = _saved_http
check("没有总量指标时返回 None", none_cp is None, none_cp)

# remain 缺失时用 total - used 兜底
C._http = lambda *a, **k: {
    "metrics": [{"name": "usageTotalPackageCredit",
                 "package_credit_amount": 100.0, "package_credit_used": 30.0}],
    "package": {},
}
try:
    fb = C.credit_package("AK", "SK", "TOK")
finally:
    C._http = _saved_http
check("remain 缺失时按 total-used 兜底", fb["remaining"] == 70.0, fb)

# ---------------------------------------------------------------------------
# 每日签到（活动页「每日签到领 1000 积分」）：/v1/ops 的积分体系
# 响应结构照抄 2026-10-19 本机客户端日志里的 delivery / claim / confirm。
# ---------------------------------------------------------------------------
print()
print("== 每日签到（积分） ==")


def _welfare_delivery(claimed):
    daily = {
        "campaignId": 1, "title": "每日签到领1000积分", "type": "USER_LOGIN",
        "benefitAmount": 1000, "benefitUnit": "CREDIT",
        "status": "CONFIRMED" if claimed else "ELIGIBLE",
        "claimable": not claimed, "description": "每日签到领取1000积分",
    }
    return {
        "channel": "IDE", "serverTime": 1792392647046,
        "items": [
            {"campaignId": 4, "title": "新用户注册送 4000 积分",
             "type": "NEW_USER_REGISTER", "benefitAmount": 4000,
             "benefitUnit": "CREDIT", "status": "CLAIMED", "claimable": False},
            daily,
        ],
    }


_welfare_state = {"claimed": False}
_welfare_calls = []


def _fake_welfare_http(method, url, headers=None, body=None, timeout=None):
    path = urllib.parse.urlsplit(url).path
    _welfare_calls.append({
        "method": method, "url": url, "headers": dict(headers or {}),
        "body": json.loads(body) if body else None,
    })
    if path == C.WELFARE_DELIVERY_PATH:
        return {"code": 0, "message": "ok", "data": _welfare_delivery(_welfare_state["claimed"])}
    if path == C.WELFARE_CLAIM_PATH:
        _welfare_state["claimed"] = True
        return {"code": 0, "message": "ok", "data": {
            "campaignId": 1, "campaignTitle": "每日签到领1000积分",
            "status": "CLAIMED", "totalAmount": 1000,
            "claimedAt": "2026-10-21T01:00:00Z"}}
    if path == C.WELFARE_CONFIRM_PATH:
        return {"code": 0, "message": "ok", "data": {
            "campaignId": 1, "campaignTitle": "每日签到领1000积分",
            "status": "CONFIRMED", "totalAmount": 1000,
            "claimedAt": "2026-10-21T01:00:00Z"}}
    raise AssertionError("unexpected welfare url: " + url)


_saved_http = C._http
C._http = _fake_welfare_http
C._welfare_cache.clear()
try:
    _acts = C.welfare_activities("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("活动清单按 type 找到每日签到", _acts["daily"]["campaign_id"] == 1, _acts["daily"])
check("活动清单保留其它活动", len(_acts["items"]) == 2, len(_acts["items"]))
check("签到金额取 benefitAmount", _acts["daily"]["amount"] == 1000, _acts["daily"])
check("可领状态是 ELIGIBLE", _acts["daily"]["status"] == "ELIGIBLE", _acts["daily"])

_get = _welfare_calls[-1]
check("delivery 是 GET 且带 channel=IDE",
      _get["method"] == "GET" and "channel=IDE" in _get["url"], _get["url"])
check("delivery 带 AK/SK 签名", "Authorization" in _get["headers"], sorted(_get["headers"]))
check("delivery 带 STS 令牌",
      _get["headers"].get("X-Security-Token") == "TOK", sorted(_get["headers"]))

# 领取：claim → confirm → 重新拉清单确认状态
_welfare_state["claimed"] = False
_welfare_calls.clear()
C._http = _fake_welfare_http
C._welfare_cache.clear()
try:
    _claim = C.welfare_claim_daily("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("签到成功", _claim["ok"] is True and _claim["already"] is False, _claim)
check("签到后状态是 CONFIRMED", _claim["status"] == "CONFIRMED", _claim)
check("签到达成后带回刷新过的活动状态",
      _claim["activity"]["status"] == "CONFIRMED", _claim.get("activity"))
check("签到带回 1000 积分", _claim["amount"] == 1000, _claim)

_claim_call = next(c for c in _welfare_calls if c["method"] == "POST"
                   and c["url"].endswith(C.WELFARE_CLAIM_PATH))
check("claim body 带 campaignId", _claim_call["body"]["campaignId"] == 1, _claim_call["body"])
check("claim body 带 channel=IDE", _claim_call["body"]["channel"] == "IDE", _claim_call["body"])
check("幂等键形如 claim_1_<毫秒>",
      _claim_call["body"]["idempotentKey"].startswith("claim_1_"), _claim_call["body"])

_confirm_call = next(c for c in _welfare_calls if c["method"] == "POST"
                     and c["url"].endswith(C.WELFARE_CONFIRM_PATH))
check("领完自动 confirm", _confirm_call["body"] == {"campaignId": 1}, _confirm_call["body"])
check("签到后重新拉了一次清单（不信本地状态）",
      sum(1 for c in _welfare_calls if c["url"].startswith(C.SNAP_HOST + C.WELFARE_DELIVERY_PATH)) == 2,
      len(_welfare_calls))

# 已领过就不要再打 claim / confirm
_welfare_state["claimed"] = True
_welfare_calls.clear()
C._http = _fake_welfare_http
C._welfare_cache.clear()
try:
    _again = C.welfare_claim_daily("AK", "SK", "TOK")
finally:
    C._http = _saved_http

check("今日已签到时直接返回 already", _again["ok"] is True and _again["already"] is True, _again)
check("已签到不再发 POST",
      not any(c["method"] == "POST" for c in _welfare_calls), _welfare_calls)

# 业务失败：code 非 0 要抛出来（HTTP 仍是 200）
C._http = lambda *a, **k: {"code": 4000,
                           "message": "invalid channel, group not found",
                           "data": None}
C._welfare_cache.clear()
try:
    _raised = False
    try:
        C.welfare_daily("AK", "SK", "TOK")
    except C.CodeArtsError as exc:
        _raised = True
        check("业务错误带上游 message", "invalid channel" in str(exc), str(exc))
    check("code 非 0 视为失败", _raised)
finally:
    C._http = _saved_http
    C._welfare_cache.clear()

# ---------------------------------------------------------------------------
# 8. 积分计费：倍率 × 单价（逆向自客户端 calculateTurnCredits）
# ---------------------------------------------------------------------------
#
# 下面这两条 ``credit`` 原样抄自 2026-10-21 抓的 /v1/model/builtin 快照
# （.workbuddy/tmp/codearts_builtin_models.json），不是编的：
#   GLM-5.2          ratio 0.05   8 / 2 / 28 元每百万，ratio_display 0.7x
#   openpangu-2.0-pro 两段：0-32000 用 3.2/0.8/14.5，32001+ 用 4.8/1.2/17.6
# 第二段的存在正是必须按 input 取档、不能只取第一段的理由。

section("8. 积分计费规则")

GLM52_RAW = {"model_id": "GLM-5.2", "model_name": "GLM-5.2",
             "model_category": "文本生成", "provider": "internal",
             "supports_images": False,
             "credit": [{"input_from": 0, "input_to": -1,
                         "output_from": 0, "output_to": -1,
                         "ratio": "0.05", "input_price": "8",
                         "cache_price": "2", "output_price": "28",
                         "status": "0", "ratio_display": "0.7x"}]}

PRO_RAW = {"model_id": "openpangu-2.0-pro", "model_name": "OpenPangu-2.0-Pro",
           "credit": [{"input_from": 0, "input_to": 32000,
                       "ratio": "0.028", "input_price": "3.2",
                       "cache_price": "0.8", "output_price": "14.5",
                       "ratio_display": "0.7x"},
                      {"input_from": 32001, "input_to": -1,
                       "ratio": "0.028", "input_price": "4.8",
                       "cache_price": "1.2", "output_price": "17.6",
                       "ratio_display": "0.7x"}]}

FREE_RAW = {"model_id": "Qwen3-VL-235B", "credit": []}

tier = C._credit_tier_raw(GLM52_RAW)
check("GLM-5.2 倍率 = 0.05", tier and tier["ratio"] == 0.05, tier)
check("GLM-5.2 三档单价 8/2/28",
      tier and (tier["input_price"], tier["cache_price"],
                tier["output_price"]) == (8.0, 2.0, 28.0), tier)
check("GLM-5.2 只有一段", len(tier["tiers"]) == 1, tier["tiers"])
check("空 credit 返回 None（不假装免费）", C._credit_tier_raw(FREE_RAW) is None)
check("ratio 为 0 返回 None", C._credit_tier_raw(
    {"credit": [{"ratio": "0", "input_price": "1"}]}) is None)

# 公式：(8*(1000-0) + 2*0 + 28*200) / 1e6 / 0.05 = 0.272
C.CREDIT_TIERS.clear()
C.normalize_builtin([GLM52_RAW, PRO_RAW, FREE_RAW])
check("normalize_builtin 填了 CREDIT_TIERS",
      set(C.CREDIT_TIERS) == {"GLM-5.2", "openpangu-2.0-pro"}, list(C.CREDIT_TIERS))

check("GLM-5.2 1000 入 / 200 出 = 0.272 积分",
      C.credit_for_usage("GLM-5.2", 1000, 0, 200) == 0.272,
      C.credit_for_usage("GLM-5.2", 1000, 0, 200))
# (8*200 + 2*800 + 28*200) / 1e6 / 0.05 = 0.176 —— 缓存命中走 cache_price
check("缓存命中按 cache_price 计（800/1000 命中 = 0.176）",
      C.credit_for_usage("GLM-5.2", 1000, 800, 200) == 0.176,
      C.credit_for_usage("GLM-5.2", 1000, 800, 200))
check("未定价模型返回 None", C.credit_for_usage("Qwen3-VL-235B", 1000, 0, 100) is None)
check("未知模型返回 None", C.credit_for_usage("no-such-model", 1000, 0, 100) is None)
check("cached > prompt 时被夹到 prompt（不产生负价）",
      C.credit_for_usage("GLM-5.2", 100, 500, 0) == round(2.0 * 100 / 1e6 / 0.05, 4),
      C.credit_for_usage("GLM-5.2", 100, 500, 0))

# 分段计价：32K 是分界，越过它单价从 3.2 跳到 4.8
pro = C.CREDIT_TIERS["openpangu-2.0-pro"]
check("32000 输入落在第一段", C._pick_credit_tier(pro, 32000)["input_price"] == 3.2)
check("32001 输入落在第二段", C._pick_credit_tier(pro, 32001)["input_price"] == 4.8)
check("1 输入落在第一段", C._pick_credit_tier(pro, 1)["input_price"] == 3.2)
check("无上限段吃住超大输入",
      C._pick_credit_tier(pro, 10 ** 7)["input_price"] == 4.8)
check("两段单价确实不同（不是重复档）",
      C.credit_for_usage("openpangu-2.0-pro", 40000, 0, 0)
      != C.credit_for_usage("openpangu-2.0-pro", 10000, 0, 0))

# 人话版规则：每百万 token 扣多少积分 = 单价 / ratio
pv = C.credit_pricing_view(C.CREDIT_TIERS["GLM-5.2"])
check("百万输入 = 160 积分", pv["credits_per_mtok_input"] == 160.0, pv)
check("百万输出 = 560 积分", pv["credits_per_mtok_output"] == 560.0, pv)
check("百万缓存 = 40 积分", pv["credits_per_mtok_cache"] == 40.0, pv)
check("单段模型不带 tiers 数组", "tiers" not in pv, list(pv))
pv_pro = C.credit_pricing_view(C.CREDIT_TIERS["openpangu-2.0-pro"])
check("多段模型带出 tiers（2 段）", len(pv_pro.get("tiers") or []) == 2, pv_pro)
check("公式写明是除以 ratio", "/ 1e6 / ratio" in pv["formula"], pv["formula"])

# ---- deepseek 错峰档：按时间而不是按 token 长度选段 ----
# 上游把 default（0.18x）与 off_peak（0.09x）写成完全相同的 input 区间，
# 只按 token 数选段会永远命中 default，夜间账目翻倍。时段 21:00 起 11 小时，
# 即 21:00–07:59 Asia/Shanghai（UTC+8，无夏令时）。
DS_RAW = {
    "model_id": "deepseek-v4.1-flash", "model_name": "DeepSeek-V4.1-Flash",
    "credit": [
        {"input_from": 0, "input_to": -1, "ratio": "0.05",
         "ratio_display": "0.18x", "time_slot_id": "default",
         "input_price": "2", "cache_price": "0.2", "output_price": "8"},
        {"input_from": 0, "input_to": -1, "ratio": "0.05",
         "ratio_display": "0.09x", "time_slot_id": "off_peak",
         "input_price": "1", "cache_price": "0.1", "output_price": "4"},
    ],
    "time_slots": {
        "off_peak": {
            "timezone": "Asia/Shanghai", "schedule": "0 0 21 * * *",
            "duration": 11, "timeunit": "hour",
            "notice": {"zh_cn": "错峰时段5折优惠（每晚21:00-次日7:59）",
                       "en_us": "Off-peak 50% discount"},
        },
        # 上游还会给一个 schedule=null 的 default 槽：它只是把说明重复一遍，
        # 不是时段，展示时不能当成第二档。
        "default": {
            "timezone": "Asia/Shanghai", "schedule": None,
            "duration": None, "timeunit": "hour",
        },
    },
}
ds_raw = C._credit_tier_raw(DS_RAW)
check("两档时段都保留，没有被拍平",
      [r["time_slot_id"] for r in ds_raw["tiers"]] == ["default", "off_peak"],
      ds_raw["tiers"])
check("时段定义随档位带出",
      ds_raw["time_slots"]["off_peak"]["schedule"] == "0 0 21 * * *",
      ds_raw["time_slots"])
C.normalize_builtin([DS_RAW])
ds = C.CREDIT_TIERS["deepseek-v4.1-flash"]

# 北京时间 → epoch（UTC = 北京 - 8h）
def bj(hour, minute=0, second=0, day=22):
    return calendar.timegm((2026, 10, day, hour - 8, minute, second))


day = bj(10)                    # 10:00 白天
night = bj(22)                  # 22:00 夜间
check("白天选默认档 0.18x",
      C._pick_credit_tier(ds, 100, day)["ratio_display"] == "0.18x",
      C._pick_credit_tier(ds, 100, day))
check("夜间选错峰档 0.09x",
      C._pick_credit_tier(ds, 100, night)["ratio_display"] == "0.09x",
      C._pick_credit_tier(ds, 100, night))
check("20:59:59 仍按默认档",
      C._pick_credit_tier(ds, 100, bj(20, 59, 59))["ratio_display"] == "0.18x")
check("21:00 整进入错峰",
      C._pick_credit_tier(ds, 100, bj(21))["ratio_display"] == "0.09x")
check("07:59:59 仍在错峰",
      C._pick_credit_tier(ds, 100, bj(7, 59, 59, day=23))["ratio_display"] == "0.09x")
check("08:00 整退出错峰",
      C._pick_credit_tier(ds, 100, bj(8, day=23))["ratio_display"] == "0.18x")
check("未知时区不打折",
      C._time_slot_active({"timezone": "UTC", "schedule": "0 0 21 * * *",
                           "duration": 11, "timeunit": "hour"}, night) is False)

# 积分：白天 2/0.05 = 40 积分每百万输入；夜间 1/0.05 = 20，正好减半
check("白天百万输入 = 40 积分",
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=day) == 40.0,
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=day))
check("夜间百万输入 = 20 积分",
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=night) == 20.0,
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=night))
check("夜间百万输出 = 80 积分",
      C.credit_for_usage("deepseek-v4.1-flash", 0, 0, 1000000, when=night) == 80.0,
      C.credit_for_usage("deepseek-v4.1-flash", 0, 0, 1000000, when=night))
check("夜间缓存价同步减半",
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 1000000, 0,
                         when=night) == 2.0,
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 1000000, 0, when=night))

# 展示：默认档的代表值不变，错峰档单独给出可读规则，且不混进 tiers
pv_ds = C.credit_pricing_view(ds)
check("错峰视图带倍率 0.09x",
      pv_ds["time_slots"]["off_peak"]["ratio_display"] == "0.09x", pv_ds)
check("错峰视图带时段说明",
      pv_ds["time_slots"]["off_peak"]["schedule"] == "0 0 21 * * *", pv_ds)
check("错峰视图带上游中文说明",
      pv_ds["time_slots"]["off_peak"]["notice"]
      == "错峰时段5折优惠（每晚21:00-次日7:59）", pv_ds)
check("default 槽不算错峰档", "default" not in pv_ds["time_slots"], pv_ds)
check("错峰档百万输入 = 20 积分",
      pv_ds["time_slots"]["off_peak"]["credits_per_mtok_input"] == 20.0, pv_ds)
check("错峰档百万输出 = 80 积分",
      pv_ds["time_slots"]["off_peak"]["credits_per_mtok_output"] == 80.0, pv_ds)
check("错峰行不算进分段 tiers（区间不会重复）", "tiers" not in pv_ds, list(pv_ds))
check("默认档仍是 0.18x / 40 积分",
      pv_ds["ratio_display"] == "0.18x"
      and pv_ds["credits_per_mtok_input"] == 40.0, pv_ds)

# 模型对象上要带出可读规则，面板才有东西显示
objs = C.normalize_builtin([GLM52_RAW])
check("模型对象带 creditPricing",
      objs[0]["creditPricing"]["credits_per_mtok_output"] == 560.0, objs[0])
check("模型对象带 creditRatio 原文（0.7x）",
      objs[0]["creditRatio"] == "0.7x", objs[0]["creditRatio"])

# 反向校准：0.02 / 0.15 / 0.51 是客户端「总已用积分」上实测到的三次增量
# （短/中/长各一次提问）。用公式反推需要的 token 量级，确认数量级没有差 10 倍。
for want, (pin, pout) in ((0.02, (100, 10)), (0.15, (300, 180)),
                          (0.51, (1000, 625))):
    got = C.credit_for_usage("GLM-5.2", pin, 0, pout)
    check("反推 %s 积分（%d 入 / %d 出）→ %.2f" % (want, pin, pout, got),
          abs(got - want) < 0.005, got)


# ---------------------------------------------------------------------------
# 真流式转发的两个地基：open_chat（只建连不读）与 iter_sse（逐行吐出）
# ---------------------------------------------------------------------------
# 为什么单独测这两个：流式路径一旦把「响应头」先发给客户端就没有退路了，
# 所以正确性全靠这两个函数 —— 建连失败必须能拿到错误体去判重试，
# 逐行读取必须能扛住「多字节字符正好被切在两块之间」和「客户端已经走了」。

class _FakeResp:
    """按给定字节块依次吐出，模拟上游 SSE 分段到达。"""

    def __init__(self, pieces, status=200):
        self.pieces = list(pieces)
        self.status = status
        self.closed = False

    def read1(self, size=8192):
        return self.pieces.pop(0) if self.pieces else b""

    def close(self):
        self.closed = True


_TEXT = "data: {\"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\ndata: [DONE]\n\n"
_RAW = _TEXT.encode("utf-8")
# 在「你」的三字节中间切开：逐块 decode 会吐替换字符，增量解码不会
_cut = _RAW.index("你".encode("utf-8")) + 1
_lines = list(C.iter_sse(_FakeResp([_RAW[:_cut], _RAW[_cut:]])))
# 4 行：data 行、空行、[DONE] 行、空行 —— SSE 的空行分隔符也要原样吐出去
check("iter_sse 跨块拼行", len(_lines) == 4, len(_lines))
check("iter_sse 不产生替换字符（多字节未被切断）",
      "\ufffd" not in "".join(_lines), "".join(_lines)[:80])
check("iter_sse 第一行完整",
      json.loads(_lines[0][5:])["choices"][0]["delta"]["content"] == "你好",
      _lines[0])

_calls = {"n": 0}


def _die():
    _calls["n"] += 1
    return True


try:
    list(C.iter_sse(_FakeResp([_RAW]), _die))
    _aborted = False
except C.ChatAborted:
    _aborted = True
check("iter_sse 客户端断开时抛 ChatAborted", _aborted)

# 尾部没有换行的残行也要吐出来，否则最后一帧会被吞掉
_tail = list(C.iter_sse(_FakeResp([b"data: {}\n", b"data: [DONE]"])))
check("iter_sse 吐出没有行尾的残行", _tail[-1] == "data: [DONE]", _tail)

# open_chat：200 要交回未读句柄，错误要把响应体读完交给重试判定
_REAL_URLOPEN = C.urllib.request.urlopen


class _OkResp(_FakeResp):
    status = 200


def _fake_open_ok(*a, **kw):
    return _OkResp([_RAW])


C.urllib.request.urlopen = _fake_open_ok
try:
    _st, _resp, _txt = C.open_chat("a", "b", "c", "glm-5.3", [], max_tokens=16)
finally:
    C.urllib.request.urlopen = _REAL_URLOPEN
check("open_chat 成功时返回未读句柄", _st == 200 and _resp is not None and _txt == "",
      (_st, type(_resp).__name__))


def _fake_open_429(*a, **kw):
    raise C.urllib.error.HTTPError(
        "u", 429, "too many", {}, io.BytesIO(b'{"error_msg":"queue full"}'))


C.urllib.request.urlopen = _fake_open_429
try:
    _st2, _resp2, _txt2 = C.open_chat("a", "b", "c", "glm-5.3", [], max_tokens=16)
finally:
    C.urllib.request.urlopen = _REAL_URLOPEN
check("open_chat 失败时返回状态码+错误体、不给句柄",
      _st2 == 429 and _resp2 is None and "queue full" in _txt2,
      (_st2, _resp2, _txt2[:60]))

# 并发判定：1041 走短退避，别混进 82 秒的 TPM 节奏
check("TM.00001041 认作并发已满",
      S2.concurrency_full(400, '{"error_code":"TM.00001041"}'))
check("TPM 81114 不算并发已满",
      not S2.concurrency_full(429, '{"error_code":"ModelArts.81114"}'))
# 81111 和 81114 是同一种瞬时限流（前者按 TPM，后者按请求数），
# 上游有时把它塞在 HTTP 400 的 body 里，只看状态码会掉进「参数错」分支
# 回 400 —— 客户端于是把一条本来等几秒就好的请求当成坏请求丢掉。
check("81114 映射成 429",
      S2.fail_spec(429, "ModelArts.81114", "")[0] == 429,
      S2.fail_spec(429, "ModelArts.81114", ""))
check("81111 即使包在 400 里也映射成 429",
      S2.fail_spec(400, "InferHub.ModelArts.81111.429",
                            "TPM limit")[0] == 429,
      S2.fail_spec(400, "InferHub.ModelArts.81111.429", "TPM limit"))
check("并发满的退避明显短于 TPU 限流",
      sum(P.CODEARTS_BUSY_DELAYS) < sum(P.CODEARTS_RETRY_DELAYS),
      (P.CODEARTS_BUSY_DELAYS, P.CODEARTS_RETRY_DELAYS))

# 网关自己只放 1 个进上游，等于让第二个客户端等第一个生成完 —— 那是
# 「发出去几分钟没反应」的另一半原因。默认必须大于 1，且不超账号上限 3。
check("码道并发默认 2（账号给 3，留一个给别人）",
      P.CODEARTS_CONCURRENCY == 2, P.CODEARTS_CONCURRENCY)
check("真流式转发默认开启",
      P.CODEARTS_STREAM_PASSTHROUGH is True, P.CODEARTS_STREAM_PASSTHROUGH)


# ---------------------------------------------------------------------------
# 多账号：每号独立名额、按空闲挑号、冷却跳过、故障转移
# ---------------------------------------------------------------------------
#
# 上游的并发上限是**账号级**的 3 个会话。旧实现只有一个全局信号量，多账号时
# 两个问题：总容量不随账号数增长（3 个号也只能跑 2 条），以及轮转挑号不看谁
# 在忙（第 3 条可能压到已满的号上，另一个号闲着）。


def _sess(aid):
    return {"accessKey": "AK-" + aid, "secretKey": "SK", "securitytoken": "TK",
            "account": {"id": aid, "label": aid},
            "expires_at": "2099-01-01T00:00:00.000Z"}


# 池的容量来自 codearts_concurrency()（面板值 > 环境变量 > 默认 2）。在面板
# 改过并发的机器上（生产服务器是 3）这套断言会全部漂移 —— 钉死成 2 再测。
_saved_cap_fn = P.codearts_concurrency
P.codearts_concurrency = lambda: 2
_pool = P._CodeartsAccountPool()
_pool._usable = lambda: [_sess("a"), _sess("b")]
_got = [_pool.acquire(0)[1] for _ in range(4)]
check("两个账号各给一份名额（不是全局共享一个）",
      sorted(_got) == ["a", "a", "b", "b"], _got)
check("每账号容量 = CODEARTS_CONCURRENCY",
      _got.count("a") == P.CODEARTS_CONCURRENCY, _got)
_sess5, _key5 = _pool.acquire(0.05)
check("全部占满时明确返回空（调用方据此回 429）",
      _sess5 is None and _key5 is None, (_sess5, _key5))
check("在跑数按账号记", _pool.snapshot()["a"]["in_flight"] == 2, _pool.snapshot())
for _k in _got:
    _pool.release(_k)
check("还名额后在跑数归零", _pool.snapshot()["a"]["in_flight"] == 0,
      _pool.snapshot())

# 冷却中的号要被跳过；全在冷却时挑最早解冻的，别饿死
_pool2 = P._CodeartsAccountPool()
_pool2._usable = lambda: [_sess("a"), _sess("b")]
_pool2.penalize("a", 60)
_pick2, _pk2 = _pool2.acquire(0)
check("冷却中的账号被跳过（换另一个号）", _pk2 == "b", _pk2)
_pool2.release(_pk2)

_pool3 = P._CodeartsAccountPool()
_pool3._usable = lambda: [_sess("a"), _sess("b")]
_pool3.penalize("a", 30)
_pool3.penalize("b", 60)
# 全在冷却时**不再直接拿最早解冻的那个**：那等于冷却没作用（单账号部署里
# 就是每次都撞同一堵墙）。等不到就如实返回「没有可用号」，由调用方回 429。
_pick3, _pk3 = _pool3.acquire(0)
check("全在冷却时如实返回没有可用号（不再硬塞一个进冷却的号）",
      _pick3 is None and _pk3 is None, (_pick3, _pk3))
# 预算够长时会等到最早的那条解冻
_pool4 = P._CodeartsAccountPool()
_pool4._usable = lambda: [_sess("a"), _sess("b")]
_pool4.penalize("a", 0.1)
_pool4.penalize("b", 60)
_pick4, _pk4 = _pool4.acquire(2.0)
check("预算够长时等到解冻再用（不饿死）", _pk4 == "a", _pk4)
_pool4.release(_pk4)
P.codearts_concurrency = _saved_cap_fn

# 故障转移：A 号报「并发会话已满」→ 给 A 打冷却、立刻换 B
_saved_pool, _saved_open, _saved_hb2 = P._CODEARTS_POOL, C.open_chat, C.heartbeat
_saved_delays, _saved_err = P.CODEARTS_BUSY_DELAYS, P.record_error
try:
    _fx = P._CodeartsAccountPool()
    _fx._usable = lambda: [_sess("a"), _sess("b")]
    P._CODEARTS_POOL = _fx
    P.CODEARTS_BUSY_DELAYS = (0.0,)
    P.record_error = lambda *a, **k: None
    C.heartbeat = lambda *a, **k: (True, "ok")
    _calls = []

    def _open_by_account(ak, sk, tk, model, messages, **kw):
        _calls.append(ak)
        if ak == "AK-a":
            return (400, None,
                    '{"error_code":"TM.00001041",'
                    '"error_msg":"并发会话数已达上限(3个)"}')
        return 200, _FakeResp([b""]), ""

    C.open_chat = _open_by_account
    _h = _FakeResponsesHandler()
    _err, _lease = _h._codearts_open_lease(
        {"model": "glm-5.3", "messages": []}, "glm-5.3", [], 64)
    check("撞并发满会换号重试（多账号故障转移）",
          _err is None and _lease is not None and _lease.account_key == "b",
          (_err, getattr(_lease, "account_key", None)))
    check("换号前先试了原账号", _calls[:2] == ["AK-a", "AK-b"], _calls)
    check("失败的账号被打上冷却",
          _fx.snapshot().get("a", {}).get("cooling_s", 0) > 0, _fx.snapshot())
    check("租约持有的是成功账号的名额",
          _fx.snapshot().get("b", {}).get("in_flight") == 1, _fx.snapshot())
    if _lease is not None:
        _lease.close()
    check("租约关闭后名额归还",
          _fx.snapshot().get("b", {}).get("in_flight") == 0, _fx.snapshot())
finally:
    P._CODEARTS_POOL = _saved_pool
    C.open_chat = _saved_open
    C.heartbeat = _saved_hb2
    P.CODEARTS_BUSY_DELAYS = _saved_delays
    P.record_error = _saved_err


print()
print("[官方形状镜像 2026-10-24] max_tokens 双向钳制 / tool_choice 缺省 / user_prompt")

# 官方 kernel 日志（27 条请求体）：glm-5.3 与 openpangu-2.0-pro 一律
# max_tokens="32000"。双向钳制：小值（思考吃光额度 → 200 OK 0 正文）和
# 超大值（拉长上游排队）都钳到官方值；没实证的模型原样放行。
check("glm-5.3 小值上钳到官方 32000",
      C.cap_output_tokens("glm-5.3", 800) == 32000,
      C.cap_output_tokens("glm-5.3", 800))
check("glm-5.3 超大值下钳到官方 32000",
      C.cap_output_tokens("glm-5.3", 128000) == 32000)
check("openpangu-2.0-pro 同值双向钳",
      C.cap_output_tokens("openpangu-2.0-pro", 100) == 32000)
check("没实证的模型原样放行",
      C.cap_output_tokens("kimi-k3", 800) == 800)
check("非 int 原样放行",
      C.cap_output_tokens("glm-5.3", "32000") == "32000")

# 官方带 tools 时无条件 tool_choice:"auto"；客户端显式 none 仍尊重。
_body = C.chat_body("glm-5.3", [], max_tokens=256, tools=_TOOLS)
check("tools 存在而 tool_choice 缺省时补 auto",
      _body.get("tool_choice") == "auto", _body)
_body = C.chat_body("glm-5.3", [], max_tokens=256, tools=_TOOLS,
                    tool_choice="none")
check("显式 tool_choice=none 不被覆盖",
      _body.get("tool_choice") == "none", _body)

# user_prompt：倒着找最近一条有正文的 user 消息；tool_result 回合跳过。
_MS = [{"role": "user", "content": "第一句"},
       {"role": "assistant", "content": "好的"},
       {"role": "user", "content": [{"type": "tool_result", "id": "t1"}]},
       {"role": "user", "content": [{"type": "text", "text": "最新正问"}]}]
check("取最近一条有正文的 user 消息",
      C.last_user_prompt_text(_MS) == "最新正问",
      C.last_user_prompt_text(_MS))
check("全是 tool_result 时继续往前找",
      C.last_user_prompt_text(_MS[:3]) == "第一句")
check("没有用户正文返回空串", C.last_user_prompt_text([]) == "")
check("超长正文截到 2000 字符",
      len(C.last_user_prompt_text(
          [{"role": "user", "content": "x" * 9999}])) == 2000)

print()
print("[手动回调 2026-10-24] /accounts/codearts/login/callback 逃生通道")


class _FakeLogin:
    def __init__(self, kind="ok", detail="hid_new"):
        self.kind, self.detail = kind, detail
        self.calls = []

    def accept_callback(self, code=None, secret=None, state=None):
        self.calls.append((code, secret))
        return (self.kind, self.detail)


class _FakeCbHandler:
    def __init__(self):
        self.sent = []

    def _error(self, status, message, *_a):
        self.sent.append(("error", status, message))
        return ("error", status, message)

    def _json(self, status, obj):
        self.sent.append(("json", status, obj))
        return obj

    def _codearts_redirect_ok(self, target):
        return P.Handler._codearts_redirect_ok(target)


def _run_cb(payload, kind="ok", detail="hid_new"):
    fake = _FakeLogin(kind, detail)
    saved_login, saved_clear = P.CODEARTS_LOGIN, P.codearts_clear_cooldown_for
    cleared = []
    P.CODEARTS_LOGIN = fake
    P.codearts_clear_cooldown_for = lambda aid: cleared.append(aid)
    h = _FakeCbHandler()
    try:
        P.Handler._route_codearts_login_callback(h, payload)
    finally:
        P.CODEARTS_LOGIN = saved_login
        P.codearts_clear_cooldown_for = saved_clear
    return h.sent, fake.calls, cleared


_sent, _calls, _cleared = _run_cb(
    {"url": "http://127.0.0.1:9000/oauth/callback?code=l3m32XZK&state=ad22bb"})
check("完整 URL：code 提取并送进 accept_callback",
      _calls == [("l3m32XZK", "")] and _sent[0][0] == "json" and _sent[0][2].get("ok") is True,
      (_calls, _sent))
check("成功路径清掉该账号的冷却", _cleared == ["hid_new"], _cleared)

_sent, _calls, _cleared = _run_cb({"url": "?code=abc&state=xyz"})
check("裸查询串同样可用", _calls == [("abc", "")], _calls)
_sent, _calls, _cleared = _run_cb({"url": "code=abc&state=xyz"})
check("不带 ? 前缀的查询串同样可用", _calls == [("abc", "")], _calls)

_sent, _calls, _cleared = _run_cb({"url": "http://127.0.0.1:9000/oauth/callback?state=xyz"})
check("缺 code/secret 报 400", _sent[0][0] == "error" and _sent[0][1] == 400, _sent)
_sent, _calls, _cleared = _run_cb({"url": ""})
check("空 url 报 400", _sent[0][0] == "error" and _sent[0][1] == 400, _sent)
_sent, _calls, _cleared = _run_cb(
    {"url": "http://127.0.0.1:9000/oauth/callback?code=x"}, kind="error", detail="STS5.1806")
check("accept_callback 失败回 400 带原因",
      _sent[0][0] == "error" and "STS5.1806" in _sent[0][2], _sent)

# old_login 的中间一跳：secret-only → redirect，把 redirect 参数校验后还给面板
_sent, _calls, _cleared = _run_cb(
    {"url": "https://login.huaweicloud.com/oauth2/continue?secret=abc"
            "&redirect=https://snap-access.cn-north-4.myhuaweicloud.com/next"},
    kind="redirect", detail="abc")
check("redirect 一跳：可信域名的续走链接还给面板",
      _sent[0][0] == "json" and _sent[0][2].get("status") == "redirect"
      and _sent[0][2].get("url", "").startswith("https://snap-access."),
      _sent)
_sent, _calls, _cleared = _run_cb(
    {"url": "https://x/oauth2/continue?secret=abc&redirect=https://evil.example.com/next"},
    kind="redirect", detail="abc")
check("redirect 目标不可信时拒绝", _sent[0][0] == "error" and _sent[0][1] == 400, _sent)

print()
print("[state 比对 / 登录补签 2026-10-25]")

_root3 = tempfile.mkdtemp(prefix="wb-codearts-state-")
_real_exchange3 = C.exchange_code
C.exchange_code = _stub_exchange          # 复用第 7 节的桩：换 token 不出网
try:
    SEEN["fail"] = None
    _LM = C.LoginManager(_root3, log=lambda *a, **k: None)
    _st = _LM.start(9000)["state"]
    _r1 = _LM.accept_callback(code="c1", state=_st)
    check("state 匹配时正常走换 token（这里被桩成成功）",
          _r1[0] == "ok", _r1)

    _LM2 = C.LoginManager(_root3, log=lambda *a, **k: None)
    _LM2.start(9000)
    _r2 = _LM2.accept_callback(code="c1", state="wrong-state-xyz")
    check("state 不匹配直接拒绝，不消耗当前 pending",
          _r2[0] == "error" and "state 不匹配" in _r2[1], _r2)
    _r3 = _LM2.accept_callback(code="c3")
    check("state 为空（老链路）跳过比对",
          _r3[0] == "ok", _r3)
finally:
    SEEN["fail"] = None
    C.exchange_code = _real_exchange3

# 登录成功 → 顺手补签当天积分（异步外壳下面的同步主体）
_welcome_hits = []
_saved_wc, _saved_load = C.welfare_claim_daily, C.load_sessions
C.welfare_claim_daily = lambda ak, sk, st: _welcome_hits.append((ak, sk, st)) or {
    "ok": True, "already": False, "amount": 1000}
C.load_sessions = lambda _d: [{
    "accessKey": "AK-1", "secretKey": "SK-1", "securitytoken": "ST-1",
    "account": {"id": "acc-1", "label": "acc-1"}}]
try:
    P._codearts_welcome_claim_sync("acc-1")
    P._codearts_welcome_claim_sync("no-such")
    P._codearts_welcome_claim_sync("")
finally:
    C.welfare_claim_daily, C.load_sessions = _saved_wc, _saved_load
check("登录补签：按账号 id 找到会话并签了一次",
      len(_welcome_hits) == 1 and _welcome_hits[0][0] == "AK-1", _welcome_hits)
check("补签找不到账号 / 空 id 时静默（不抛不签）", len(_welcome_hits) == 1)

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

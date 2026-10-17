"""码道 CodeArts（华为云）授权链路的确定性测试。

不联网。所有服务端交互都用打桩函数替换，但**密码学部分是真算的**——
里面钉了几个真实样本做金标准：

1. P-256 已知向量（d=1 → G，2G 坐标，RFC 6979 A.2.5 的 r）。
2. JWK thumbprint 对着服务端在真实 refresh_token 里写下的 `cnf.jkt`
   （`9um3t6uGoxSBURtpFD0aLLJhrNduFQekMsgZyJj3gxg`）。这一条把曲线运算、
   JWK 规范化、base64url 三件事同时钉死 —— 三者任一有偏差都对不上。
3. DPoP proof 用公钥独立验签，而不是复用自己的签名函数。
"""

import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_codearts as C  # noqa: E402

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

_ticket = C.session_from_ticket({
    "user_id": "u1", "user_name": "hid_x", "domain_id": "d1",
    "credential": {"access": "AK", "secret": "SK", "securitytoken": "ST",
                   "expires_at": "2026-10-17T10:00:00Z"},
}, dpop_key=_key, pkce=_pkce)
check("ticket 通道也归一出会话", _ticket["accessKey"] == "AK" and _ticket["accessKey"] != "")
check("ticket 通道没有 refresh_token", _ticket["refresh_token"] == "")
check("ticket 通道摘要为 old_login", C.summarize(_ticket)["mode"] == "old_login")

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

from wb_proxy import Handler  # noqa: E402  (需要完整模块才能取到静态方法)

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

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

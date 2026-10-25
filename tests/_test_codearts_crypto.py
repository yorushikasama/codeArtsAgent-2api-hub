# -*- coding: utf-8 -*-
"""码道授权链路的密码学部分（P-256 曲线 / JWK thumbprint / PKCE / DPoP）

不联网。2026-10-24 自 _test_codearts.py 按域拆出；共享夹具在
_codearts_fixtures.py。跑法：python tests/_test_codearts_crypto.py
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



print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

# -*- coding: utf-8 -*-
"""ca_codearts.py - 码道 CodeArts Agent（华为云）授权链路

纯标准库实现，不引入 cryptography / jose：DPoP 要的 ES256 私钥签名自己算。

## 实测确认的三件事

样本取自本机已登录的码道 5.4.2（`%APPDATA%/codearts-agent` 的
`secret://huaweicloud.authentication/HuaweiCloudSession`，Chromium OSCrypt
`v10` 密文，DPAPI 解主密钥后 AES-256-GCM 解出）：

1. `client_id = "codearts-agent"` 被服务端接受
   —— 它其实就是 product.json 的 urlProtocol（扩展里写的是
   `CLIENT_ID = vscode.env.uriScheme`）。refresh_token 载荷里明写着
   `"client_id": "codearts-agent"`。
2. DPoP 是强制的
   —— refresh_token 带 `cnf.jkt`（DPoP 公钥的 JWK thumbprint），
   服务端把 token 钉死在这把私钥上，换 token 必须用同一把私钥签 proof。
   错误码：`STS5.1804` 无效 DPoP 头、`STS5.1806` 无效 refresh token。
3. `accessToken` 是空串
   —— 这条链路最终拿到的不是 IAM token，而是 **STS 临时凭据三件套**
   （access_key_id / secret_access_key / security_token）+ 30 天 refresh_token。

## 一个反直觉的点

官方函数名叫 `generateDpopJWE`，但**它根本不是 JWE**：

    new SignJWT(payload)
      .setProtectedHeader({alg:"ES256", typ:"dpop+jwt", jwk: publicKeyJwk})
      .sign(key)

就是普通的 ES256 JWS 紧凑序列化。名字里的 JWE 是历史遗留，别被误导。

## 两条登录通道

- `new_iam_login`（推荐）：浏览器回跳 `127.0.0.1:{port}/oauth/callback?code=`
  → `POST {iamSts}/v1/oauth2/tokens`（带 DPoP）→ STS + 30 天 refresh_token。
- `old_login`（后备）：回调带回 `?secret=`，再轮询
  `GET {snapEngine}/v1/login/ticket?ticket_id=&secret=` → 只有 STS，无 refresh_token，
  到期必须重新走浏览器。只在 new_iam_login 拿不到时用。

## 与 WorkBuddy 插件的区别

WorkBuddy 那套是 `state + authUrl` 轮询、一次一个 state；码道这套是
**PKCE + DPoP + 本地回跳**。所以面板「添加账号」不能复用原来那条链路，
必须让 hub 自己起回调端点（hub 本身就是 HTTP 服务，天然能接）。
"""

import base64
import codecs
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import select
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import ca_env

# ---------------------------------------------------------------------------
# 环境常量（prod / cn-north-4）
# ---------------------------------------------------------------------------

PORTAL_HOST = "https://codearts.huaweicloud.com/portal"
SNAP_ENGINE = "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager"
IAM_STS = "https://sts.cn-north-4.myhuaweicloud.com"
IAM_LOGIN = "https://auth.huaweicloud.com/authui/login.html"

CLIENT_ID = "codearts-agent"
LOGIN_PLUGIN_NAME = "snap_AIIDE"
PLUGIN_VERSION = "5.4.2"

AUTH_REDIRECT_PATH = "/oauth/callback"
IAM_TOKEN_API = "/v1/oauth2/tokens"

# 官方轮询节奏，照抄

DEFAULT_TIMEOUT = 20.0

# 错误码 → 人话
ERROR_CODES = {
    "STS5.1804": "DPoP 头无效（签名错、密钥不匹配，或本机时钟偏差过大）",
    "STS5.1806": "refresh token 无效 / 已过期 / 已被使用过",
}


class CodeArtsError(Exception):
    """授权链路上的可预期失败。"""

    def __init__(self, message, code="", status=0, payload=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.payload = payload

    def __str__(self):
        head = f"[{self.code}] " if self.code else ""
        return f"{head}{self.message}"


# ---------------------------------------------------------------------------
# P-256（NIST secp256r1）—— 纯整数运算
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_INF = (0, 0, 0)


def _jac_double(pt):
    """a = -3 的倍点公式（dbl-2001-b）。"""
    x1, y1, z1 = pt
    if y1 == 0 or z1 == 0:
        return _INF
    delta = z1 * z1 % _P
    gamma = y1 * y1 % _P
    beta = x1 * gamma % _P
    alpha = 3 * (x1 - delta) * (x1 + delta) % _P
    x3 = (alpha * alpha - 8 * beta) % _P
    z3 = ((y1 + z1) * (y1 + z1) - gamma - delta) % _P
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % _P
    return (x3, y3, z3)


def _jac_add(left, right):
    """通用加法（add-2007-bl）。"""
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 == 0:
        return right
    if z2 == 0:
        return left
    z1z1 = z1 * z1 % _P
    z2z2 = z2 * z2 % _P
    u1 = x1 * z2z2 % _P
    u2 = x2 * z1z1 % _P
    s1 = y1 * z2 * z2z2 % _P
    s2 = y2 * z1 * z1z1 % _P
    if u1 == u2:
        if s1 != s2:
            return _INF
        return _jac_double(left)
    h = (u2 - u1) % _P
    i = 4 * h * h % _P
    j = h * i % _P
    r = 2 * (s2 - s1) % _P
    v = u1 * i % _P
    x3 = (r * r - j - 2 * v) % _P
    y3 = (r * (v - x3) - 2 * s1 * j) % _P
    z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) % _P * h % _P
    return (x3, y3, z3)


def _to_affine(pt):
    x, y, z = pt
    if z == 0:
        return None
    zinv = pow(z, -1, _P)
    zinv2 = zinv * zinv % _P
    return (x * zinv2 % _P, y * zinv2 * zinv % _P)


def _scalar_mul(k, point):
    """左到右二进制展开，point 为仿射坐标。"""
    if k % _N == 0 or point is None:
        return _INF
    acc = _INF
    addend = (point[0], point[1], 1)
    while k:
        if k & 1:
            acc = _jac_add(acc, addend)
        addend = _jac_double(addend)
        k >>= 1
    return acc


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    if isinstance(text, bytes):
        text = text.decode("ascii")
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _int_to_bytes32(value):
    return int(value).to_bytes(32, "big")


class EcKey:
    """P-256 密钥对。只支持 ES256 —— 华为 DPoP 只认这一种。"""

    ALG = "ES256"
    CURVE = "P-256"

    def __init__(self, d):
        self.d = int(d) % _N
        if self.d == 0:
            raise ValueError("私钥不能为 0")
        pub = _to_affine(_scalar_mul(self.d, (_GX, _GY)))
        if pub is None:
            raise ValueError("私钥非法：公钥落在无穷远点")
        self.x, self.y = pub
        # 自检：公钥必须真的在曲线上，否则后面签出来的东西服务端全拒
        if (self.y * self.y - (self.x ** 3 + _A * self.x + _B)) % _P != 0:
            raise ValueError("私钥非法：公钥不在 P-256 曲线上")

    # -- 导出 ---------------------------------------------------------------

    @property
    def public_jwk(self):
        # 字段顺序与官方导出保持一致，便于人眼对拍
        return {
            "kty": "EC",
            "crv": self.CURVE,
            "x": _b64u(_int_to_bytes32(self.x)),
            "y": _b64u(_int_to_bytes32(self.y)),
        }

    @property
    def private_jwk(self):
        jwk = {"kty": "EC", "x": _b64u(_int_to_bytes32(self.x)),
               "y": _b64u(_int_to_bytes32(self.y)), "crv": self.CURVE,
               "d": _b64u(_int_to_bytes32(self.d))}
        return jwk

    def thumbprint(self):
        """RFC 7638 JWK thumbprint，对应服务端 token 里的 cnf.jkt。"""
        canonical = json.dumps(
            {"crv": self.CURVE, "kty": "EC",
             "x": self.public_jwk["x"], "y": self.public_jwk["y"]},
            separators=(",", ":"), sort_keys=True,
        )
        return _b64u(hashlib.sha256(canonical.encode("ascii")).digest())

    # -- 签名 ---------------------------------------------------------------

    def sign(self, message, k=None):
        """ES256：ECDSA/SHA-256，输出 JOSE 要的 raw r||s（不是 DER）。"""
        digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
        while True:
            nonce = k if k is not None else secrets.randbelow(_N - 1) + 1
            point = _to_affine(_scalar_mul(nonce, (_GX, _GY)))
            if point is None:
                if k is not None:
                    raise ValueError("测试用的 k 退化成了无穷远点")
                continue
            r = point[0] % _N
            if r == 0:
                if k is not None:
                    raise ValueError("测试用的 k 让 r 为 0")
                continue
            s = pow(nonce, -1, _N) * (digest + r * self.d) % _N
            if s == 0:
                if k is not None:
                    raise ValueError("测试用的 k 让 s 为 0")
                continue
            # low-s：JOSE 不强制，但部分实现会拒高 s，统一压到低半区
            if s > _N // 2:
                s = _N - s
            return _int_to_bytes32(r) + _int_to_bytes32(s)


def generate_keypair():
    """等价于官方 generateDpopKeyPair，但内部直接持有私钥整数。"""
    while True:
        candidate = secrets.randbelow(_N - 1) + 1
        try:
            return EcKey(candidate)
        except ValueError:
            continue


def import_keypair(jwk):
    """从存档里的 privateKeyJwk 还原（刷新 token 时必须用同一把）。"""
    if not jwk:
        raise CodeArtsError("缺少 DPoP 私钥（loginContext.dpopKeyPair.privateKeyJwk）")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise CodeArtsError(f"不支持的 DPoP 私钥类型: {jwk.get('kty')}/{jwk.get('crv')}")
    raw_d = _b64u_decode(jwk["d"])
    return EcKey(int.from_bytes(raw_d, "big"))


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------

def generate_pkce():
    """S256 挑战。官方 codeChallengeMethod 固定写 "SHA-256"。"""
    verifier = _b64u(secrets.token_bytes(64))
    challenge = _b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return {
        "codeVerifier": verifier,
        "codeChallenge": challenge,
        "codeChallengeMethod": "SHA-256",
    }


# ---------------------------------------------------------------------------
# DPoP
# ---------------------------------------------------------------------------

def dpop_payload(method, url):
    return {
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
        "jti": secrets.token_hex(32),
    }


def dpop_proof(key, method, url, payload=None):
    """生成 DPoP proof（ES256 JWS 紧凑序列化）。

    官方把这里叫 generateDpopJWE，实际是 JWS。header 里必须带公钥 jwk，
    服务端用它算 thumbprint 去比对 refresh_token 的 cnf.jkt。
    """
    body = payload or dpop_payload(method, url)
    header = {"alg": key.ALG, "typ": "dpop+jwt", "jwk": key.public_jwk}
    signing_input = (
        _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + _b64u(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    )
    signature = key.sign(signing_input.encode("ascii"))
    return signing_input + "." + _b64u(signature)


# ---------------------------------------------------------------------------
# 登录编排
# ---------------------------------------------------------------------------

def new_ticket_id():
    """官方是 32 字节随机数的 hex（64 字符）。"""
    return secrets.token_hex(32)


def redirect_uri(port):
    return f"http://127.0.0.1:{int(port)}{AUTH_REDIRECT_PATH}"


def authorize_url(port, pkce, ticket_id, theme=1, locale="zh-cn",
                  plugin_version=PLUGIN_VERSION):
    """拼 portal 授权页地址。

    theme / locale 只是 UI，ticket_id / port / code_challenge 才是链路必需。
    hub 自己就是 HTTP 服务，所以 port 直接填 hub 的端口，浏览器会带着 code
    回跳到 hub 上。
    """
    query = {
        "theme": theme,
        "locale": locale,
        "uri_scheme": CLIENT_ID,
        "client_id": CLIENT_ID,
        "port": int(port),
        "code_challenge": pkce["codeChallenge"],
        "code_challenge_method": pkce["codeChallengeMethod"],
        "ticket_id": ticket_id,
        "plugin-name": LOGIN_PLUGIN_NAME,
        "plugin-version": plugin_version,
    }
    return f"{PORTAL_HOST}/authorize?" + urllib.parse.urlencode(query)


def _http(method, url, headers=None, body=None, timeout=DEFAULT_TIMEOUT,
          query=None):
    data = body.encode("utf-8") if isinstance(body, str) else body
    if query:
        # query 由调用方交给 aksk_sign 参与签名后，这里按同一排序拼回 URL ——
        # 两边顺序不一致就是一记 APIG.0301（签名对不上实际请求）。
        url = url + "?" + "&".join(
            "%s=%s" % (urllib.parse.quote(str(k), safe=""),
                       urllib.parse.quote(str(query[k]), safe=""))
            for k in sorted(query))
    req = urllib.request.Request(url, data=data, method=method.upper())
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        status = exc.code
    except urllib.error.URLError as exc:
        raise CodeArtsError(f"连接不上 {urllib.parse.urlsplit(url).netloc}：{exc.reason}") from exc
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        payload = {"_raw": text}
    code = str(payload.get("error_code") or "")
    # 码道有两种错误约定：换 token 那套只看 HTTP 状态码（成功时没有 error_code），
    # 业务接口（网关配置等）则是 HTTP 200 + error_code，"0000" 表示成功。
    if status >= 400 or (code and code != "0000"):
        hint = ERROR_CODES.get(code, "")
        message = payload.get("error_msg") or payload.get("message") or text[:200] or f"HTTP {status}"
        raise CodeArtsError(
            f"{message}{'（' + hint + '）' if hint else ''}",
            code=code, status=status, payload=payload,
        )
    return payload


def _token_request(key, form):
    """POST {iamSts}/v1/oauth2/tokens，DPoP 签名覆盖实际 URL。"""
    url = IAM_STS + IAM_TOKEN_API
    proof = dpop_proof(key, "POST", url)
    return _http(
        "POST", url,
        headers={
            "DPoP": proof,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=urllib.parse.urlencode(form),
    )


def exchange_code(key, code, pkce, port):
    """授权码换凭据。

    返回 {credentials:{access_key_id, secret_access_key, security_token,
    expiration}, refresh_token}。
    """
    return _token_request(key, {
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": pkce["codeVerifier"],
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri(port),
    })


def refresh(key, pkce, refresh_token):
    """刷新。注意官方也带 code_verifier —— 不是笔误，服务端会校验。"""
    return _token_request(key, {
        "client_id": CLIENT_ID,
        "code_verifier": pkce["codeVerifier"],
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })


# ---------------------------------------------------------------------------
# 结果归一
# ---------------------------------------------------------------------------

def parse_iso8601(text):
    """解析华为返回的 '2026-10-17T04:40:18.715Z'。返回 epoch 秒，失败给 None。"""
    if not text:
        return None
    value = str(text).strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        from datetime import datetime
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def user_from_refresh_token(refresh_token):
    """从 refresh_token 的内嵌 user_profile 直接读用户身分，省一次 HTTP。

    官方 tryToResolveUserInfoFromRefreshToken 就是这么做的。
    """
    try:
        part = str(refresh_token).split(".")[1]
        claims = json.loads(_b64u_decode(part))
        profile = claims.get("user_profile")
        if not profile:
            return {}
        return json.loads(_b64u_decode(profile))
    except Exception:
        return {}


def short_name(principal_urn):
    """'iam::xxx:user:hid_abc/agent' → 'hid_abc/agent' 或去掉斜杠前缀。"""
    text = str(principal_urn or "")
    tail = text[text.rfind(":") + 1:] if ":" in text else text
    if "/" in tail:
        tail = tail[tail.index("/") + 1:]
    return tail


def session_from_iam_response(response, key, pkce, portal_url=""):
    """把 new_iam_login 的响应整理成与官方存档同形的会话对象。

    字段名刻意保持驼峰（accessKey / secretKey / securitytoken / expires_at），
    这样能和 `%APPDATA%/codearts-agent` 里的真实存档直接对拍。
    """
    credentials = (response or {}).get("credentials") or {}
    refresh_token = (response or {}).get("refresh_token") or ""
    if not credentials.get("access_key_id"):
        raise CodeArtsError("换 token 成功但响应里没有 credentials", payload=response)

    profile = user_from_refresh_token(refresh_token)
    domain_id = profile.get("account_id") or ""
    label = short_name(profile.get("principal_urn") or "") or profile.get("account_name") or ""
    user_id = profile.get("principal_id") or profile.get("principal_ii") or ""

    return {
        "id": "huawei-cloud-authentication",
        "account": {"id": user_id, "label": label},
        "scopes": [],
        "accessToken": "",
        "accessKey": credentials.get("access_key_id"),
        "secretKey": credentials.get("secret_access_key"),
        "securitytoken": credentials.get("security_token"),
        "expires_at": credentials.get("expiration"),
        "domainId": domain_id,
        "refresh_token": refresh_token,
        "loginContext": {
            "pkcePair": pkce,
            "dpopKeyPair": {
                "privateKeyJwk": key.private_jwk,
                "publicKeyJwk": key.public_jwk,
            },
        },
        "portal": portal_url,
    }


def summarize(session, now=None):
    """给人看的摘要，面板上直接显示。"""
    now = now if now is not None else time.time()
    expires = parse_iso8601(session.get("expires_at"))
    remain = None if expires is None else int(expires - now)
    refresh_claims = {}
    token = session.get("refresh_token") or ""
    if token.count(".") == 2:
        try:
            refresh_claims = json.loads(_b64u_decode(token.split(".")[1]))
        except Exception:
            refresh_claims = {}
    return {
        "account": (session.get("account") or {}).get("label") or "",
        "account_id": (session.get("account") or {}).get("id") or "",
        "domain_id": session.get("domainId") or "",
        "access_key": (session.get("accessKey") or "")[:8] + "…"
                      if session.get("accessKey") else "",
        "expires_at": session.get("expires_at") or "",
        "sts_remaining_seconds": remain,
        "sts_expired": None if remain is None else remain <= 0,
        "refresh_expires_at": refresh_claims.get("exp"),
        "renewable": bool(token),
        "mode": "new_iam_login" if token else "old_login",
    }


# ---------------------------------------------------------------------------
# 对话网关：模型清单与推理入口
# ---------------------------------------------------------------------------
#
# 与登录链路是两码事。登录只用了 DPoP；这里要的是**华为云 AK/SK 请求签名**
# （SDK-HMAC-SHA256，ROA 那套），因为码道所有业务接口都走 APIG 网关、只认签名。
#
# 权威模型表不是「内置模型」那个接口，而是网关配置：
#   GET https://opengw.developer.huaweicloud.com/api/v1/gateway/config
#   → {"error_code":"0000","result":{"base_url":".../v2","models":[{model_id,
#      model_name, context_window, max_tokens, sort}, ...]}}
# 它同时给出**推理入口**和**这账号能用的对话模型**，比 PromptCenter 的
# /v1/model/builtin 权威 —— 后者是 IDE 聊天用的目录（GLM-5.2 / Qwen3-VL /
# 盘古那批），两者不是一回事。

# 出站身份：真正发出去的只有 User-Agent（内核的 OPENCODE_SERVICE_NAME 默认
# CodeAgent3.0、tracing 层名 Kernel），照抄以免被网关按客户端特征拦。
GATEWAY_USER_AGENT = "CodeAgent3.0-Kernel"


def _local_client_ip():
    """本机 IP（client-ip 头用，官方传的是局域网 IP，纯遥测）。

    UDP connect 探针不发任何包，只让内核选默认路由的源地址 —— 比
    gethostbyname(hostname) 靠谱（后者在云主机上常解析成 127.0.1.1）。
    """
    import socket
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

SIGN_ALGORITHM = "SDK-HMAC-SHA256"
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# 官方 noEscape 表：只有字母数字与 - . _ 不转义
_UNRESERVED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._")


def url_encode(text):
    out = []
    for byte in str(text).encode("utf-8"):
        ch = chr(byte)
        out.append(ch if ch in _UNRESERVED else "%%%02X" % byte)
    return "".join(out)


def canonical_uri(path):
    """分段编码后用 / 连接，**末尾补一个斜杠**。

    补斜杠是官方 AKSKSigner 的行为，漏掉它签名就对不上——踩过一次，报的是
    「verify ak sk signature fail」而不是更具体的错。
    """
    uri = "/".join(url_encode(part) for part in path.split("/"))
    return uri if uri.endswith("/") else uri + "/"


def aksk_sign(access_key, secret_key, method, url, query=None, headers=None,
              payload_hash=None):
    """给请求补上 Authorization / X-Sdk-Date / Host。

    逐条对齐官方 AKSKSigner：头名小写排序后用 ; 拼成 SignedHeaders，canonical
    headers 的值做 ``.trim()``（官方 signer 原文如此），并且**实际发送的头也用
    裁过的值** —— 签名覆盖的是服务端收到的字节，两边不一致就是 401。
    （2026-10-24 更正：以前这里不裁空白，靠的是我们自己构造的头恰好没有首尾
    空白；哪个头哪天带进空白就是一记 ``APIG.0301``。）
    query 取自 query_params 而不是 url 里的原始顺序。
    """
    if not access_key or not secret_key:
        raise CodeArtsError("缺少 AK/SK，无法给业务接口签名")
    parts = urllib.parse.urlsplit(url)
    netloc = parts.hostname or ""
    if parts.port and not ((parts.scheme == "https" and parts.port == 443)
                           or (parts.scheme == "http" and parts.port == 80)):
        netloc = "%s:%d" % (netloc, parts.port)

    now = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    merged = {str(k): str(v).strip()
              for k, v in dict(headers or {}).items()}
    merged["X-Sdk-Date"] = now
    merged["Host"] = netloc

    names = sorted(merged, key=lambda k: k.lower())
    signed_headers = ";".join(names).lower()
    canonical_headers = "".join("%s:%s\n" % (k.lower(), merged[k]) for k in names)
    query = query or {}
    canonical_query = "&".join("%s=%s" % (url_encode(k), url_encode(query[k]))
                               for k in sorted(query))
    canonical = "\n".join([method.upper(), canonical_uri(parts.path),
                           canonical_query, canonical_headers,
                           signed_headers, payload_hash or EMPTY_BODY_SHA256])
    string_to_sign = "\n".join([
        SIGN_ALGORITHM, now,
        base64.b16encode(hashlib.sha256(canonical.encode("utf-8")).digest())
        .decode("ascii").lower()])
    signature = hmac.new(secret_key.encode("utf-8"),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    signed = dict(merged)
    signed["Authorization"] = "%s Access=%s, SignedHeaders=%s, Signature=%s" % (
        SIGN_ALGORITHM, access_key, signed_headers, signature)
    return signed


# ---------------------------------------------------------------------------
# 推理入口（实测确认）
# ---------------------------------------------------------------------------
#
# 扩展里拼的是 `${agentChatDomain}/api/v2/`，而 agentChatDomain 在 prod 下
# 就是 snap-engine 那台主机。曾经的「权益网关」opengw（免费额度 / claim /
# gateway-config）已由官方下线，这里不再有第二套基址。
#
# 实测（AK/SK 签名 + X-Security-Token，2026-10-17）：
#   POST {CHAT_BASE}chat/completions  model=deepseek-v4.1-flash → 429 TPM 超限
#   同一个请求换另外三个模型名 → 404 InferHub.002002009「model is not registered」
# 429 而不是 401，说明签名与令牌都被接受、请求确实打到了模型服务；被卡住的是
# 账号自己的 TPM 配额，不是协议。
#
# 更正过一次结论：早期只探了权益网关那 4 个名字，判成「只有 deepseek-v4.1-flash
# 可路由」。**这个结论只对那一组成立**。后来补探 PromptCenter 的内置分组，7 个里
# 6 个真能跑（GLM-5.2 回了真实文本、多模态 Qwen3-VL-235B 能真的读图），只有
# `glm-5.3` 稳定 400 且响应体为空 —— 它与限时福利的 `glm-5.3-flash` 是两个东西。

CHAT_HOST = "https://snap-access.cn-north-4.myhuaweicloud.com"
CHAT_BASE = CHAT_HOST + "/api/v2/"
CHAT_PATH = CHAT_BASE + "chat/completions"

# 实测可路由的推理模型名。这份是**验证过**的：逐个打推理入口，6 个内置 + 4 个
# 限时福利里只有 glm-5.3 是死的（400 空响应体）。早期只探过限时福利那组的 4 个，
# 当时把另外 3 个判成「服务端不认」—— 那个结论只对那一组成立，内置那组整体可路由。
#: 可推理模型（逐个实测过）。**只收内置目录里的**：限时福利渠道已由官方
#: 下线（2026-10-23 实测 opengw /api/v1/gateway/config 回
#: ``[4000] invalid channel, group not found``），原来那 4 个福利模型里
#: ``deepseek-v4-flash-0731`` / ``glm-5.3-flash`` / ``deepseek-v4-pro-0813``
#: 两条通道都打不通（不带 maas_type 是 002002009 未注册，带上就是 4004.200），
#: 已从名单移除；``deepseek-v4.1-flash`` 上游已内置化，照常保留。
CHAT_MODELS = ("deepseek-v4.1-flash",
               "glm-5.3",
               "GLM-5.2", "Qwen3-VL-235B", "kimi-k2.6-vl",
               "openpangu-2.0-flash", "openpangu-2.0-pro",
               "glm-5.2-sft-harmony",
               # 2026-10-23 补：上游内置目录新出现，且 `display_enabled=true`
               # （官方 IDE 的模型选择器里能看到）。实测推理入口 200 正常出字。
               # 不加这一条的后果很隐蔽 —— 清单里没有它，请求会被判成「不是
               # 码道模型」掉进 WorkBuddy 池，只配了码道账号的部署回
               # 503 no usable account，报错和模型名毫无关系。
               "kimi-k3")


# ---------------------------------------------------------------------------
# 模型清单：只有内置一组
# ---------------------------------------------------------------------------
#
# 2026-10-23 起清单只来自 PromptCenter ``/v1/model/builtin``。曾经的第二组
# 「限时福利」走权益网关 ``/api/v1/gateway/config``，官方已把它下线 —— 该接口
# 现在直接回 ``[4000] invalid channel, group not found``，那几个福利模型里除了
# 已内置化的 ``deepseek-v4.1-flash``，其余两条通道都打不通。
#
# 内置这一组一度被判成「IDE 聊天目录、不是网关推理目录」而排除，那是错的：
# 实测内置模型在推理入口**全部真的能跑通**（GLM-5.2 返回真实回复、多模态
# Qwen3-VL-235B 能真的读图）。``glm-5.3`` 曾因「400 且响应体为空」被误判死，
# 实际是它只收 ``stream=true``（见 chat_body）。
#
# 一条容易踩的口径：`model_id` 与 `model_name` 不一致。界面显示的是 **model_name**
# （如 glm-5.2-sft-harmony 显示成「GLM-5.2-ArkTS-SPARK」），而请求要发的是
# **model_id**。归一时两者都要留。

#: 推理的读超时。DEFAULT_TIMEOUT(20s) 对**目录类**接口够用，对推理不够：
#: 实测 GLM-5.2 单次回答要 17 秒以上，从远端机房打过去更慢，20 秒会稳定超时。
#: 推理是「等它把话说完」，不是「探测对方在不在」，所以给足。
#: 可用 CODEARTS_CHAT_TIMEOUT 环境变量覆盖。
CHAT_TIMEOUT = ca_env.number("CODEARTS_CHAT_TIMEOUT", 180.0, minimum=1.0)

BUILTIN_MODELS_PATH = "/v1/model/builtin"

#: 体验版积分的真实来源（客户端「总已用积分 4,817 / 11,500」那一栏）。
#:
#: 2026-10-21 从本机 CodeArts Agent 逆向取得：扩展里的 getTstatisticsPluginUrl()
#: 拼的是 {chatDomain}/snap-manager/v1/statistics/plugin，chatDomain 在公有云是
#: https://snap-access.cn-north-4.myhuaweicloud.com。它**不在** opengw 的
#: benefit 接口上 —— 那边只有每日 token 额度（benefit/claim/balance）。
#: 鉴权仍是 AK/SK 签名 + X-Security-Token，与其它 snap-access 接口一致。
CREDIT_PACKAGE_PATH = "/snap-manager/v1/statistics/plugin"

#: PromptCenter 所在的主机，与推理入口同一台（agentChatDomain 在 prod 下就是它）
SNAP_HOST = CHAT_HOST

#: 推理入口实测不可路由的内置模型。目前是空的 —— 清单里 7 个内置模型全部可用。
#: 留着这个集合是为了以后真出现不通的模型时有地方标；「routable」字段的语义
#: 也依赖它，面板按它决定是否显示「推理不可达」。
#:
#: 别急着往里加：曾经把 glm-5.3 放进来过，理由是「连续两次 400 且响应体为空」。
#: 那是误判 —— glm-5.3 只收 stream=true，非流式才回 400 空响应体（见
#: chat_body）。**把某个模型加进来之前，先用流式形态复测一遍。**
#: 内置模型的真实上下文/输出上限（2026-10-21 从本机 CodeArts Agent 实测取得）。
#:
#: `/v1/model/builtin` 不返回这两个值，网关原来一律兜底成 1,000,000 —— 对
#: glm-5.2-sft-harmony 这类仍是 202,752 的模型等于**高估 5 倍**，客户端会
#: 以为塞得进更长的上下文。这里存一份实测值，`normalize_builtin` 在上游
#: 没给值时用它。
#:
#: 来源：GET /v1/agent-center/agents/useragents → agents[].agent_id →
#:       GET /v1/agent-center/agents/detail?agent_id=… → gpts.models[].model_parameters
#:       （需要 X-Security-Token 头，STS 凭证必须带）。
#: 2026-10-21 15:46 本机客户端日志 `【AgentCore model-config update】` 复核：
#: GLM-5.2 / glm-5.3 已从 202,752 提升到 1,048,576 上下文（输入 1,044,480），
#: 输出均为 65,536；glm-5.2-sft-harmony 仍为 202,752 / 131,072。
#: Qwen3-VL-235B 取自同行的公开缓存（AgentCenter 里没列出它）；kimi 暂无实测值。
BUILTIN_MODEL_LIMITS = {
    "GLM-5.2": (1048576, 65536),
    "glm-5.2-sft-harmony": (202752, 131072),
    "glm-5.3": (1048576, 65536),
    "openpangu-2.0-pro": (524288, 131072),
    "openpangu-2.0-flash": (524288, 131072),
    "Qwen3-VL-235B": (1048576, 131072),
    # 2026-10-21 从本机客户端配置里取到的真值（原先没有这一条，显示成 1M 占位）
    "deepseek-v4.1-flash": (1048576, 65536),
    # 2026-10-23 实测（线上账号，逐个 max_tokens 打推理入口）：
    #   65536 → 200 正常出字；81920 / 100000 / 131072 / 262144 → 全部
    #   `InferHub.001001005.400 The request param is invalid`。
    # 所以输出上限就是 65536，和 GLM-5.2 / glm-5.3 一致。
    # 输入窗口**上游不返回**（`/v1/model/builtin` 没有这一项，远端目录也没给），
    # 按本文件的口径留 0 —— 不拿同厂兄弟的 1M 顶替，那是在编数字。
    "kimi-k3": (1044480, 65536),
}

#: kimi-k3 的输入窗口 2026-10-23 之前写 0（上游不返回）。真值来自本机官方
#: kernel 日志 ``provider models replace body``（2026-10-23）：input=1044480、
#: context=1048576、output=65536 —— 与 GLM-5.2 / glm-5.3 / deepseek-v4.1-flash
#: 同一套 1M 窗口。

#: 官方客户端**实际发送**的输出上限（kernel 日志 requestBodyValues 实证：
#: glm-5.3 每轮都带 ``max_tokens:32000``，而目录能力值是 65536）。客户端要
#: 更大的值时向下钳：官方的请求形状就是上游调度最顺的形状，「按能力值顶满」
#: 的请求只会拉长上游排队。只钳有实证的模型，没有的原样放行。
#: 2026-10-24 再补一条：同一份 kernel 日志 27 条请求体里，openpangu-2.0-pro
#: 也一律 ``"32000"`` —— 连 50 字的起标题小任务都不例外。
MODEL_OUTPUT_CAPS = {
    "glm-5.3": 32000,
    "openpangu-2.0-pro": 32000,
}


def cap_output_tokens(model, max_tokens):
    """按官方口径把输出上限**双向**钳到固定值；没有实证值的模型原样放行。

    只向下钳不够（2026-10-24 网关实测踩坑）：思考模型的推理和正文共用
    ``max_tokens`` 额度，客户端发小值（400-6000）时思考能把额度整个吃光
    —— 上游照常 200，usage 里 completion_tokens 恰好等于 max_tokens，
    正文一个字没有，客户端还照付思考的积分。官方客户端不存在这类「空
    回答」，靠的就是**预算恒定**：任何请求（含起标题这种小任务）一律
    32000，思考随便吃，正文永远有余量。双向钳 = 完整镜像官方形状。
    """
    cap = MODEL_OUTPUT_CAPS.get(str(model or ""))
    if not cap or not isinstance(max_tokens, int):
        return max_tokens
    return cap

#: 内置模型的缺省采样参数 (temperature, top_p)。
#:
#: `/v1/model/builtin` 不返回这两个值，AgentCenter 的
#: `gpts.models[].model_parameters` 才有。2026-10-22 用线上账号实测拉取：
#:   · GLM-5.2 / glm-5.2-sft-harmony / glm-5.3 / deepseek-v4.1-flash
#:     → temperature 0.5、top_p 0
#:   · openpangu-2.0-flash / openpangu-2.0-pro → temperature 1.0、top_p 0
#: 这些是**请求不带采样参数时上游生效的默认值**，只做展示，不改写客户端请求。
#:
#: Qwen3-VL-235B / kimi-k2.6-vl 不在 AgentCenter 清单里（上游
#: display_enabled=false），没有实测值 —— 不填，面板显示「—」，
#: 不拿同厂别的模型顶替。
BUILTIN_MODEL_SAMPLING = {
    "GLM-5.2": (0.5, 0.0),
    "glm-5.2-sft-harmony": (0.5, 0.0),
    "glm-5.3": (0.5, 0.0),
    "deepseek-v4.1-flash": (0.5, 0.0),
    "openpangu-2.0-flash": (1.0, 0.0),
    "openpangu-2.0-pro": (1.0, 0.0),
}

BUILTIN_UNROUTABLE = set()

#: 模型分组。福利（限时福利渠道）已由官方下线，只剩内置一组 —— 留着这个
#: 常量是因为清单条目、面板与测试都按 ``group`` 字段渲染/断言。
GROUP_BUILTIN = "builtin"
MODEL_GROUPS = (GROUP_BUILTIN,)


def _model_index():
    """大小写无关的模型名索引：``lower()`` → 上游真名。

    两张表都收：可推理名单（CHAT_MODELS）、实测上限表。真实名字以先出现的
    为准 —— 两张表的键本来就一致，``setdefault`` 只是防以后有人只改一张表时
    把名字改出两个写法。
    """
    index = {}
    for name in CHAT_MODELS:
        index.setdefault(str(name).lower(), name)
    for table in (BUILTIN_MODEL_LIMITS,):
        for name in table:
            index.setdefault(str(name).lower(), name)
    return index


_MODEL_INDEX = None


def resolve_model(model_id):
    """把客户端写的模型名解析成**上游真名**（大小写无关）。

    为什么必须做（2026-10-22 线上实测）：上游的模型 id 大小写是混的 ——
    ``GLM-5.2`` 全大写、``glm-5.3`` 全小写、``Qwen3-VL-235B`` 混合，而客户端
    习惯一律写小写。原样接收会在三个地方同时出错，且**都不报「模型名不对」**：

      1. 分流判错（最严重）：``is_codearts_model("glm-5.2")`` 为假，请求掉进
         WorkBuddy 账号池；那个池在这个部署里是空的，于是回
         ``503 no usable account`` —— 一个和模型名毫无关系的
         报错，用户根本看不出是自己把大写写成了小写。
      2. ``max_tokens`` 夹不住：``BUILTIN_MODEL_LIMITS`` 查不到 → 客户端发
         128000 原样上去 → ``InferHub.001001005.400``，这条路还会被当成
         不可重试的参数错。

    认不出来的名字原样返回：宁可交给上游拒绝（它会给准确错误），也不在这里
    编一个近似名把请求打到别的模型上。
    """
    text = str(model_id or "").strip()
    if not text:
        return text
    global _MODEL_INDEX
    if _MODEL_INDEX is None:
        _MODEL_INDEX = _model_index()
    return _MODEL_INDEX.get(text.lower(), text)


def clamp_max_tokens(model_id, max_tokens):
    """把 max_tokens 夹到模型真实输出上限，返回 (值, 是否被夹过)。

    **为什么必须夹（2026-10-21 线上实测）**：客户端（ZCode / CodeArts IDE、
    Codex CLI 等）习惯性发一个「模型族里最大的那个」值 —— ZCode 对所有模型
    固定发 `max_tokens=128000`。上游对超限值不回「值太大」这种明白错误，而是
    `InferHub.001001005.400 The request param is invalid`，一句话把整个请求
    打死，且这个码**不在** `ca_stream.retryable` 里，所以重试多少次都是同样的
    502，用户侧表现为「这个模型一直失败」。

    实测 glm-5.3：`65536`（正好等于输出上限）200 正常出字，`128000` 立刻
    001001005.400。**65536 是模型能力，不该往下砍** —— 砍了等于替用户决定
    「你不需要那么长的文档」，正常的长输出会被硬截断，比报错更糟。

    表里没有的模型不夹 —— 宁可原样发过去让上游自己判断，也不要用一个
    猜的数把本来能过的请求改坏。
    """
    limit = (BUILTIN_MODEL_LIMITS.get(resolve_model(model_id))
             or (None, None))[1]
    if not limit:
        return max_tokens, False
    try:
        value = int(max_tokens)
    except (TypeError, ValueError):
        return limit, False
    if value > limit:
        return limit, True
    return value, False

#: UI 的两分组，与客户端侧一致。


def builtin_models(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """内置模型目录（只读）。返回服务端 builtinModels 原样。

    X-Security-Token 必须**在签名前**就放进请求头：令牌参与签名，
    「先签一次、补上令牌、再重签」会把第一次产出的 Authorization / Host /
    X-Sdk-Date 也一起签进去，服务端回 APIG.0301。
    """
    url = SNAP_HOST + BUILTIN_MODELS_PATH
    headers = {
        "Agent-Type": "PromptCenter",
        "X-Language": "zh-cn",
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    headers = aksk_sign(access_key, secret_key, "GET", url, {}, headers)
    payload = _http("GET", url, headers=headers, timeout=timeout)
    return payload.get("builtinModels") or []


def credit_package(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """体验版积分配额：已用 / 总量 / 剩余 / 各分项。

    就是客户端「总已用积分 x / y」那一栏的同一个接口（见 CREDIT_PACKAGE_PATH）。
    服务端返回 ``metrics`` 列表，其中 ``usageTotalPackageCredit`` 是总量那一条，
    另外还有 basic（基础包）/ bonus（赠送包）/ on-demand 三个分项。
    """
    url = SNAP_HOST + CREDIT_PACKAGE_PATH
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    headers = aksk_sign(access_key, secret_key, "GET", url, {}, headers)
    payload = _http("GET", url, headers=headers, timeout=timeout)

    metrics = {}
    for item in payload.get("metrics") or []:
        if isinstance(item, dict) and item.get("name"):
            metrics[item["name"]] = item
    total = metrics.get("usageTotalPackageCredit") or {}
    amount = total.get("package_credit_amount")
    if amount is None:
        return None
    used = total.get("package_credit_used") or 0
    remain = total.get("package_credit_remain")
    if remain is None:
        remain = amount - used
    package = payload.get("package") or {}

    def part(name):
        m = metrics.get(name) or {}
        if m.get("package_credit_amount") is None:
            return None
        return {"used": m.get("package_credit_used"),
                "total": m.get("package_credit_amount"),
                "remaining": m.get("package_credit_remain")}

    # usageTokenChatMessages：套餐 token 用量的主指标（官方 fetchSubscriptionInfo
    # 用它算「>80% / ≥100%」告警）。字段名与 credit 那组不同：usage_token_num /
    # package_token_amount。show=False 表示账号没有 token 包（值为 -1），不返回。
    tokens = metrics.get("usageTokenChatMessages") or {}
    token_usage = None
    if tokens.get("show") and tokens.get("usage_token_num") is not None:
        token_usage = {"used": tokens.get("usage_token_num"),
                       "amount": tokens.get("package_token_amount"),
                       "show": True}
    return {
        "used": used,
        "total": amount,
        "remaining": remain,
        "percent": round(used / amount * 100, 2) if amount else None,
        "package_name": (package.get("package_name_cn")
                         or package.get("package_name_en") or ""),
        "package_type": package.get("spec_code") or "",
        "status": package.get("status") or "",
        "start_date": payload.get("start_date"),
        "end_date": payload.get("end_date"),
        "basic": part("usageBasicPackageCredit"),
        "bonus": part("usageBonusPackageCredit"),
        "ondemand": part("usageOnDemandPackageCredit"),
        "token_usage": token_usage,
    }


def _credit_tier(raw):
    """挑出该模型适用的计费档，返回 (倍率文案, 输入价, 输出价)。

    ``credit`` 是**按 token 数分段**的列表（如 openpangu-2.0-pro 有 0–32000 与
    32001–两档）。面板只要一个代表值，取第一档 —— 服务端按实际用量选档，网关
    这里不做逐段计价。列表为空（免费 / 未定价）返回 (None, None, None)。
    """
    tiers = raw.get("credit") or []
    if not isinstance(tiers, list) or not tiers:
        return None, None, None
    tier = tiers[0] or {}
    return (tier.get("ratio_display") or None,
            tier.get("input_price") or None,
            tier.get("output_price") or None)


def _credit_tier_raw(raw):
    """完整计费档：ratio / ratio_display / 三档单价，外加**按输入长度分段**的原始列表。

    这些是算积分要用的原始字段。2026-10-21 从本机 CodeArts Agent 的
    extension.js 里逆向出计费公式（``pj.calculateTurnCredits``）：

        credits = (input_price*(input-cache) + cache_price*cache
                   + output_price*output) / 1e6 / ratio

    注意是**除以** ratio（倍率），不是乘以 —— ratio 越小，同样 token 扣得越多。
    同一个方法里的 ``matchCreditInterval`` 才是选档逻辑：``credit`` 是**按输入
    token 数分段**的列表，服务端拿实际 input 落在哪一段就用哪一段的三个单价。
    实测 openpangu-2.0-pro 就有 0–32000 与 32001–∞ 两段（3.2/4.8 元每百万输入），
    所以这里必须把整段列表带出去，只在展示时取第一段。

    拿不到档位（免费 / 未定价，如 Qwen3-VL、kimi-k2.6-vl 的 ``credit`` 为空）
    返回 None —— 不编倍率，也不假装免费。
    """
    tiers = raw.get("credit") or []
    if not isinstance(tiers, list) or not tiers:
        return None

    def num(value):
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0.0

    rows = []
    for item in tiers:
        item = item or {}
        ratio = num(item.get("ratio"))
        if ratio <= 0:
            continue
        rows.append({
            "input_from": int(num(item.get("input_from"))),
            # -1 是「无上限」的哨兵值，原样留着，判档时再翻译
            "input_to": int(num(item.get("input_to"))),
            "ratio": ratio,
            "ratio_display": item.get("ratio_display") or "",
            "input_price": num(item.get("input_price")),
            "cache_price": num(item.get("cache_price")),
            "output_price": num(item.get("output_price")),
            # 错峰档："off_peak"；普通档是 null 或 "default"。
            # 同一 model 会同时给出 default 与 off_peak，两段 input 区间完全
            # 相同 —— 只按 token 数选档永远命中第一段（deepseek 实测如此）。
            "time_slot_id": item.get("time_slot_id") or "",
        })
    if not rows:
        return None
    head = rows[0]
    return {
        "ratio": head["ratio"],
        "ratio_display": head["ratio_display"],
        "input_price": head["input_price"],
        "cache_price": head["cache_price"],
        "output_price": head["output_price"],
        # 完整分段（判档用）
        "tiers": rows,
        # 时段定义（timezone/schedule/duration/notice），错峰判档用
        "time_slots": raw.get("time_slots") or {},
    }


#: 模型 → 计费档。模型目录每次刷新时填，record_usage 算积分时查。
CREDIT_TIERS = {}

#: 计费档的**静态兜底**。`CREDIT_TIERS` 是进程内的运行时状态，只在有人请求
#: 模型清单（`/v1/models` 或面板拉目录）时才被 `normalize_builtin` 填。
#: 这带来一个隐蔽的时序依赖：**服务刚重启、还没人拉过模型目录时，所有请求的
#: 积分都会算成 0**（`credit_for_usage` 查不到档位返回 None，记录里就留着 0）。
#: 2026-10-22 实测复现：重启后 19:37 那批请求 credit 全是 0；手动打一次
#: `/v1/models` 之后再发请求，credit 立刻变成 0.0428。
#:
#: 所以把 2026-10-21 从上游 `/v1/model/builtin` 实测到的几档固化在这里，
#: 查不到运行时档位时回落到它 —— 计费不该取决于「有没有人先访问过目录」。
#:
#: 数值来源：`GET /v1/model/builtin` 的 `credit[]`（与客户端 UI 的倍率一致）。
#: Qwen3-VL-235B / kimi-k2.6-vl 的 `credit` 是空数组（上游没定价），
#: 刻意不放进表里 —— 编一个倍率比显示「未定价」更糟。
CREDIT_TIERS_STATIC = {
    "GLM-5.2": {
        "ratio": 0.05, "ratio_display": "0.7x",
        "tiers": [{"input_from": 0, "input_to": -1, "ratio": 0.05,
                   "ratio_display": "0.7x",
                   "input_price": 8.0, "cache_price": 2.0, "output_price": 28.0}],
    },
    "glm-5.2-sft-harmony": {
        "ratio": 0.05, "ratio_display": "0.7x",
        "tiers": [{"input_from": 0, "input_to": -1, "ratio": 0.05,
                   "ratio_display": "0.7x",
                   "input_price": 8.0, "cache_price": 2.0, "output_price": 28.0}],
    },
    "glm-5.3": {
        "ratio": 0.0443, "ratio_display": "0.79x",
        "tiers": [{"input_from": 0, "input_to": -1, "ratio": 0.0443,
                   "ratio_display": "0.79x",
                   "input_price": 8.0, "cache_price": 2.0, "output_price": 28.0}],
    },
    # deepseek 有两档**按时间**而不是按长度：default 0.18x，off_peak 0.09x。
    # 上游把两段写成相同的 input 区间，只按 token 数选档会永远命中第一段 ——
    # 夜间那 11 小时会被算成双倍积分。time_slots 的 schedule 是
    # Quartz 六段式（秒 分 时 …），21:00 起持续 11 小时 → 21:00–07:59。
    "deepseek-v4.1-flash": {
        "ratio": 0.05, "ratio_display": "0.18x",
        # 顶层的三个单价要与 tiers[0] 一致：credit_pricing_view 用它换算
        # 「入 40 · 出 160 积分/M」，缺了会显示成 0。
        "input_price": 2.0, "cache_price": 0.2, "output_price": 8.0,
        "tiers": [
            {"input_from": 0, "input_to": -1, "ratio": 0.05,
             "ratio_display": "0.18x", "time_slot_id": "default",
             "input_price": 2.0, "cache_price": 0.2, "output_price": 8.0},
            {"input_from": 0, "input_to": -1, "ratio": 0.05,
             "ratio_display": "0.09x", "time_slot_id": "off_peak",
             "input_price": 1.0, "cache_price": 0.1, "output_price": 4.0},
        ],
        "time_slots": {"off_peak": {
            "timezone": "Asia/Shanghai",
            "schedule": "0 0 21 * * *",
            "duration": 11,
            "timeunit": "hour",
            "notice": {"zh_cn": "错峰时段5折优惠，积分消耗速度从0.18x降至0.09x"
                                "（每晚21:00-次日7:59）"},
        }},
    },
    "openpangu-2.0-flash": {
        "ratio": 0.011, "ratio_display": "0.32x",
        "tiers": [{"input_from": 0, "input_to": -1, "ratio": 0.011,
                   "ratio_display": "0.32x",
                   "input_price": 0.8, "cache_price": 0.2, "output_price": 1.6}],
    },
    # 实测两段：32K 以内 3.2/0.8/14.5，以上 4.8/1.2/17.6。只取第一段会把
    # 长输入的账少算 50%（客户端 matchCreditInterval 也是分段取的）。
    "openpangu-2.0-pro": {
        "ratio": 0.028, "ratio_display": "0.7x",
        "tiers": [
            {"input_from": 0, "input_to": 32000, "ratio": 0.028,
             "ratio_display": "0.7x",
             "input_price": 3.2, "cache_price": 0.8, "output_price": 14.5},
            {"input_from": 32001, "input_to": -1, "ratio": 0.028,
             "ratio_display": "0.7x",
             "input_price": 4.8, "cache_price": 1.2, "output_price": 17.6},
        ],
    },
}


def credit_tier_for(model):
    """取一个模型的计费档：先查运行时（上游最新值），再回落静态兜底。

    运行时优先是刻意的 —— 上游调价时 `/v1/model/builtin` 会给出新倍率，
    静态表只是「还没拉到目录时」的兜底，不应该盖过真值。
    """
    tier = CREDIT_TIERS.get(model)
    if tier:
        return tier
    return CREDIT_TIERS_STATIC.get(model)

#: 模型 → 可选的思考档位（逆向后确认：值直接当 reasoning_effort 用）。
#: 2026-10-21 实测：GLM-5.2 / glm-5.2-sft-harmony 给 ["high","max"]，
#: 其余内置模型返回空数组（没有可调档位）。
THINKING_STRENGTHS = {}

THINKING_VARIANTS_PATH = "/v1/model/thinking-variants"


AGENT_CENTER_USERAGENTS_PATH = "/v1/agent-center/agents/useragents"
AGENT_CENTER_DETAIL_PATH = "/v1/agent-center/agents/detail"


def agent_center_agents(access_key, secret_key, security_token,
                        timeout=DEFAULT_TIMEOUT):
    """AgentCenter：当前账号可用的 agent 清单（含 agent_id）。

    逆自 kernel 的 agent-center 模块：GET {snap}/v1/agent-center/agents/
    useragents?offset=0&limit=100，头必须带 ``Agent-Type: AgentCenter`` +
    ``X-Language`` + ``plugin-version``；**query 必须进签名**（传给
    ``aksk_sign`` 的 query 参数，不是拼进 URL）—— 否则 APIG.0301
    ``verify ak sk signature fail``（2026-10-24 线上实测，docs 里也记过这个坑）。
    """
    query = {"offset": "0", "limit": "100"}
    url = SNAP_HOST + AGENT_CENTER_USERAGENTS_PATH
    headers = {
        "Agent-Type": "AgentCenter",
        "X-Language": "zh-cn",
        "Content-Type": "application/json",
        "plugin-version": "26.10.0",
        "User-Agent": GATEWAY_USER_AGENT,
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    headers = aksk_sign(access_key, secret_key, "GET", url, query, headers)
    return _http("GET", url, headers=headers, timeout=timeout,
                 query=query)


def agent_center_agent_detail(access_key, secret_key, security_token,
                              agent_id, timeout=DEFAULT_TIMEOUT):
    """AgentCenter：单个 agent 的详情（``gpts.models[]`` 是模型真值来源）。

    同一签名口径；``agent_id`` 来自 :func:`agent_center_agents`。
    """
    query = {"agent_id": str(agent_id)}
    url = SNAP_HOST + AGENT_CENTER_DETAIL_PATH
    headers = {
        "Agent-Type": "AgentCenter",
        "X-Language": "zh-cn",
        "Content-Type": "application/json",
        "plugin-version": "26.10.0",
        "User-Agent": GATEWAY_USER_AGENT,
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    headers = aksk_sign(access_key, secret_key, "GET", url, query, headers)
    return _http("GET", url, headers=headers, timeout=timeout,
                 query=query)


def thinking_variants(access_key, secret_key, security_token, model_names,
                      timeout=DEFAULT_TIMEOUT):
    """每个模型能选哪些思考档位。

    逆向自本机客户端 kernel 的 fetchThinkingVariants：
      POST {xcenter}/v1/model/thinking-variants  body {"model_names": [...]}
      → data.variants[model].strengths / default_strength
    strengths 里的字符串就是请求里的 ``reasoning_effort``（客户端 mB() 直接
    拼成 {reasoningEffort: 值}）。必须带 Agent-Type: PromptCenter。
    """
    url = SNAP_HOST + THINKING_VARIANTS_PATH
    headers = {
        "Content-Type": "application/json",
        "Agent-Type": "PromptCenter",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    body = json.dumps({"model_names": list(model_names)[:50]},
                      ensure_ascii=False).encode("utf-8")
    headers = aksk_sign(access_key, secret_key, "POST", url, {}, headers,
                        payload_hash=hashlib.sha256(body).hexdigest())
    payload = _http("POST", url, headers=headers, body=body, timeout=timeout)
    variants = payload.get("variants") or {}
    out = {}
    for name, info in variants.items():
        if not isinstance(info, dict):
            continue
        strengths = [str(x) for x in (info.get("strengths") or []) if x]
        out[name] = {"strengths": strengths,
                     "default": info.get("default_strength") or ""}


#: 各模型的思考档位白名单：``reasoning_effort`` 只允许取列表里的值。
#:
#: 种子抄自本机官方客户端的档位缓存（``state.vscdb →
#: hc-thinking-variants-cache-key``，2026-10-23）。关键的一条：**glm-5.3 的
#: strengths 是空的** —— 官方对它永远不发 ``reasoning_effort``（kernel 日志
#: ``reasoningEffort=undefined``），UI 上连档位选择器都不出现。我们以前把
#: 客户端发来的 effort=max 原样转发，上游深度思考几十秒不吐首字节，正好撞进
#: APIG 的 ~60s 空闲上限（2026-10-23 线上同一请求连断四次就是这么来的）。
#: 上游档位表会覆盖种子（TTL 见 ``THINKING_STRENGTHS_TTL``，拉取失败沿用
#: 种子）；两头都没有的模型返回 None = 不约束，维持「客户端给什么发什么」。
THINKING_STRENGTHS_SEED = {
    "glm-5.2": ("high", "max"),
    "glm-5.3": (),
    "glm-5.3-flash": ("low", "high", "max"),
    "openpangu-2.0-pro": (),
    "kimi-k3": (),
    "deepseek-v4.1-flash": (),
}

#: 档位表的缓存时长（秒）。官方客户端缓存 24h；1h 足够跟上上游改配置。
THINKING_STRENGTHS_TTL = 3600.0

_THINKING_STRENGTHS_LOCK = threading.Lock()
_THINKING_STRENGTHS = {}      # model -> (expires_at, strengths 元组或 None)


def refresh_thinking_strengths(access_key, secret_key, security_token,
                               model, timeout=8.0):
    """查一个模型的思考档位白名单：tuple（可为空）或 None（未知）。

    带 TTL 缓存；上游拉取失败时回落到种子表 —— 种子来自官方客户端本地缓存，
    比「查不到就照发 effort」安全：官方自己就不给这些模型开档位。
    """
    model = str(model or "")
    now = time.time()
    with _THINKING_STRENGTHS_LOCK:
        hit = _THINKING_STRENGTHS.get(model)
        if hit and hit[0] > now:
            return hit[1]
    resolved = None
    try:
        info = thinking_variants(access_key, secret_key, security_token,
                                 [model], timeout=timeout).get(model)
        if info is not None:
            resolved = tuple(str(x) for x in (info.get("strengths") or []))
    except Exception:                      # noqa: BLE001 —— 网络失败回落种子
        resolved = None
    if resolved is None:
        resolved = THINKING_STRENGTHS_SEED.get(model)
    with _THINKING_STRENGTHS_LOCK:
        _THINKING_STRENGTHS[model] = (now + THINKING_STRENGTHS_TTL, resolved)
    return resolved


#: 模型真值的 AgentCenter 刷新：种子（BUILTIN_MODEL_LIMITS 手表）→ 活数据。
#: ``gpts.models[].model_parameters`` 里有 context_window / input_length /
#: max_tokens / truncate_length / enable_queue / temperature 等全套字段
#: （2026-10-24 线上实测）。成功后**直接写回 BUILTIN_MODEL_LIMITS** ——
#: resolve_model 的大小写归一和 _codearts_max_tokens / prune 的查表全都
#: 自动受益，调用点一行不用改。失败（网络/鉴权/形状不对）保留旧值。
MODEL_LIMITS_TTL = 3600.0
_MODEL_LIMITS_REFRESHED_AT = [0.0]

#: 模型选模真值（官方 model-selector 用）：flagship/fallback 标签与场景。
#: 来自 agent-center ``gpts.models[].model_parameters.custom_config.tags``
#: （逗号分隔字符串）与 ``scenario``。官方选模就是「先 tags 含 flagship 的，
#: 再 fallback 的」——这份元数据随 refresh_model_limits 一起刷。
_MODEL_META = {}


def model_truth_meta(model_id):
    """模型的官方选模元数据（tags/scenario）；没拉到返回空 dict。"""
    m = _MODEL_META.get(str(model_id or ""))
    return dict(m) if m else {}


def refresh_model_limits(access_key, secret_key, security_token,
                         timeout=15.0):
    """从 AgentCenter 拉模型真值并写回 BUILTIN_MODEL_LIMITS（TTL 1h）。

    挑 agent：名字叫 ``CodeAgent`` 的第一个（官方默认），否则清单第一个。
    每条 ``model_parameters`` 只要 input_length / max_tokens 都能读出数字
    就收录 —— 上游哪天上新模型，网关不用等手表更新。
    """
    now = time.time()
    if now - _MODEL_LIMITS_REFRESHED_AT[0] < MODEL_LIMITS_TTL:
        return
    try:
        agents = agent_center_agents(access_key, secret_key, security_token,
                                     timeout=timeout) or {}
        listing = agents.get("agents") or []
        agent_id = next((a.get("agent_id") for a in listing
                         if isinstance(a, dict)
                         and str(a.get("agent_name") or "") == "CodeAgent"
                         and a.get("agent_id")),
                        listing[0].get("agent_id") if listing else None)
        if not agent_id:
            return
        detail = agent_center_agent_detail(access_key, secret_key,
                                           security_token, agent_id,
                                           timeout=timeout) or {}
        models = ((detail.get("gpts") or {}).get("models")) or []
        fresh = 0
        for item in models:
            mp = (item or {}).get("model_parameters") or {}
            mid = str(mp.get("model_id") or "").strip()
            try:
                inp = int(mp.get("input_length") or 0)
                out = int(mp.get("max_tokens") or 0)
            except (TypeError, ValueError):
                continue
            tags_raw = ((mp.get("custom_config") or {}).get("tags"))
            tags = ([t.strip() for t in str(tags_raw).split(",")
                     if t.strip()] if tags_raw else [])
            if mid:
                _MODEL_META[mid] = {"tags": tags,
                                    "scenario": str(mp.get("scenario") or "")}
            if mid and inp > 0 and out > 0:
                BUILTIN_MODEL_LIMITS[mid] = (inp, out)
                fresh += 1
        if fresh:
            _MODEL_LIMITS_REFRESHED_AT[0] = now
            # resolve_model 的大小写索引是模块级缓存，表变了不重建的话，
            # 新收录的模型永远走不到归一（查表/钳制全部 miss）。
            global _MODEL_INDEX
            _MODEL_INDEX = None
            _qlog("model limits refreshed from AgentCenter: %d models" % fresh)
    except Exception:                      # noqa: BLE001 —— 刷新失败保留旧值
        pass


def thinking_strengths_for(model):
    """只读缓存/种子的档位白名单，不发起网络请求；None = 未知。"""
    model = str(model or "")
    now = time.time()
    with _THINKING_STRENGTHS_LOCK:
        hit = _THINKING_STRENGTHS.get(model)
        if hit and hit[0] > now:
            return hit[1]
    return THINKING_STRENGTHS_SEED.get(model)
    return out


def _time_slot_active(slot, when):
    """``when``（epoch 秒）是否落在 slot 的 schedule + duration 窗口内。

    schedule 是 Quartz 六段式（秒 分 时 日 月 周），只解析前三个字段；
    日/月/周非 ``*`` 的规则判不准，宁可返回 False（按原价）也不要在错误的
    时间段打折。时区只认 Asia/Shanghai（固定 UTC+8，无夏令时）——
    上游当前只有这一种，遇到别的时区同样按不生效处理。
    """
    if not isinstance(slot, dict):
        return False
    fields = str(slot.get("schedule") or "").split()
    if len(fields) < 3:
        return False
    try:
        second, minute, hour = int(fields[0]), int(fields[1]), int(fields[2])
        duration = float(slot.get("duration") or 0)
    except (TypeError, ValueError):
        return False
    if duration <= 0:
        return False
    if str(slot.get("timezone") or "") not in ("", "Asia/Shanghai"):
        return False
    unit = str(slot.get("timeunit") or "hour").lower()
    seconds = duration * (60 if unit == "minute" else 3600)
    start = hour * 3600 + minute * 60 + second
    end = start + int(seconds)
    clock = time.gmtime(float(when) + 8 * 3600)
    now = clock.tm_hour * 3600 + clock.tm_min * 60 + clock.tm_sec
    if end <= 86400:
        return start <= now < end
    # 跨午夜：21:00 + 11h = 次日 08:00 → [21:00, 24:00) ∪ [00:00, 08:00)
    return now >= start or now < (end - 86400)


def _rows_for_time(tier, when):
    """挑出 ``when`` 时刻适用的计费行。

    有生效的错峰时段就只用该时段的行；否则用 default / 无时段标记的行。
    时段行和默认行的 input 区间可能完全相同（deepseek），所以必须先按
    时段过滤，再按 token 选段。
    """
    rows = (tier or {}).get("tiers") or []
    slots = (tier or {}).get("time_slots") or {}
    active = ""
    for slot_id, slot in slots.items():
        if slot_id == "default":
            continue
        if when is not None and _time_slot_active(slot, when):
            active = slot_id
            break
    if active:
        chosen = [r for r in rows if (r.get("time_slot_id") or "") == active]
        if chosen:
            return chosen
    base = [r for r in rows if (r.get("time_slot_id") or "") in ("", "default")]
    return base or rows


def _pick_credit_tier(tier, prompt_tokens, when=None):
    """按输入 token 数与时刻挑计费段。

    ``input_to`` 为 -1 表示该段无上限。落在任何段之外（理论上不会发生）时
    退回第一段，而不是返回 0 —— 返回 0 会让这条请求在面板上看起来免费。
    ``when`` 为 epoch 秒；None 表示「不看时段，取默认档」，供纯分段测试用。
    """
    rows = _rows_for_time(tier, when)
    if not rows:
        return tier or {}
    n = max(0, int(prompt_tokens or 0))
    for row in rows:
        low = row.get("input_from") or 0
        high = row.get("input_to")
        if high is None or high < 0:
            if n >= low:
                return row
        elif low <= n <= high:
            return row
    return rows[0]


def credit_for_usage(model, prompt_tokens, cached_tokens, completion_tokens,
                     when=None):
    """按逆向出来的公式算一条请求的积分。拿不到该模型的档位时返回 None。

    公式与取整口径都照抄客户端：``calculateTurnCredits`` 内部
    ``Math.round(d*100)/100``，也就是**面板上看到的两位小数**。这里保留 4 位
    （累加多条时不丢精度），显示时再按两位取整，与客户端逐条对得上。

    ``when`` 是计费时刻（epoch 秒），默认取当前时间。deepseek 的错峰档
    （21:00–07:59 Asia/Shanghai）价格减半，必须按请求完成时刻选档，
    否则夜间账目会比上游实际扣费高一倍。

    实测校准（2026-10-21，GLM-5.2，ratio 0.05 / 8·2·28 元每百万）：
    短请求 ≈ 0.02、中 ≈ 0.15、长 ≈ 0.51 积分 —— 与客户端「总已用积分」的
    增量一致，说明公式与 ratio 方向（除以，不是乘以）都取对了。
    """
    tier = credit_tier_for(model)
    if not tier:
        return None
    prompt = max(0, int(prompt_tokens or 0))
    cached = min(max(0, int(cached_tokens or 0)), prompt)
    output = max(0, int(completion_tokens or 0))
    row = _pick_credit_tier(tier, prompt,
                            time.time() if when is None else when)
    ratio = float(row.get("ratio") or 0)
    if ratio <= 0:
        return None
    cost = (float(row.get("input_price") or 0) * (prompt - cached)
            + float(row.get("cache_price") or 0) * cached
            + float(row.get("output_price") or 0) * output)
    return round(cost / 1e6 / ratio, 4)


def credit_pricing_view(tier):
    """计费档 → 对外可读的计费规则（每 100 万 token 扣多少积分）。

    面板/API 里光有「0.7x」说明不了花多少积分：真正要乘的是三个单价再除了
    ratio。这里把换算结果直接算出来，谁都能一眼对上账：

        credits_per_mtok_input = input_price / ratio
        credits_per_mtok_output = output_price / ratio
    """
    if not tier:
        return None
    ratio = float(tier.get("ratio") or 0)
    if ratio <= 0:
        return None

    def per_mtok(price):
        return round(float(price or 0) / ratio, 4)

    view = {
        "ratio": ratio,
        "ratio_display": tier.get("ratio_display") or "",
        "input_price": tier.get("input_price"),
        "cache_price": tier.get("cache_price"),
        "output_price": tier.get("output_price"),
        "currency": "CNY",
        "price_unit_tokens": 1000000,
        "credits_per_mtok_input": per_mtok(tier.get("input_price")),
        "credits_per_mtok_cache": per_mtok(tier.get("cache_price")),
        "credits_per_mtok_output": per_mtok(tier.get("output_price")),
        "formula": ("credits = (input_price*(input-cache) + cache_price*cache"
                    " + output_price*output) / 1e6 / ratio"),
        "source": "CodeArts Agent 客户端 calculateTurnCredits（逆向）",
    }
    rows = tier.get("tiers") or []
    # 分段数组只装「默认时段里按输入长度分的段」。错峰档的 input 区间和
    # 默认档一模一样，混进来会变成两行完全相同的区间（2026-10-22 实测
    # deepseek 就是这样），读的人只会以为数据重复了。
    base_rows = [r for r in rows
                 if (r.get("time_slot_id") or "") in ("", "default")]
    if len(base_rows) > 1:
        # 只有真的分段计价的模型（如 openpangu-2.0-pro 的 32K 分界）才带，
        # 单段的模型多给一份数组只是噪音。
        view["tiers"] = [{
            "input_from": row.get("input_from"),
            "input_to": row.get("input_to"),
            "credits_per_mtok_input": per_mtok(row.get("input_price")),
            "credits_per_mtok_cache": per_mtok(row.get("cache_price")),
            "credits_per_mtok_output": per_mtok(row.get("output_price")),
        } for row in base_rows]
    slots = tier.get("time_slots") or {}
    if slots:
        view["time_slots"] = {}
        for slot_id, slot in slots.items():
            if slot_id == "default" or not isinstance(slot, dict):
                continue
            entry = {}
            for key in ("timezone", "schedule", "duration", "timeunit"):
                if slot.get(key) is not None:
                    entry[key] = slot[key]
            notice = slot.get("notice")
            if isinstance(notice, dict) and notice.get("zh_cn"):
                entry["notice"] = notice["zh_cn"]
            match = next((r for r in rows
                          if (r.get("time_slot_id") or "") == slot_id), None)
            if match:
                # 按时段自己的 ratio 换算：错峰档的 ratio 不一定和默认档一样，
                # 用外层的 per_mtok 会把倍率串过去。
                row_ratio = float(match.get("ratio") or 0) or ratio
                entry["ratio_display"] = match.get("ratio_display") or ""
                entry["credits_per_mtok_input"] = round(
                    float(match.get("input_price") or 0) / row_ratio, 4)
                entry["credits_per_mtok_output"] = round(
                    float(match.get("output_price") or 0) / row_ratio, 4)
            view["time_slots"][slot_id] = entry
    return view


def normalize_builtin(raw_list):
    """内置模型 → 网关内部统一的模型对象形状。

    福利渠道下线后这是**唯一**的清单来源，条目带真实的能力标签与计费信息：
    ``supportsImages`` 取服务端的 ``supports_images``（实测多模态那三个确实能读图），
    计费倍率原样带出，供面板显示 0.7x 之类。
    """
    out = []
    for raw in raw_list or []:
        mid = str(raw.get("model_id") or "").strip()
        if not mid:
            continue
        ratio, in_price, out_price = _credit_tier(raw)
        raw_tier = _credit_tier_raw(raw)
        if raw_tier:
            CREDIT_TIERS[mid] = raw_tier
        item = {
            "id": mid,
            # 界面展示用 model_name：它和 model_id 常常不一样
            "name": str(raw.get("model_name") or mid),
            "group": GROUP_BUILTIN,
            "category": raw.get("model_category") or "",
            "description": raw.get("model_desc") or "",
            "provider": raw.get("provider") or "",
            "supportsImages": bool(raw.get("supports_images")),
            # 推理入口实测打不通的模型仍列出但标记出来，排查时能一眼看到
            "routable": mid not in BUILTIN_UNROUTABLE,
            "creditRatio": ratio,
            "inputPrice": in_price,
            "outputPrice": out_price,
            # 计费档原值（含 ratio 与 cache_price），算积分用
            "creditTier": raw_tier,
            # 人话版计费规则：每 100 万 token 扣多少积分
            "creditPricing": credit_pricing_view(raw_tier),
            # 服务端不返回上下文窗口；用实测表兜底，查不到的留 0（不编数字）。
            "maxInputTokens": BUILTIN_MODEL_LIMITS.get(mid, (0, 0))[0],
            "maxOutputTokens": BUILTIN_MODEL_LIMITS.get(mid, (0, 0))[1],
            "supportsReasoning": True,
            "supportsToolCall": True,
        }
        sample = BUILTIN_MODEL_SAMPLING.get(mid)
        if sample:
            item["temperature"], item["top_p"] = sample
        out.append(item)
    return out


def model_catalog(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """码道模型清单（只有内置一组）。

    限时福利渠道（opengw ``/api/v1/gateway/config``）已由官方下线 —— 2026-10-23
    实测该接口直接回 ``[4000] invalid channel, group not found``，福利那 4 个
    模型里 3 个两条通道都不通、``deepseek-v4.1-flash`` 已内置化。所以清单只
    可能来自 ``/v1/model/builtin``，不再有「两组合并」这回事。

    取数失败不让整份清单失败：回空清单 + ``errors``，面板据此说明原因。
    """
    models = []
    errors = {}
    try:
        models = normalize_builtin(
            builtin_models(access_key, secret_key, security_token, timeout=timeout))
    except Exception as exc:
        errors[GROUP_BUILTIN] = str(exc)

    # 思考档位：另开一个接口问「每个模型能选哪几档」，拿到了就贴到模型上。
    # 失败不影响清单本身（档位是可选功能），但要记进 errors —— 否则面板上
    # 所有模型都显示「原生」，看不出是「本来没有档位」还是「这次没问到」。
    if models:
        try:
            variants = thinking_variants(
                access_key, secret_key, security_token,
                # 这个接口认的是 model_name（客户端也是发展示名）。发 model_id
                # 时上游对不上号，两者不同的模型连档位都问不到。
                [item.get("name") or item["id"] for item in models],
                timeout=timeout)
            # 上游返回的键是 **model_name**（如 "GLM-5.2-ArkTS-SPARK"），不是
            # model_id（glm-5.2-sft-harmony）。只按 id 查会让两者不一致的模型
            # 丢掉真实档位 —— 面板上那个模型会错误地显示「原生」。
            by_id = {item["id"]: item for item in models}
            by_name = {item.get("name"): item for item in models}
            matched = {}
            for key, info in variants.items():
                item = by_id.get(key) or by_name.get(key)
                if item:
                    matched[item["id"]] = info
            THINKING_STRENGTHS.clear()
            THINKING_STRENGTHS.update(matched)
            for item in models:
                info = matched.get(item["id"]) or {}
                item["thinkingStrengths"] = info.get("strengths") or []
                item["thinkingDefault"] = info.get("default") or ""
        except Exception as exc:
            errors["thinking"] = str(exc)

    return {"models": models, "groups": {GROUP_BUILTIN: models}, "errors": errors}


def chat_headers(access_key, secret_key, security_token, payload_hash,
                 stream=False, model=None, session_id=None, session_retry=None,
                 msg_id=None):
    """推理请求头：与网关配置同一套签名，只是多一个 Accept。

    **不再有 ``maas_type``**：那是限时福利渠道的分组开关，官方已下线
    （2026-10-23 实测 opengw ``/api/v1/gateway/config`` 回
    ``[4000] invalid channel, group not found``）。以前福利组必须带
    ``maas_type: benefit``，现在带上去只会换回
    ``InferHub.4004.200 benefit not found`` —— ``deepseek-v4.1-flash``
    已经内置化，和 glm-5.3 一样不带这个头。

    ``session_id``：会话名额的句柄（见 ``heartbeat``）。**必须参与签名** ——
    上游按签名覆盖的头集合校验，改了头不重签会直接 401。带上它，这次推理才
    会计入我们已 busy 的那条会话，收尾的 idle 才能真正归还名额。

    客户端还带一套 x-ot-* 观测头（trace/span 等），实测**不带也通**，这里就
    不复制了 —— 复制只会让签名串更长、排障更难。

    下面这一族是官方 opencode 路径真发的（2026-10-24 逆向 ``chat.headers``
    钩子 + doStream 合并点；HC 白名单路径会把它们滤掉，但网关对齐的就是
    opencode/Bearer 形态，那一条是全量合并）：

      · ``x-session-affinity`` = 会话 id（同一会话每轮稳定，新会话才换）——
        上游网关按它做会话粘性路由，同会话命中同一后端实例的 prompt cache；
      · ``user-msg-id`` / ``x-message-id`` = 本轮用户消息 id（同一用户回合内
        稳定，官方一个回合内的子代理调用共享同一个值；重试也复用）；
      · ``created-time`` = 每次请求的 ISO8601 UTC 秒级时间戳；
      · ``model-id`` / ``model-name``（name 做 URL 编码）。
    """
    headers = {
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
        "Accept": "text/event-stream" if stream else "application/json",
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    if session_id:
        headers["user-session-id"] = session_id
        # 会话粘性路由（官方 x-session-affinity = sessionID；普通会话与
        # user-session-id 同值，agent-team 子会话才分叉 —— 网关没有子会话）。
        headers["x-session-affinity"] = session_id
    if msg_id:
        # 官方两头同值：user-msg-id 与 x-message-id 都是「本轮用户消息 id」。
        headers["user-msg-id"] = msg_id
        headers["x-message-id"] = msg_id
    headers["created-time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                            time.gmtime())
    if model:
        headers["model-id"] = str(model)
        headers["model-name"] = urllib.parse.quote(str(model), safe="")
    # 官方 HC 白名单路径的头（2026-10-24 对照官方 kernel 日志 header-debug）：
    # APIG 可能按 plugin/ide 身份区分请求待遇 —— 我们此前一个都不带，上游
    # 眼里是个「不明客户端」。值照抄官方（plugin-version/ide-version 26.10.1）。
    headers["plugin-name"] = "codemate_vscode"
    headers["plugin-version"] = "26.10.1"
    headers["ide-name"] = "VSCode"
    headers["ide-version"] = "26.10.1"
    headers["X-Language"] = "zh-cn"
    headers["client-ip"] = _local_client_ip()
    if session_retry is not None:
        # 官方重试协议：第 N 次尝试带 N，服务端据此调度/限流（x-session-retry
        # <10 才肯重试 BusyException）。首次尝试是 0。
        headers["x-session-retry"] = str(int(session_retry))
    if QUEUE_ENABLED:
        # 官方两个头一起设：声明参与服务端排队。不带它们时 429 是硬失败，
        # 带了才可能收到 queue-status: queued（见 open_chat 的排队重发）。
        headers["app-id"] = "CodeAgent3.0"
        headers["is-need-queue"] = "true"
    return aksk_sign(access_key, secret_key, "POST", CHAT_PATH, {}, headers,
                     payload_hash=payload_hash)


#: 会话名额心跳。上游的并发闸**不认「请求结束」**，只认这条心跳的 busy/idle：
#: 每个账号 3 路并发，对话前 busy 登记一个自造的 32 位十六进制 user-session-id
#: （对话请求带同一个头），对话结束 idle 注销。
#:
#: 不做这套的后果（2026-10-22 线上实测）：客户端连接早就关了，上游那边的会话
#: 还挂着，连着快发两三个请求就把 3 个名额占满，之后一律
#: `TM.00001041 并发会话数已达上限(3个)`，而我们的退避重试等的是「别人释放」，
#: 上游只肯按超时回收。同一批日志里还夹着 21 次 `IncompleteRead` —— 会话被
#: 服务端回收时直接掐 TCP，就是我们看到的「断流」。
HEARTBEAT_PATH = "/snap-manager/v1/chat-session/heartbeat"


def new_session_id():
    """自造 32 位十六进制会话 id（对齐官方客户端 UUIDv4 去连字符的形状）。

    绝不复用别人的 id：idle 是**注销**语义，拿官方 IDE 的 id 去 idle 会把用户
    正在用的那条对话踢掉。
    """
    return secrets.token_hex(16)


def heartbeat(access_key, secret_key, security_token, session_id, status,
              timeout=10):
    """登记 / 注销一条上游会话名额。返回 ``(ok, detail)``，**不抛**。

    ``status`` 只能是 busy / idle，且必须走 **query**。实测三种摆法：
      · ``PUT  ?status=busy`` + body ``{}``  → 200 ``{"status":"ok"}``（唯一可用）
      · ``PUT`` 把 status 放 body            → 400 ``TM.00001001 参数校验失败:
                                                wsf.validator.session.status``
      · ``POST`` / ``GET`` 同一个路径        → 404 ``APIG.0101 method not found``

    ok 的判定是 **200 且 body 里 status == "ok"**，只看状态码不够：网关层 200
    可以包着业务失败，当真会让槽位从没登记过、我们却以为限流解除了。
    """
    if not (access_key and secret_key and session_id):
        return False, "missing credentials"
    status = "idle" if str(status).lower() == "idle" else "busy"
    url = SNAP_HOST + HEARTBEAT_PATH
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-language": "zh-cn",
        "x-client-type": "kernel",
        "user-session-id": session_id,
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    body = b"{}"
    try:
        signed = aksk_sign(access_key, secret_key, "PUT", url,
                           {"status": status}, headers,
                           payload_hash=hashlib.sha256(body).hexdigest())
        req = urllib.request.Request(url + "?status=" + status, data=body,
                                     headers=signed, method="PUT")
        resp = urllib.request.urlopen(req, timeout=timeout)
        raw = resp.read(2048)
        resp.close()
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(512).decode("utf-8", "replace")
        except Exception:                        # noqa: BLE001
            detail = ""
        return False, "HTTP %s %s" % (exc.code, detail[:200])
    except Exception as exc:                     # noqa: BLE001
        return False, "%s: %s" % (type(exc).__name__, exc)
    try:
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
    except Exception:                            # noqa: BLE001
        payload = {}
    if isinstance(payload, dict) and payload.get("status") == "ok":
        return True, "ok"
    return False, "unconfirmed: %s" % raw[:160]


def normalize_tools(tools):
    """把工具声明统一成**码道上游认的 Chat 包裹形状**。

    两套上游对 tools 的摆法不一样，这是实测出来的差异，别混：

      WorkBuddy  收扁平的：{"type":"function","name":"x","description":…}
                 原样透传即可（见 ca_proxy._tools_for_chat 的契约测试）
      码道       只认包裹的：{"type":"function","function":{"name":"x",…}}
                 少了这层包裹就回
                 `InferHub.001001015.400 Tool function cannot empty` ——
                 上游按 tool["function"] 取名字，取到空就直接拒掉整个请求，
                 现象是「一挂工具就 502，不挂工具就正常」。

    已经是包裹形状的原样放过：重复包一层会变成
    {"function":{"function":{…}}}，上游同样认不出。
    """
    out = []
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        if isinstance(tool.get("function"), dict):
            out.append(tool)
            continue
        kind = str(tool.get("type") or "function").lower()
        if kind == "function" and tool.get("name"):
            fn = {}
            for key in ("name", "description", "parameters", "strict"):
                if tool.get(key) is not None:
                    fn[key] = tool[key]
            out.append({"type": "function", "function": fn})
            continue
        # custom / web_search 这类码道没有执行器的声明直接丢掉：
        # 发过去只会换一个 400，不如让模型按「没有这个工具」去回答。
        continue
    return out


def last_user_prompt_text(messages, limit=2000):
    """从消息列表倒着找最近一条**有正文**的用户消息，返回其纯文本。

    官方请求体顶层带 ``user_prompt``（当前用户原话，2026-10-24 kernel 日志
    27 条请求体全部如此，起标题/记忆抽取这类客户端自产请求也不例外）。
    上游拿它做什么没有公开文档；网关能给的最近似值就是消息里最后一条
    用户正文 —— tool_result 块不算正文，跳过继续往前找。

    ``limit``：官方未观察到截断，但贴码型 prompt 可能有几十 KB，往一个
    元数据字段里灌全文不妥，2000 字符封顶。
    """
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        text = ""
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "".join(
                str(part.get("text") or "") for part in content
                if isinstance(part, dict) and part.get("type") == "text")
        text = text.strip()
        if text:
            return text[:limit]
    return ""


def chat_body(model, messages, max_tokens=256, stream=True, extra=None,
              tools=None, tool_choice=None):
    """推理请求体。

    **stream 默认 True，这不是随便定的。** `glm-5.3` 只收流式：传
    ``stream=false`` 服务端回 **400 且响应体为空**，看起来像「模型不存在」，
    实际上换 ``stream=true`` 立刻 200 并正常吐出内容。客户端一直走流式，
    所以人用着没问题；按 OpenAI 习惯默认非流式的探针会误判它已死。

    **tools 必须透传（2026-10-21 实测）**：上游原生支持 function calling，
    带 tools 时回标准 `delta.tool_calls` + `finish_reason="tool_calls"`。
    早先这里只组 model/messages/max_tokens/stream，tools 整个被丢掉 ——
    IDE 客户端（ZCode 一次就发 39 个工具）于是完全不知道有哪些工具可用，
    只能自己把调用写成 `<tool_call>…</tool_call>` **纯文本**发回来，
    客户端解析不了，用户看到的是「模型在胡言乱语地编工具调用」。
    """
    body = {"model": model, "messages": messages,
            "max_tokens": clamp_max_tokens(model, max_tokens)[0],
            "stream": stream}
    # 思考开关（thinking / reasoning_effort）由调用方按客户端要求放进 extra。
    # 上游认这两个字段：实测 thinking.type=disabled 时 reasoning_tokens 恒为 0，
    # enabled + budget_tokens 能给出非零推理量（11 个模型全部如此）。
    if extra:
        body.update(extra)
    if tools:
        shaped = normalize_tools(tools)
        if shaped:
            body["tools"] = shaped
            # 官方带 tools 时无条件发 ``tool_choice:"auto"``（2026-10-24
            # kernel 日志 27 条请求体全部如此）。客户端显式给了 none /
            # required / 具名函数时仍尊重客户端，只在缺省时补 auto。
            if not tool_choice:
                tool_choice = "auto"
            body["tool_choice"] = tool_choice
            # 官方对 inferhub 供应商无条件开（chat params 钩子
            # ``u.options.tool_stream = !0``，2026-10-24 kernel 日志实证请求体
            # 里带 ``"tool_stream":true``）：上游据此流式下发工具调用增量。
            # 我们本来就消费 delta.tool_calls，声明它让行为与官方完全一致。
            body["tool_stream"] = True
    return body


def thinking_extra_from(payload, effort_allowed=None):
    """客户端请求 → 上游思考参数。没有可用项时返回 None（沿用上游默认）。

    **重要更正（2026-10-20 实测）**：上游**不接受关掉思考**。
    `thinking={"type":"disabled"}` 会回 `InferHub.ModelArts.81001.400 参数有误`，
    而且是以 HTTP 200 + SSE 错误帧的形式返回的 —— 早期探针把这种空响应当成
    「推理 0 token」，误判成「可以关」，实际是请求失败。

    所以这里只透传「打开 + 预算」这一类真的能用的参数，关思考的请求被丢弃
    （思考保持默认开启），避免把客户端默认发出的 disabled 变成 502。

    ``effort_allowed``：该模型的思考档位白名单（官方档位表，见
    ``refresh_thinking_strengths``）。``None`` = 未知，沿用旧行为原样转发；
    tuple（可以为空）= 白名单，之外的 effort 一律不发 —— 官方对档位表为空的
    模型（glm-5.3）永远不发 effort，深思考 60s 静默就是 effort=max 引出来的。
    """
    if not isinstance(payload, dict):
        return None
    extra = {}
    thinking = payload.get("thinking")
    effort = payload.get("reasoning_effort") or payload.get("reasoningEffort")

    if isinstance(thinking, dict):
        kind = str(thinking.get("type") or "").strip().lower()
        if kind == "enabled":
            # budget_tokens 原样带上：它是上限，实测 11 个模型都接受
            extra["thinking"] = dict(thinking)
        elif kind:
            extra["thinking"] = None      # disabled 之类的，下面统一剔除
    elif isinstance(thinking, str) and thinking.strip().lower() == "enabled":
        extra["thinking"] = {"type": "enabled"}

    if effort is not None:
        effort = str(effort).strip().lower()
        if effort and effort != "none":
            # 白名单之外的 effort 不发（None = 未知，维持转发）。effort 被丢
            # 时思考保持上游默认 —— 官方的请求形状就是这个。
            if effort_allowed is not None and effort not in effort_allowed:
                effort = None
        if effort and effort != "none":
            extra.setdefault("thinking", {"type": "enabled"})
            extra["reasoning_effort"] = effort

    # 上游不收「关思考」：剔掉，而不是发过去换一个 502
    if extra.get("thinking") is None:
        extra.pop("thinking", None)
    return extra or None


#: 上游认、我们也该转发的采样参数。2026-10-22 逐个实测过：故意给非法值
#: （temperature="abc"、top_p=9、seed="abc"），上游都回帧内 001001005 ——
#: 说明它真的解析并校验这些字段，而不是当未知键忽略。
SAMPLING_FIELDS = ("temperature", "top_p", "seed",
                   "presence_penalty", "frequency_penalty")


def sampling_extra_from(payload):
    """客户端请求 → 上游采样参数。没有可用项时返回 None。

    为什么需要它：码道路径以前只转发 model/messages/max_tokens/stream/
    thinking/tools/tool_choice，其余字段全丢。后果是 ``temperature=0`` 不生效
    （代码类任务的重复性没法保证），而 Anthropic 的 ``stop_sequences`` 在翻译层
    明明已经转成了 chat 的 ``stop``，到这一层又被吞掉 —— 客户端以为停了，
    实际还在生成。

    ``stop`` 单独处理：实测上游**只收数组**（``stop="END"`` 回 001001005），
    所以字符串要包成单元素列表。OpenAI 的语义上限是 4 条，多出来的我们裁掉
    —— 但**不再悄悄裁**：以前静默丢弃，客户端传 6 条时会以为全生效，实际
    只有前 4 条（2026-10-23）。裁掉的部分由 ``stop_dropped`` 带出去，调用方
    记一行日志。
    """
    if not isinstance(payload, dict):
        return None
    extra = {}
    for key in SAMPLING_FIELDS:
        if key not in payload:
            continue
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue                # 坏值就地丢掉，别发上去换一个 400
        extra[key] = int(value) if key == "seed" else float(value)
    stop = payload.get("stop")
    if isinstance(stop, str) and stop:
        extra["stop"] = [stop]
    elif isinstance(stop, (list, tuple)):
        items = [s for s in stop if isinstance(s, str) and s]
        if items:
            extra["stop"] = items[:4]
            if len(items) > 4:
                extra["stop_dropped"] = len(items) - 4
    return extra or None


class ChatAborted(Exception):
    """下游客户端已经不要这条结果了，主动掐掉上游连接。

    码道账号的**并发会话上限只有 3 个**，而上游是靠「这条 HTTP 连接还在不在」
    判断会话活着的（客户端点停止 = AbortController 断 TCP，见 CodeArts 客户端
    的 fetch 用法；它没有单独的「中止生成」接口）。

    网关如果一口气 `resp.read()` 读到底，那么客户端早就断开、重试、甚至换了
    别的问题，网关这个线程还在替一个没人要的回答读上游 —— 会话一直挂在账号上。
    连着三条就把 3 个名额吃干净，之后所有请求都撞
    `TM.00001041 并发会话数已达上限`，整个网关看起来像死了（2026-10-22 实测
    持续 25 分钟，因为那几条生成真的还在跑）。

    所以读上游改成「分块读 + 每块问一次调用方还要不要」，一旦发现客户端断了
    就抛这个异常，`with` 退出时 `HTTPResponse.close()` 会关掉 socket，上游随即
    回收会话。
    """


class UpstreamBroken(Exception):
    """上游连接在中途断掉 —— chunked 流没写终止块就把 socket 关了。

    ``http.client`` 把它报成 ``IncompleteRead``。这**不是**网关的错：码道上游
    （APIG 后面的推理服务）在会话被服务端回收、账号并发名额被抢占、或网关侧
    空闲超时时，会直接把 TCP 关掉，连 ``0\\r\\n\\r\\n`` 都不写。

    以前这个异常没人接，会一路冒到 ``socketserver.process_request_thread``：
    客户端拿到的是一条「200 + 半截 delta，然后连接凭空消失」的响应，既没有
    ``finish_reason`` 也没有 ``[DONE]`` —— 前端看到的就是**直接断流**
    （2026-10-22 线上复现，日志里 21 次同样的 traceback）。

    读侧统一把它翻译成这个类型并带上已收字节数，由各协议层决定怎么收尾。
    """

    def __init__(self, message, received=0):
        Exception.__init__(self, message)
        self.received = received


def apply_stream_idle_timeout(response, seconds):
    """把已建连的响应 socket 切到「两次读取之间」的空闲上限。

    ``urllib`` 的 timeout 只覆盖建连/首包；拿到响应头之后同一条 socket 会被
    整条 SSE 流继续读。这里把它的读超时改成 idle 值，避免上游中途静默时一直
    挂着。拿不到 socket（假对象、老版本 http.client）或值非法时返回 False，
    保持原来的 header 超时，绝不让调参把请求弄失败。
    """
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return False
    if seconds <= 0:
        return False
    sock = _stream_socket(response)
    if sock is None:
        fp = getattr(response, "fp", None)
        sock = getattr(fp, "_sock", None)
    if sock is None:
        return False
    try:
        sock.settimeout(seconds)
        return True
    except Exception:
        return False


#: 官方服务端排队叫号协议（逆自 kernel 的 queue-retry：函数 Z3/B8/cz/kCn）。
#:
#: 请求带 ``app-id: CodeAgent3.0`` + ``is-need-queue: true`` 声明参与；撞上
#: 429 且响应头 ``queue-status: queued`` 时，改按服务端给的节奏轮询
#: ``GET /api/v1/concurrency/trace-queues/{traceId}``（头 ``trace-id`` 必需，
#: ``retry-after`` 秒，缺省 5），响应体 ``{status, queue_length,
#: queue_wait_time, retry_after}``，``status=="promoted"`` 后**原样重发**请求。
#: ``not_found`` / 连续 3 次 GET 失败 / 超时上限 → 按 429 失败交回上层退避。
#: 排队**不计入** ``x-session-retry``。官方总上限 12h，网关不能把客户端连接
#: 挂那么久，默认 180s（ZCode 客户端自己的超时是 4 分钟）。
QUEUE_ENABLED = ca_env.flag("CODEARTS_QUEUE", True)
QUEUE_MAX_WAIT = ca_env.number("CODEARTS_QUEUE_MAX_WAIT", 180.0, minimum=1.0)
QUEUE_MAX_GET_FAILURES = 3
QUEUE_TRACE_BASE = "/api/v1/concurrency/trace-queues/"


def _qlog(msg):
    """排队路径的可观测性：gw.log 由 systemd 收 stdout/stderr，这里带前缀即可。"""
    print("[codearts-hub] queue: %s" % msg, flush=True)


def _queue_info_from_headers(headers):
    """429 响应头 → 排队参数；不可排队（缺 trace-id / 不是 queued）返回 None。

    头名全小写比较（http.client 的 HTTPMessage 大小写不敏感，但统一掉最稳）。
    ``retry-after`` 单位是**秒**（官方 sleep 内部 ×1000）；数值坏掉按官方缺省。
    """
    h = {}
    try:
        for key, value in (headers.items() if headers is not None else []):
            h[str(key).lower()] = str(value)
    except Exception:
        return None
    if h.get("queue-status", "").lower() != "queued":
        return None
    trace_id = (h.get("trace-id") or "").strip()
    if not trace_id:
        return None

    def _num(name, default):
        try:
            return float(h.get(name))
        except (TypeError, ValueError):
            return default

    try:
        retry_after = float(h.get("retry-after"))
        if retry_after <= 0:
            raise ValueError
    except (TypeError, ValueError):
        retry_after = 5.0
    return {"trace_id": trace_id,
            "retry_after": min(retry_after, 30.0),
            "length": _num("queue-length", 1),
            "wait": _num("queue-wait-time", 0)}


def _retry_after_hint(exc, code):
    """HTTPError 的响应头 → ``[server-retry-after: Ns]`` 标记；没有返回 ""。

    只看 429/503。``retry-after-ms`` 是毫秒直读（官方 rS.delay 优先级一），
    ``retry-after`` 数字按秒、HTTP-date 不解析（网关场景里没有出现过）。
    """
    if code not in (429, 503) or exc.headers is None:
        return ""
    h = {}
    try:
        for key, value in exc.headers.items():
            h[str(key).lower()] = str(value)
    except Exception:
        return ""
    ms = 0.0
    try:
        if h.get("retry-after-ms"):
            ms = float(h["retry-after-ms"])
    except (TypeError, ValueError):
        ms = 0.0
    if ms <= 0:
        try:
            if h.get("retry-after"):
                ms = float(h["retry-after"]) * 1000.0
        except (TypeError, ValueError):
            ms = 0.0
    if ms <= 0 or ms > 600000.0:
        return ""
    return " [server-retry-after: %.1fs]" % (ms / 1000.0)


def open_chat(access_key, secret_key, security_token, model, messages,
              max_tokens=256, stream=True, timeout=None, extra=None,
              tools=None, tool_choice=None, session_id=None,
              idle_timeout=None, session_retry=None):
    """建立一次推理连接，**不读响应体**。返回 (status, resp, text)。

    - 200：resp 是未读的响应句柄，**调用方负责 close()**；text 为空串。
    - 其它：resp 为 None，text 是错误体（已读尽），可直接拿去判重试。

    为什么要有这个「只建连不读」的入口：真流式转发必须在**拿到句柄的那一刻**
    就把响应头回给客户端，然后边收边转。用 chat_for_model 只能等整条流读完，
    客户端在这期间一个字都收不到 —— 长回答（几千 token）时它就干转几分钟，
    最后一次性刷出全文，还容易触发客户端自己的空闲超时（ZCode 是 4 分钟）后
    重试，叠出多个上游会话把账号的并发名额吃干净（2026-10-22 实测事故）。

    ``timeout`` 管到响应头为止；``idle_timeout``（可选）在拿到响应头后把
    socket 读超时切到该值，供整条流使用。
    """
    timeout = CHAT_TIMEOUT if timeout is None else timeout
    body = json.dumps(chat_body(model, messages, max_tokens=max_tokens,
                                stream=stream, extra=extra, tools=tools,
                                tool_choice=tool_choice),
                      ensure_ascii=False).encode("utf-8")

    # 本轮用户消息 id：一次生成、各次尝试与排队重发复用（官方同一回合稳定）。
    msg_id = "msg-" + secrets.token_hex(10)

    def _send():
        """按同一 body/参数重发一次（promoted 后的「原样重发」，签名重新算）。"""
        fresh = chat_headers(access_key, secret_key, security_token,
                             hashlib.sha256(body).hexdigest(),
                             stream=stream, model=model,
                             session_id=session_id,
                             session_retry=session_retry, msg_id=msg_id)
        return urllib.request.urlopen(
            urllib.request.Request(CHAT_PATH, data=body, headers=fresh,
                                   method="POST"), timeout=timeout)

    def _poll_queue(info):
        """按服务端节奏轮询一次 trace-queue。返回 (状态, 新info或None)。"""
        url = SNAP_HOST + QUEUE_TRACE_BASE + urllib.parse.quote(
            info["trace_id"], safe="")
        poll_headers = {"User-Agent": GATEWAY_USER_AGENT,
                        "x-snap-traceid": info["trace_id"],
                        "Accept": "application/json"}
        if security_token:
            poll_headers["X-Security-Token"] = security_token
        poll_headers = aksk_sign(access_key, secret_key, "GET", url, {},
                                 poll_headers)
        req = urllib.request.Request(url, headers=poll_headers, method="GET")
        with urllib.request.urlopen(req, timeout=15) as r:
            payload = json.loads(r.read().decode("utf-8", "replace") or "{}")
        if not isinstance(payload, dict):
            return "queued", info
        for key in ("retry_after",):
            value = payload.get(key)
            if isinstance(value, (int, float)) and value > 0:
                info = dict(info, retry_after=min(float(value), 30.0))
                break
        status = str(payload.get("status") or "queued")
        return status, info

    def _cancel_queue(trace_id):
        """退出排队时 best-effort 注销（官方只在 abort/超时路径发 DELETE）。"""
        try:
            url = SNAP_HOST + QUEUE_TRACE_BASE + urllib.parse.quote(
                trace_id, safe="")
            h = {"User-Agent": GATEWAY_USER_AGENT}
            if security_token:
                h["X-Security-Token"] = security_token
            h = aksk_sign(access_key, secret_key, "DELETE", url, {}, h)
            urllib.request.urlopen(
                urllib.request.Request(url, headers=h, method="DELETE"),
                timeout=10).close()
        except Exception:                     # noqa: BLE001 —— 取消失败无所谓
            pass

    deadline = time.time() + QUEUE_MAX_WAIT
    get_failures = 0
    while True:
        try:
            resp = _send()
        except urllib.error.HTTPError as exc:
            if not QUEUE_ENABLED or exc.code != 429:
                plain = exc.read().decode("utf-8", "replace")
                hint = _retry_after_hint(exc, exc.code)
                return (exc.code, None,
                        (plain[:200] + hint) if hint else plain)
            info = _queue_info_from_headers(exc.headers)
            body_text = exc.read().decode("utf-8", "replace")
            if info is None:
                # 429 但不带排队头（或 queue-status: rejected）：保持旧行为，
                # 原样交回错误体，由上层退避；rejected 时补一句便于归因。
                note = ""
                try:
                    qs = str((exc.headers or {}).get("queue-status") or "").strip()
                except Exception:
                    qs = ""
                if qs and qs.lower() != "queued":
                    note = " (queue-status=%s)" % qs
                # 服务端退避提示（官方 rS 策略：retry-after-ms 毫秒优先、
                # retry-after 秒次之）：折成秒追加到文本尾部，上层重试取
                # max(自家退避, 服务端提示)。只有 429/503 带；400 的 1041
                # 虽然也带 retry-after-ms: 2000，但官方**不睡它**（并发上限
                # 只能靠关会话解除），我们照办 —— BUSY 退避本来就起步 2s。
                hint = _retry_after_hint(exc, exc.code)
                if hint:
                    note += hint
                if note:
                    return exc.code, None, body_text[:200] + note
                return exc.code, None, body_text
            _qlog("joined trace=%s retry_after=%.0fs length=%s wait=%ss"
                  % (info["trace_id"], info["retry_after"], info["length"],
                     info["wait"]))
            status = "queued"
            while status not in ("promoted", "not_found") and get_failures < 3:
                now = time.time()
                if now >= deadline:
                    _qlog("gave up after %.0fs cap (trace=%s)"
                          % (QUEUE_MAX_WAIT, info["trace_id"]))
                    _cancel_queue(info["trace_id"])
                    return 429, None, (
                        "429 queued upstream; promotion did not arrive "
                        "within %.0fs" % QUEUE_MAX_WAIT)
                # 最多睡到上限为止：服务端给的间隔可能比网关能等的时间长。
                time.sleep(min(info["retry_after"], deadline - now))
                try:
                    status, info = _poll_queue(info)
                except Exception as exc:       # noqa: BLE001 —— GET 失败可重试
                    get_failures += 1
                    _qlog("poll failed (%d/3): %r" % (get_failures, exc))
            if status != "promoted":
                _qlog("left queue without promotion (status=%s, failures=%d)"
                      % (status, get_failures))
                return 429, None, (
                    "429 queued upstream; queue status=%s" % status)
            _qlog("promoted (trace=%s)" % info["trace_id"])
            continue          # promoted：原样重发（循环顶重签新请求）
        if idle_timeout is not None:
            apply_stream_idle_timeout(resp, idle_timeout)
        return getattr(resp, "status", 200), resp, ""


#: ``iter_sse`` 的空闲哨兵：上游 ``idle_timeout`` 秒没吐字节时 yield 它。
#:
#: 为什么要往**客户端**发心跳：上游思考时是一段真的静默（GLM-5.2 的 reasoning
#: 有时 20~40 秒不出一个字），而中间层对这种静默有自己的耐心 —— nginx 默认
#: 60s、Cloudflare 免费版约 100s 无数据就掐连接。掐掉时客户端看到的是「回答
#: 到一半没了」，而我们这边还在老老实实读上游。
#: SSE 的注释行（以 ``:`` 开头）是协议允许的噪声，任何合规的解析器都会忽略
#: 它 —— 用它当心跳不会污染正文。
KEEPALIVE = object()

#: 一次空闲等待的默认秒数。15s 足够小于常见中间层的 60s，又不会太碎。
STREAM_IDLE_TIMEOUT = ca_env.number("CODEARTS_STREAM_IDLE", 15.0, minimum=0.5)

#: 连续静默多少次之后认定上游卡死（次数 × STREAM_IDLE_TIMEOUT = 总静默上限）。
STREAM_MAX_IDLE = ca_env.number("CODEARTS_STREAM_MAX_IDLE", 40,
                                minimum=0, integer=True, zero_ok=True)

#: 静默总时长的**硬上限**（秒）。``STREAM_MAX_IDLE=0``（或面板把次数配成 0）
#: 表示「关掉这个看门狗」，但本地不能真让一条静默的流无限挂下去 —— 上游
#: 会话名额会被它一直占着，而本地没有任何东西会来回收。这里给个物理上限：
#: 超过它就是上游已经不要这条流了。
IDLE_HARD_CEILING = ca_env.number("CODEARTS_STREAM_IDLE_CEILING", 900.0,
                                  minimum=1.0)


def _stream_socket(resp):
    """挖出 HTTPResponse 底下的 socket；拿不到就返回 None（老版本/假对象）。

    ``resp.fp`` 是 ``sock.makefile('rb')`` 给的 BufferedReader，``.raw`` 是
    SocketIO，``._sock`` 才是真正的 socket。整条链任何一跳缺失都只是「不能
    发心跳」，不该让请求失败 —— 所以一路 getattr。
    """
    fp = getattr(resp, "fp", None)
    raw = getattr(fp, "raw", None)
    return getattr(raw, "_sock", None)


def _wait_readable(sock, timeout, fp=None, resp=None):
    """等 socket 变可读，**不碰 socket 自己的读超时**。

    返回 True（有数据）/ False（等满了 timeout，上游静默）/ None（这个 socket
    等不了，调用方应放弃心跳、退回阻塞读）。

    为什么不用 ``sock.settimeout()`` 做空闲检测 —— 2026-10-22 线上事故：
    CPython 的 ``socket.SocketIO`` 只要碰到过一次读超时就会置
    ``_timeout_occurred``，此后每次 ``read`` 都直接抛
    ``OSError: cannot read from timed out object``。而 ``HTTPResponse`` 读的
    正是 ``sock.makefile()`` 出来的那个 SocketIO —— 一旦拿短超时去「探」静默，
    这根连接就永久废了。所以空闲只能靠 select 看 fd，读写超时交还给
    open_chat 的兜底值。

    ``fp`` / ``resp`` 是 ``resp.fp``（BufferedReader）与响应对象。**必须一起
    看**：socket 可读只说明「内核里有字节」，而 HTTPResponse 读的是上面那层
    Python 缓冲 —— 响应头和头几个 body 块常常在同一个 TCP 包里到达，
    ``readline()`` 解析响应头时把 body 一起读进了缓冲。此时 fd 上已经没有新
    字节，select 会一直等到超时，这段时间里明明有数据可读却发不出去（本地
    socket 实测首字被推迟 6 秒）；更糟的是连续空等到 max_idle 就把一条完好的
    流误报成断流。

    **只看「缓冲里有没有字节」不够**（2026-10-23 的回归）：chunked 每块数据
    后面跟着 ``\\r\\n``，那一块载荷被 ``read1`` 取走之后，缓冲里还剩着这两个
    分帧字节。``peek(0)`` 非空 → 判可读 → ``read1`` 进去先吃掉 ``\\r\\n``、
    再去读下一块的长度行，于是**阻塞在 socket 上**：心跳不再发、静默看门狗
    与客户端断开检测一起失效（模型长思考时中间层 60~100 秒就切断连接）。
    所以这里判断的是「缓冲里有没有**可以交付的载荷**」，见
    ``_buffered_payload``。
    """
    try:
        # TLS 把明文解在内存里时，fd 上可能暂时没有新字节，select 会误判成
        # 静默；pending() 是「还有没交付的明文」的先手判断。
        pending = getattr(sock, "pending", None)
        if callable(pending) and pending() > 0:
            return True
    except Exception:
        pass
    buffered = _buffered_payload(fp, resp)
    if buffered:
        return True
    try:
        fd = sock.fileno()
    except Exception:
        return None
    if not isinstance(fd, int) or fd < 0:
        return None
    try:
        ready, _, _ = select.select([sock], [], [], max(0.0, float(timeout)))
        return bool(ready)
    except (OSError, ValueError):
        return None


def _peek_bytes(fp):
    """非阻塞地看一眼 ``BufferedReader`` 里已收到、尚未交付的字节。

    ``peek(0)`` 是唯一能在**不消费**的前提下看缓冲内容的办法。它默认会为了
    拿到至少一个字节而阻塞读 socket —— 这在这里正好是灾难（那会绕过 select
    的静默判定，还可能撞上 SocketIO 的超时毒化）。所以先暂时把 socket 切成
    非阻塞：有缓冲就当次返回、没有就返回 ``b""``，然后在 finally 里恢复原
    超时。已实测「非阻塞 peek 失败之后连接仍可正常读」。

    拿不到 fp / 不是 BufferedReader / 任何异常 → 返回 ``b""``。
    """
    peek = getattr(fp, "peek", None)
    if not callable(peek):
        return b""
    sock = None
    try:
        # BufferedReader.raw 是 SocketIO，._sock 才是 socket（同 _stream_socket）
        sock = getattr(getattr(fp, "raw", None), "_sock", None)
        prev = None
        if sock is not None:
            prev = sock.gettimeout()
            sock.setblocking(False)
        try:
            return peek(0) or b""
        finally:
            if sock is not None:
                sock.settimeout(prev)
    except (BlockingIOError, OSError, ValueError, AttributeError):
        # 非阻塞 peek 在缓冲为空时可能抛 BlockingIOError（不同版本行为不一），
        # 那就是「没有缓冲数据」；其余异常同样按「不知道」处理。
        return b""
    except Exception:
        return b""


def _buffered_bytes(fp):
    """``BufferedReader`` 里已经收到、还没交付给调用方的字节数。

    保留给测试与调用方做体积统计；**判断「能不能立刻读出来」请用
    ``_buffered_payload``** —— 字节非零不代表 read1 不会阻塞（chunked 的分帧
    字节就是一例）。
    """
    return len(_peek_bytes(fp))


def _chunk_payload_ready(data, chunk_left):
    """按 chunked 分帧判断：``read1`` 能不能只靠缓冲就返回载荷。

    ``data`` 是缓冲里的全部字节（未消费），``chunk_left`` 是
    ``HTTPResponse.chunk_left``（None = 还没读长度行，0 = 当前块读完了，
    正数 = 当前块还剩这么多载荷）。

    只有三种情况 ``read1`` 不碰 socket：
      · 当前块还有载荷（``chunk_left > 0``）且缓冲里有字节 —— read1 直接取；
      · 缓冲里有一整行长度声明，**且声明后面还有载荷字节**；
      · 末块（长度 0）且它的结束空行也在缓冲里 —— 只做收尾，不发数据。

    其余一律判「不能立刻读」，交回 select：多等一次 select 的代价是零，而误
    判一次的代价是心跳停摆、看门狗失效。
    """
    if not data:
        return False
    pos = 0
    if isinstance(chunk_left, int):
        if chunk_left > 0:
            # 当前块还有载荷：缓冲里有任何字节都能立刻交出去。
            return True
        # chunk_left == 0：缓冲以本块的结束 CRLF 开头。
        if len(data) < 2:
            return False
        if data[:2] != b"\r\n":
            return False
        pos = 2
    # 解析下一块的长度声明（允许 chunk-extension，分号之后忽略）
    end = data.find(b"\r\n", pos)
    if end < 0:
        return False
    size_text = data[pos:end].split(b";")[0].strip()
    try:
        size = int(size_text, 16)
    except ValueError:
        return False
    rest = data[end + 2:]
    if size == 0:
        # 末块：read1 会读掉 trailer，缓冲里得有它的结束空行才不算阻塞。
        return rest.startswith(b"\r\n") or rest.startswith(b"\n")
    return len(rest) > 0


def _buffered_payload(fp, resp=None):
    """缓冲里有没有**可以立刻交付**的载荷字节（而不是分帧/协议开销）。

    ``resp`` 为空时退回「有字节就算有」（老调用方 / 测试的假对象）。
    """
    data = _peek_bytes(fp)
    if not data:
        return False
    if resp is None:
        return True
    try:
        if getattr(resp, "chunked", False):
            return _chunk_payload_ready(data, getattr(resp, "chunk_left", None))
        # 定长响应：length 是「还剩多少」，读完了就不再有载荷。
        length = getattr(resp, "length", None)
        if isinstance(length, int) and length <= 0:
            return False
        return True
    except Exception:
        # 形状认不出来时按「有载荷」处理：这只会让调用方多试一次 read1，
        # 而 read1 在缓冲非空时不会阻塞。
        return True


def iter_sse(resp, abort_check=None, read_size=8192, stats=None,
             idle_timeout=None, max_idle=None):
    """逐行吐出上游 SSE 文本（含行尾换行）。resp 的生命周期由调用方管。

    ``abort_check`` 每读一块前问一次，为真就抛 ``ChatAborted`` —— 客户端走了
    还继续读，会替一个没人要的回答占着账号的并发名额（见 ChatAborted）。

    用增量解码器而不是逐块 ``decode``：一块 8192 字节很容易正好切在中文或
    emoji 的三/四字节序列中间，逐块解会吐出替换字符，前端显示成「锟斤拷」。

    读侧的网络异常一律收敛成 ``UpstreamBroken``（正常 EOF 不抛）。``stats``
    是可选的可变字典，回填 ``bytes``（已收字节数）与 ``truncated``（是否
    异常中断），供上层区分「上游没给内容就断」和「吐到一半断」。

    给了 ``idle_timeout`` 就**每读一块之前先 select 等这么久**：等不到数据
    就 yield 一次 ``KEEPALIVE``，让调用方给客户端发心跳，然后接着等同一根
    连接。``max_idle`` 次连续空等之后才认定上游卡死（抛 ``UpstreamBroken``）。
    **注意这里绝不动 socket 的读超时** —— 原因见 ``_wait_readable``。
    """
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    buf = ""
    total = 0
    if stats is None:
        stats = {}
    stats.setdefault("bytes", 0)

    sock = _stream_socket(resp) if idle_timeout else None
    idle_streak = 0
    limit = max_idle if max_idle is not None else STREAM_MAX_IDLE
    # 0 / 负数一律按「上限关掉了」，但**不能真的无限等**：一条静默的流会挂到
    # 上游自己超时（实测可达分钟级），这期间账号的并发名额一直被它占着，
    # 而本地又没有看门狗会回收它。以前 max_idle=0 就是 `if limit and ...`
    # 永远为假，于是「无限挂着」。
    # 这里给一个硬上限：IDLE_HARD_CEILING 秒（按硬上限/单次等待折算成次数）。
    if not limit or limit <= 0:
        limit = max(1, int(IDLE_HARD_CEILING / max(1.0, float(idle_timeout))))
    # 三个只用于断流归因的计数：socket 到底拿没拿到（拿不到就没有心跳、
    # 也不会续期）、发了几次心跳、最后一次收到字节是什么时候。
    stats["sock"] = sock is not None
    stats.setdefault("pings", 0)
    last_data_at = time.time()

    while True:
        if abort_check is not None and abort_check():
            raise ChatAborted("client gone")
        if sock is not None and idle_timeout:
            # 把 resp 与 resp.fp 一起传进去：光看 socket 会把「已经在 Python
            # 缓冲里的字节」当成静默（见 _wait_readable）；只看「缓冲里有字节」
            # 又会被 chunked 的分帧 CRLF 骗到（见 _buffered_payload）。
            ready = _wait_readable(sock, idle_timeout,
                                   getattr(resp, "fp", None), resp)
            if ready is None:
                # 等不了（假对象 / 已关闭 / 没 fileno）：放弃心跳，退回阻塞读。
                # 宁可少一条心跳，也不要在这里抛错把好好的流弄断。
                sock = None
            elif not ready:
                idle_streak += 1
                if limit and idle_streak > limit:
                    stats["truncated"] = True
                    raise UpstreamBroken(
                        "upstream silent for %ss (%d idle reads)"
                        % (idle_timeout, idle_streak), total)
                stats["pings"] += 1
                yield KEEPALIVE
                continue
        failed = None
        try:
            try:
                piece = resp.read1(read_size)
            except AttributeError:      # 老版本 http.client 没有 read1
                piece = resp.read(read_size)
        except (http.client.HTTPException, OSError) as exc:
            # 走到这里说明连接真的坏了，或者撞上了 open_chat 设的兜底读超时
            # （默认 300s，只在半帧里卡住时才会触发）。**不能在这里发心跳
            # 接着读**：SocketIO 一次超时就永久拒绝再读（见 _wait_readable）。
            # IncompleteRead 带着已读到的 partial；其余按 0 处理。注意
            # IncompleteRead 是 HTTPException 但不是 OSError，两个都要接。
            piece = getattr(exc, "partial", b"") or b""
            failed = exc
        if piece:
            idle_streak = 0
            last_data_at = time.time()
            total += len(piece)
            stats["bytes"] = total
            buf += decoder.decode(piece)
            while True:
                cut = buf.find("\n")
                if cut < 0:
                    break
                line, buf = buf[:cut + 1], buf[cut + 1:]
                yield line
        if failed is not None:
            stats["truncated"] = True
            stats["silent_s"] = round(time.time() - last_data_at, 1)
            raise UpstreamBroken(
                "upstream closed early: %s" % (str(failed) or type(failed).__name__),
                total)
        if not piece:
            break
    buf += decoder.decode(b"", True)
    if buf:
        yield buf


def chat_for_model(access_key, secret_key, security_token, model, messages,
                   max_tokens=256, stream=True, timeout=None, extra=None,
                   tools=None, tool_choice=None, abort_check=None,
                   session_id=None, idle_timeout=None, session_retry=None):
    """发一次真实推理，返回 (http 状态码, 原始响应体)。

    福利渠道下线后所有模型都走内置通道，不再需要按分组挑请求头。
    返回 (http 状态码, 原始响应体)。**不走 _http** —— 那个函数会把非 JSON 的
    SSE 流包成 {"_raw": ...}，还会把流式帧里的 error_code 当业务错误抛掉，
    推理这边需要的是原样字节，判定交给调用方。

    ``abort_check``：可选的无参回调，每读完一块就问一次「下游还要吗」。返回
    真值时抛 ``ChatAborted``，让上层立刻关掉上游连接。这**不是**优化，是正确性：
    不这么做，一个被客户端放弃的长回答会把账号的并发名额占死（见 ChatAborted）。
    """
    status, resp, text = open_chat(
        access_key, secret_key, security_token, model, messages,
        max_tokens=max_tokens, stream=stream, timeout=timeout, extra=extra,
        tools=tools, tool_choice=tool_choice, session_id=session_id,
        idle_timeout=idle_timeout, session_retry=session_retry)
    if resp is None:
        return status, text
    try:
        return status, "".join(iter_sse(resp, abort_check))
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# 积分签到（客户端「活动与权益 → 每日签到领 1000 积分」）
# ---------------------------------------------------------------------------
#
# 这与上面的 token 额度是两套账，别混：
#   额度  opengw /api/v1/benefit/claim        每天 1000 万 token，随渠道收回会失效
#   积分  snap-access /v1/ops/claim          每天 1000 积分，走活动系统
#
# 端点与请求形状逆自本机客户端（vscode-codebot/out/extension.js 的 s6i 对象）：
#   GET  /v1/ops/delivery?channel=IDE        活动清单（含「今天签没签」的状态）
#   POST /v1/ops/claim                       领取，body 见 welfare_claim
#   POST /v1/ops/confirm                     确认到账；客户端领完立刻调一次
#
# 响应约定与 benefit 不同：业务成败看 ``code``（0 成功），不是 error_code。
#
# 鉴权：客户端带 x-auth-token，但 hub 用 AK/SK 签名即可 —— 同一台
# snap-access 的 /v1/* 上，/v1/model/builtin 与 /v1/model/thinking-variants
# 一直是 AK/SK 打通并投产的（见 builtin_models / thinking_variants）。
# 客户端之所以用 token，只是它的 toolkit 手里有 IAM 令牌而已。

WELFARE_DELIVERY_PATH = "/v1/ops/delivery"
WELFARE_CLAIM_PATH = "/v1/ops/claim"
WELFARE_CONFIRM_PATH = "/v1/ops/confirm"
WELFARE_CHANNEL = "IDE"
WELFARE_DAILY_TYPE = "USER_LOGIN"

#: 活动清单变化不快，面板每几秒轮询一次账号列表，按账号缓存一会儿。
#: 失败也缓存（更短），免得接口坏掉时每次轮询都多打一次上游。
WELFARE_CACHE_TTL = 60.0
WELFARE_ERROR_TTL = 30.0
#: **永久失败**（渠道被收回 / 活动下线 / 参数永远不成立）的缓存时长。
#:
#: 这类错误重试再多次也是同一句话：上游回的是 ``[4000] invalid channel,
#: group not found`` 或「活动清单里没有每日签到」，与时间、限流、网络都无关。
#: 按 30 秒缓存时，面板每 5 秒一次轮询 = 每 30 秒一次必然失败的上游请求，
#: 一天两千多次，日志与活动历史里堆了几百条一模一样的失败（2026-10-23 实测
#: 攒到 100 条）。这里按小时级缓存，同时**不再记活动历史**（见
#: ``welfare_permanent_failure``）—— 同一句永久失败记一次是证据，记一百次是噪声。
WELFARE_PERMANENT_TTL = 6 * 3600.0

_welfare_cache = {}


def welfare_permanent_failure(exc):
    """这个失败是「上游不会变」的那种吗？

    只有明确的**渠道 / 活动不存在**才算：``invalid channel``、``group not
    found``、``activity not found``、清单里根本没有每日签到那一条。判据必须
    窄 —— 把 401（STS 过期，重新授权就好）、429（限流，等一会儿就好）、
    5xx（抖动）算成永久失败，等于把一个能自愈的问题永久钉死。
    """
    text = str(getattr(exc, "message", "") or exc or "")
    low = text.lower()
    return any(marker in low for marker in (
        "invalid channel",
        "group not found",
        "activity not found",
        "没有「每日签到」",
        "活动清单里没有",
    ))


def _welfare_item(raw):
    """把 delivery 的一条活动归一成面板能直接用的形状。"""
    status = str(raw.get("status") or "").upper()
    return {
        "campaign_id": raw.get("campaignId"),
        "title": raw.get("title") or "",
        "type": raw.get("type") or "",
        "status": status,
        "amount": raw.get("benefitAmount"),
        "unit": raw.get("benefitUnit") or "",
        "claimable": bool(raw.get("claimable")),
        "description": raw.get("description") or "",
        "claimed_at": raw.get("claimedAt") or "",
        "expire_at": raw.get("expireAt") or "",
    }


def _welfare_request(access_key, secret_key, security_token, method, path,
                     query=None, body=None, timeout=DEFAULT_TIMEOUT):
    """打一次 /v1/ops/*，返回 data 部分。

    GET 的 query 必须同时进 URL 与签名串，否则 APIG 会报签名不匹配。
    POST 的 payload hash 也要算进签名（与 credit_headers 同一个坑）。
    """
    url = SNAP_HOST + path
    query = dict(query or {})
    if query:
        url += "?" + urllib.parse.urlencode(query)
    raw_body = None if body is None else json.dumps(body).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "Agent-Type": "PromptCenter",
        "X-Language": "zh-cn",
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    headers = aksk_sign(
        access_key, secret_key, method, url, query, headers,
        payload_hash=hashlib.sha256(raw_body).hexdigest() if raw_body is not None else None)
    payload = _http(method, url, headers=headers, body=raw_body, timeout=timeout)
    if not isinstance(payload, dict):
        raise CodeArtsError("积分签到接口返回了非 JSON 内容")
    code = payload.get("code")
    if code not in (None, 0, "0"):
        raise CodeArtsError(str(payload.get("message") or ("code=%s" % code)))
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def welfare_activities(access_key, secret_key, security_token,
                       timeout=DEFAULT_TIMEOUT, use_cache=True):
    """积分活动清单。返回 {"channel", "items", "daily"}。

    ``daily`` 是「每日签到」那一条（type=USER_LOGIN），没有就是 None。
    结果按 AK 缓存 WELFARE_CACHE_TTL 秒；失败缓存 WELFARE_ERROR_TTL 秒，
    **永久失败**（渠道被收回之类）缓存 WELFARE_PERMANENT_TTL 秒 —— 见
    welfare_permanent_failure 的说明。
    """
    key = access_key or ""
    now = time.time()
    if use_cache:
        hit = _welfare_cache.get(key)
        if hit and hit[0] > now:
            if hit[1] is None:
                raise CodeArtsError(hit[2])
            return hit[1]
    try:
        data = _welfare_request(access_key, secret_key, security_token, "GET",
                                WELFARE_DELIVERY_PATH,
                                query={"channel": WELFARE_CHANNEL},
                                timeout=timeout)
    except Exception as exc:
        ttl = (WELFARE_PERMANENT_TTL if welfare_permanent_failure(exc)
               else WELFARE_ERROR_TTL)
        _welfare_cache[key] = (now + ttl, None, str(exc))
        raise
    items = [_welfare_item(raw) for raw in (data.get("items") or [])
             if isinstance(raw, dict)]
    daily = next((it for it in items if it["type"] == WELFARE_DAILY_TYPE), None)
    result = {
        "channel": data.get("channel") or "",
        "items": items,
        "daily": daily,
    }
    _welfare_cache[key] = (now + WELFARE_CACHE_TTL, result, "")
    return result


def welfare_daily(access_key, secret_key, security_token,
                  timeout=DEFAULT_TIMEOUT, use_cache=True):
    """只看每日签到那一条；清单里没有返回 None。"""
    return welfare_activities(access_key, secret_key, security_token,
                              timeout=timeout, use_cache=use_cache)["daily"]


def welfare_claim(access_key, secret_key, security_token, campaign_id,
                  timeout=DEFAULT_TIMEOUT):
    """领取一个活动，并按客户端的做法立刻 confirm。

    客户端在 claim 成功且返回里带 campaignId 时自动调 confirm；只有
    confirm 成功才算真正到账。判据同样看 status ∈ CLAIMED/CONFIRMED/CONSUMED。
    """
    try:
        campaign_id = int(campaign_id)
    except (TypeError, ValueError):
        raise CodeArtsError("积分签到缺少有效的 campaignId")
    claim_body = {
        "campaignId": campaign_id,
        "idempotentKey": "claim_%s_%d" % (campaign_id, int(time.time() * 1000)),
        "channel": WELFARE_CHANNEL,
    }
    data = _welfare_request(access_key, secret_key, security_token, "POST",
                            WELFARE_CLAIM_PATH, body=claim_body, timeout=timeout)
    status = str(data.get("status") or "").upper()
    if data.get("campaignId") is not None:
        confirmed = _welfare_request(access_key, secret_key, security_token, "POST",
                                     WELFARE_CONFIRM_PATH,
                                     body={"campaignId": campaign_id},
                                     timeout=timeout)
        confirmed_status = str((confirmed or {}).get("status") or "").upper()
        if confirmed_status in ("CLAIMED", "CONFIRMED", "CONSUMED"):
            data = confirmed
            status = confirmed_status
    _welfare_cache.pop(access_key or "", None)
    if status not in ("CLAIMED", "CONFIRMED", "CONSUMED"):
        raise CodeArtsError("领取未生效（状态 %s）" % (status or "空"))
    return {
        "ok": True,
        "campaign_id": campaign_id,
        "status": status,
        "title": data.get("campaignTitle") or "",
        "claimed_at": data.get("claimedAt") or "",
        "raw": data,
    }


def welfare_claim_daily(access_key, secret_key, security_token,
                        timeout=DEFAULT_TIMEOUT):
    """签到：先看清单里今天的签到是不是已经领过，没有就 claim + confirm。

    返回 claim 结果，并带 ``activity``（重新拉一次清单后的签到条目），
    面板据此直接显示「今日已领」，不靠猜。
    """
    daily = welfare_daily(access_key, secret_key, security_token,
                          timeout=timeout, use_cache=False)
    if not daily:
        raise CodeArtsError("活动清单里没有「每日签到」")
    campaign_id = daily.get("campaign_id")
    if daily.get("status") in ("CLAIMED", "CONFIRMED", "CONSUMED"):
        return {"ok": True, "already": True, "campaign_id": campaign_id,
                "status": daily["status"], "title": daily.get("title") or "",
                "amount": daily.get("amount"),
                "claimed_at": daily.get("claimed_at") or "",
                "activity": daily}
    result = welfare_claim(access_key, secret_key, security_token, campaign_id,
                           timeout=timeout)
    result["already"] = False
    try:
        fresh = welfare_daily(access_key, secret_key, security_token,
                              timeout=timeout, use_cache=False)
    except Exception:
        fresh = None
    if fresh:
        result["activity"] = fresh
        if fresh.get("amount") is not None:
            result["amount"] = fresh["amount"]
    if result.get("amount") is None:
        result["amount"] = daily.get("amount")
    return result


# ---------------------------------------------------------------------------
# 会话存储
# ---------------------------------------------------------------------------
#
# 刻意放在 accounts/codearts/ 子目录：AccountPool.load() 只扫 accounts/ 顶层的
# *.json，放子目录里它一个都看不见，不会把码道会话当成「读不懂的 WorkBuddy 账号」
# 而报警或误判。

SESSION_SUBDIR = "codearts"


def session_dir(accounts_dir):
    return os.path.join(accounts_dir, SESSION_SUBDIR)


def _safe_name(value):
    text = re.sub(r"[^A-Za-z0-9_-]", "_", str(value or "")).strip("_")
    return text or "unknown"


def session_path(accounts_dir, account_id):
    return os.path.join(session_dir(accounts_dir), _safe_name(account_id) + ".json")


def load_sessions(accounts_dir):
    """读回全部码道会话，按账号名排序。坏文件跳过，不影响其他账号。"""
    directory = session_dir(accounts_dir)
    if not os.path.isdir(directory):
        return []
    sessions = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        if isinstance(data, dict) and data.get("accessKey"):
            sessions.append(data)
    return sessions


def save_session(accounts_dir, session, path=None):
    """原子落盘。返回文件路径。

    **权限收紧到 0600**（2026-10-23）：这个文件里躺着 accessKey / secretKey /
    securitytoken / refresh_token 和 DPoP 私钥 —— 等于账号的完整所有权。
    以前用 ``open()`` 默认权限（Linux/macOS 上受 umask 影响，通常 0644），
    同一台机器上的任何用户都能读走它。``os.open`` 带 ``mode=0o600`` 才是
    真的收得住：``open()`` 的 mode 参数不存在，事后 ``chmod`` 又有窗口期。
    """
    directory = session_dir(accounts_dir)
    os.makedirs(directory, exist_ok=True)
    account_id = (session.get("account") or {}).get("id") or "unknown"
    target = path or session_path(accounts_dir, account_id)
    tmp = "%s.%d.%d.tmp" % (target, os.getpid(), threading.get_ident())
    try:
        raw = json.dumps(session, ensure_ascii=False, indent=2).encode("utf-8")
        # 0o600 在 Windows 上会被忽略（Windows 用 ACL，没有 POSIX 位），
        # 那里靠 %APPDATA% / %LOCALAPPDATA% 的用户隔离，行为与以前一致。
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            os.write(fd, raw)
        finally:
            os.close(fd)
        try:
            # umask 会从 0o600 里再抹掉位（常见 022 不影响，077 会变成 0o600
            # 本身 —— 已经够紧）；无条件再 chmod 一次，避免 umask 0177 把
            # 文件写成 0o400 之后续期写不进去。
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise
    return target


def delete_session(accounts_dir, account_id):
    path = session_path(accounts_dir, account_id)
    if os.path.exists(path):
        os.unlink(path)
        return True
    return False


#: STS 剩余寿命低于这个值就自动续期。码道 STS 只有约 2 小时寿命。
REFRESH_MARGIN_SECONDS = ca_env.number("CODEARTS_REFRESH_MARGIN", 300.0,
                                       minimum=0.0, zero_ok=True)

#: refresh_token 一次性轮换：两个线程同时拿同一个旧 token 去换，后到的必然
#: 1806。这里把「重读存档 → 换 token → 落盘」整段串行化，进程内只可能有一个
#: 续期在飞；锁内重读还能让并发调用复用别人刚换回来的结果。
_REFRESH_LOCK = threading.Lock()


def refresh_session(accounts_dir, account_id, min_remaining=None):
    """用存档里的 DPoP 私钥 + refresh_token 续一次 STS，并覆盖存档。

    min_remaining=None 表示无条件续期（面板上的「续期」按钮）；给数字则表示
    「锁内重读后若剩余寿命已够长就直接复用」，自动续期走这条，避免刚续完又被
    另一个线程拿新 token 再换一次。

    注意：refresh_token 是**一次性轮换**的，换成功会拿到新的 refresh_token。
    换失败（1806）说明被别的客户端用掉了或已过期，只能重新走浏览器登录。
    """
    with _REFRESH_LOCK:
        sessions = {((s.get("account") or {}).get("id")): s
                    for s in load_sessions(accounts_dir)}
        session = sessions.get(account_id)
        if not session:
            raise CodeArtsError("找不到该码道账号的存档")
        if min_remaining is not None:
            current = summarize(session)
            left = current.get("sts_remaining_seconds")
            if not current.get("sts_expired") and isinstance(left, (int, float)) \
                    and left >= min_remaining:
                return session
        if not session.get("refresh_token"):
            raise CodeArtsError("该账号是 old_login 产物，没有 refresh_token，只能重新登录")

        context = session.get("loginContext") or {}
        key = import_keypair((context.get("dpopKeyPair") or {}).get("privateKeyJwk"))
        pkce = context.get("pkcePair") or {}
        if not pkce.get("codeVerifier"):
            raise CodeArtsError("存档里缺少 code_verifier，无法续期")

        response = refresh(key, pkce, session["refresh_token"])
        renewed = session_from_iam_response(response, key, pkce, session.get("portal") or "")
        # 服务端没回新 refresh_token 时沿用旧的（理论上不会，但别把好东西弄丢）
        if not renewed.get("refresh_token"):
            renewed["refresh_token"] = session["refresh_token"]
        # 新 refresh_token 偶尔不带 user_profile。若直接落盘，account.id 会变成
        # 空串、文件被写成 unknown.json，面板上账号名消失且旧文件再也续不上。
        old_account = session.get("account") or {}
        new_account = renewed.get("account") or {}
        if not new_account.get("id"):
            new_account["id"] = old_account.get("id") or ""
        if not new_account.get("label"):
            new_account["label"] = old_account.get("label") or ""
        renewed["account"] = new_account
        if not renewed.get("domainId"):
            renewed["domainId"] = session.get("domainId") or ""
        save_session(accounts_dir, renewed)
        return renewed


def ensure_fresh_session(accounts_dir, session, margin=None):
    """STS 快到期/已过期且可续期时续一次，返回最新会话。

    不需要续期、或该账号没有 refresh_token 时原样返回。真正续期失败会抛
    CodeArtsError —— 调用方据此把「为什么领不到」写进日志/看板，而不是拿
    过期凭证去打上游再收到一个含糊的 401。
    """
    if not session:
        return session
    current = summarize(session)
    left = current.get("sts_remaining_seconds")
    margin = REFRESH_MARGIN_SECONDS if margin is None else margin
    need = current.get("sts_expired") or (
        isinstance(left, (int, float)) and left < margin)
    if not need or not current.get("renewable"):
        return session
    account_id = (session.get("account") or {}).get("id")
    if not account_id:
        return session
    return refresh_session(accounts_dir, account_id, min_remaining=margin)


# ---------------------------------------------------------------------------
# 登录状态机
# ---------------------------------------------------------------------------

LOGIN_TTL_SECONDS = 600


class LoginManager:
    """一次一条码道登录流。

    官方客户端每次登录独占一个本地端口，回调里的 code/secret 不带 state，
    天然靠端口区分。hub 只有一个端口，所以这里退化成「单槽位」：
    同时只允许一条 pending，重复 start 会顶掉旧的（旧链接失效）。
    """

    def __init__(self, accounts_dir, log=None):
        self.accounts_dir = accounts_dir
        self.log = log or (lambda *a, **k: None)
        self._lock = threading.Lock()
        self._pending = {}

    # -- 生命周期 -----------------------------------------------------------

    def start(self, port, theme=1, locale="zh-cn", plugin_version=PLUGIN_VERSION):
        key = generate_keypair()
        pkce = generate_pkce()
        ticket = new_ticket_id()
        url = authorize_url(port, pkce, ticket, theme=theme, locale=locale,
                            plugin_version=plugin_version)
        record = {
            "state": ticket,
            "created": time.time(),
            "key": key,
            "pkce": pkce,
            "port": int(port),
            "authUrl": url,
            "secret": "",
            "status": "pending",
            "message": "等待浏览器完成华为云登录",
            "account": None,
            "error": "",
        }
        with self._lock:
            # 顶掉所有旧槽位，保证回调永远只有唯一候选
            for old in list(self._pending):
                if self._pending[old]["status"] == "pending":
                    self._pending[old]["status"] = "superseded"
                    self._pending[old]["message"] = "已被新的登录请求取代"
            self._pending[ticket] = record
        self.log("码道登录已发起（ticket=%s…, port=%s）" % (ticket[:8], port))
        return {"state": ticket, "authUrl": url, "port": int(port),
                "mode": "new_iam_login", "expiresIn": LOGIN_TTL_SECONDS}

    def _current(self):
        """回调不带 state，只能按「唯一 pending」定位。

        **过期在取用时就判**：``/oauth/callback`` 是免鉴权入口，以前只有
        ``poll()`` 和 ``sweep()`` 看 TTL，而 ``accept_callback`` 不看 ——
        一条发起后放弃的登录链接会永远有效。结果是任何人都能拿它把自己
        的华为云账号塞进网关（或把真正在登录的那个人挤掉）。
        """
        now = time.time()
        with self._lock:
            live = []
            for record in self._pending.values():
                if record["status"] != "pending":
                    continue
                if now - record["created"] > LOGIN_TTL_SECONDS:
                    record["status"] = "expired"
                    record["message"] = "登录窗口已过期（10 分钟），请重新发起"
                    continue
                live.append(record)
            if not live:
                return None
            return max(live, key=lambda r: r["created"])

    def accept_callback(self, code=None, secret=None):
        """浏览器回跳时调用。返回 (kind, detail)。

        kind: 'redirect' 需要把浏览器继续 307 送走；'ok' / 'error' 直接渲染页面。
        """
        record = self._current()
        if record is None:
            return ("error", "没有正在等待的登录请求（可能已超时，或链接是旧的）")
        if secret and not code:
            # old_login 的第一步：先记下 secret，把浏览器放行去继续走流程
            with self._lock:
                record["secret"] = secret
            return ("redirect", secret)
        if not code:
            return ("error", "回调里既没有 code 也没有 secret")

        try:
            response = exchange_code(record["key"], code, record["pkce"], record["port"])
            session = session_from_iam_response(response, record["key"], record["pkce"],
                                                record["authUrl"])
            save_session(self.accounts_dir, session)
        except CodeArtsError as exc:
            with self._lock:
                record["status"] = "error"
                record["error"] = str(exc)
                record["message"] = "换 token 失败：%s" % exc
            self.log("码道登录换 token 失败：%s" % exc, level="WARN")
            return ("error", str(exc))
        except Exception as exc:  # 存档失败等意外
            with self._lock:
                record["status"] = "error"
                record["error"] = repr(exc)
                record["message"] = "保存失败：%r" % exc
            self.log("码道登录保存失败：%r" % exc, level="WARN")
            return ("error", repr(exc))

        with self._lock:
            record["status"] = "ok"
            record["account"] = session
            record["message"] = "登录成功"
        self.log("码道账号已添加：%s" % (session.get("account") or {}).get("label"))
        return ("ok", (session.get("account") or {}).get("label") or "")

    def poll(self, state):
        state = str(state or "").strip()
        with self._lock:
            record = self._pending.get(state)
            if not record:
                return {"status": "unknown", "message": "state 不认识，请重新发起登录"}
            if time.time() - record["created"] > LOGIN_TTL_SECONDS:
                record["status"] = "expired"
                record["message"] = "登录窗口已过期（10 分钟），请重新发起"
            snapshot = {
                "state": state,
                "status": record["status"],
                "message": record["message"],
                "error": record.get("error") or "",
                # **只给摘要，不给凭据**（2026-10-23）。以前这里返回完整的
                # session：accessKey / secretKey / securitytoken / refresh_token
                # / DPoP 私钥。这条路是面板轮询用的，而面板只是个浏览器页面 ——
                # 一次 XSS、一个扩展、一段被截的 HAR 就能把账号整个搬走。
                # 面板真正需要的只有「成功没成功、是哪个号」。
                "account": (summarize(record["account"])
                            if record.get("account") else None),
            }
        # 面板读的是 summary.account（老字段名），保持兼容：两个键同一个值。
        snapshot["summary"] = snapshot["account"]
        return snapshot

    def cancel(self, state):
        with self._lock:
            record = self._pending.pop(str(state or "").strip(), None)
        return record is not None

    def sweep(self):
        """清掉超过 TTL 的槽位，避免常驻进程里积垃圾。"""
        cutoff = time.time() - LOGIN_TTL_SECONDS
        with self._lock:
            for state in [s for s, r in self._pending.items() if r["created"] < cutoff]:
                self._pending.pop(state, None)


def _html_escape(value):
    """HTML 转义。回调页把上游错误文本、跳转地址写进页面，那些都是外部输入。"""
    import html as _html
    return _html.escape(str(value or ""), quote=True)


def callback_page(ok, title, detail):
    """回调落地页。浏览器里直接看到，所以要写成人话。

    **所有插值都转义**：``detail`` 里可能带上游回显的错误文本，而
    ``/oauth/callback`` 是**免鉴权**的路由（浏览器跳回来时带不了面板令牌）。
    以前直接 ``%`` 插进 HTML，一个精心构造的错误说明就是一段可执行的脚本，
    能读走 localStorage 里的 API key。``title`` 虽然只有内部常量，也一并转义
    —— 「只有常量」这种假设迟早会被下一个改动打破。
    """
    color = "#16a34a" if ok else "#dc2626"
    icon = "✓" if ok else "✕"
    hint = ("可以关闭此页面，回到网关面板查看账号。"
            if ok else "请关闭此页面，回到网关面板重试。")
    return """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#f6f7f9;font:15px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#1f2328}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:36px 40px;max-width:440px;
box-shadow:0 8px 30px rgba(0,0,0,.06);text-align:center}
.badge{width:56px;height:56px;border-radius:50%%;display:flex;align-items:center;justify-content:center;
margin:0 auto 18px;font-size:28px;color:#fff;background:%s}
h1{font-size:19px;margin:0 0 10px;font-weight:600}
p{margin:0;color:#57606a;font-size:14px;word-break:break-all}
.tip{margin-top:18px;font-size:13px;color:#8b949e}
@media (prefers-color-scheme:dark){
body{background:#0d1117;color:#e6edf3}
.card{background:#161b22;border-color:#30363d;box-shadow:none}
p{color:#8b949e}.tip{color:#6e7681}}
</style></head><body><div class="card">
<div class="badge">%s</div><h1>%s</h1><p>%s</p><div class="tip">%s</div>
</div></body></html>""" % (_html_escape(title), color, icon, _html_escape(title),
                          _html_escape(detail), _html_escape(hint))


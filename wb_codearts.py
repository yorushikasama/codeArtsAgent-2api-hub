# -*- coding: utf-8 -*-
"""wb_codearts.py - 码道 CodeArts Agent（华为云）授权链路

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
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

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
TICKET_RETRY_SECONDS = 2.0
TICKET_MAX_TRIES = 10

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


def _http(method, url, headers=None, body=None, timeout=DEFAULT_TIMEOUT):
    data = body.encode("utf-8") if isinstance(body, str) else body
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


def poll_ticket(ticket_id, secret, plugin_version=PLUGIN_VERSION,
                timeout=DEFAULT_TIMEOUT):
    """old_login 通道：轮询一次性 ticket。

    返回 {user_id, user_name, domain_id, credential:{access, secret,
    securitytoken, expires_at}}。没有 refresh_token，到期只能重新登录。
    """
    url = (f"{SNAP_ENGINE}/v1/login/ticket?"
           + urllib.parse.urlencode({"ticket_id": ticket_id, "secret": secret}))
    return _http("GET", url, headers={
        "Content-Type": "application/json;charset=UTF-8",
        "plugin-name": LOGIN_PLUGIN_NAME,
        "plugin-version": plugin_version,
    }, timeout=timeout)


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


def session_from_ticket(ticket, dpop_key=None, pkce=None):
    """把 old_login 的 ticket 结果整理成同形会话（无 refresh_token）。"""
    credential = (ticket or {}).get("credential") or {}
    if not credential.get("access"):
        raise CodeArtsError("ticket 已确认但没有 credential", payload=ticket)
    login_context = {}
    if pkce:
        login_context["pkcePair"] = pkce
    if dpop_key is not None:
        login_context["dpopKeyPair"] = {
            "privateKeyJwk": dpop_key.private_jwk,
            "publicKeyJwk": dpop_key.public_jwk,
        }
    return {
        "id": "huawei-cloud-authentication",
        "account": {
            "id": ticket.get("user_id") or "",
            "label": ticket.get("user_name") or "",
        },
        "scopes": [],
        "accessToken": "",
        "accessKey": credential.get("access"),
        "secretKey": credential.get("secret"),
        "securitytoken": credential.get("securitytoken"),
        "expires_at": credential.get("expires_at"),
        "domainId": ticket.get("domain_id") or "",
        "refresh_token": "",
        "loginContext": login_context,
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

GATEWAY_HOST = "https://opengw.developer.huaweicloud.com"
GATEWAY_CONFIG_PATH = "/api/v1/gateway/config"

# 出站身份：内核用的就是这两个（OPENCODE_SERVICE_NAME 默认 CodeAgent3.0，
# tracing 层名 Kernel），照抄以免被网关按客户端特征拦。
GATEWAY_USER_AGENT = "CodeAgent3.0-Kernel"
GATEWAY_SERVICE_NAME = "w3"

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

    逐条对齐官方 AKSKSigner：头名小写排序后用 ; 拼成 SignedHeaders，
    canonical headers 的**值不裁空白**，query 取自 query_params 而不是
    url 里的原始顺序。
    """
    if not access_key or not secret_key:
        raise CodeArtsError("缺少 AK/SK，无法给业务接口签名")
    parts = urllib.parse.urlsplit(url)
    netloc = parts.hostname or ""
    if parts.port and not ((parts.scheme == "https" and parts.port == 443)
                           or (parts.scheme == "http" and parts.port == 80)):
        netloc = "%s:%d" % (netloc, parts.port)

    now = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    merged = dict(headers or {})
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

    signed = dict(headers or {})
    signed["Host"] = netloc
    signed["X-Sdk-Date"] = now
    signed["Authorization"] = "%s Access=%s, SignedHeaders=%s, Signature=%s" % (
        SIGN_ALGORITHM, access_key, signed_headers, signature)
    return signed


def gateway_config(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """取对话网关配置：推理入口 + 这账号可用的对话模型。

    返回 {"base_url": ..., "models": [...]}；models 已按 sort 排好序。
    """
    url = GATEWAY_HOST + GATEWAY_CONFIG_PATH
    # security token 是**参与签名**的头，必须在签名前就放进请求头里。
    # 先签一次再补 token、再拿补过的头去签第二次是错的：第二次会把第一次
    # 产出的 Authorization / Host / X-Sdk-Date 一起签进去，对不上。
    base = {
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        base["X-Security-Token"] = security_token
    headers = aksk_sign(access_key, secret_key, "GET", url, {}, base)
    payload = _http("GET", url, headers=headers, timeout=timeout)
    if str(payload.get("error_code") or "") not in ("", "0000"):
        raise CodeArtsError(
            "网关配置返回 %s：%s" % (payload.get("error_code"), payload.get("error_msg")),
            code=str(payload.get("error_code")), payload=payload)
    result = payload.get("result") or {}
    models = result.get("models") or []
    models.sort(key=lambda m: (m.get("sort") if isinstance(m.get("sort"), (int, float))
                               else 999))
    return {"base_url": result.get("base_url") or result.get("endpoint") or "",
            "models": models}


def normalize_models(models):
    """码道网关的模型条目 → 网关内部统一的模型对象形状。

    网关这份只给 id / 名字 / 上下文窗口 / 最大输出，没有能力标签与定价，
    所以 supportsImages 一律 False、credits 不给（不给 = 非免费，避免被
    「有免费兄弟模型」的逻辑误判）。
    """
    out = []
    for raw in models or []:
        mid = str(raw.get("model_id") or "").strip()
        if not mid:
            continue
        try:
            ctx = int(raw.get("context_window") or 0)
        except (TypeError, ValueError):
            ctx = 0
        try:
            out_tokens = int(raw.get("max_tokens") or 0)
        except (TypeError, ValueError):
            out_tokens = 0
        out.append({
            "id": mid,
            "name": str(raw.get("model_name") or mid),
            "maxInputTokens": ctx,
            "maxOutputTokens": out_tokens,
            "contextWindow": ctx,
            "maxAllowedSize": ctx,
            "supportsImages": False,
            "supportsReasoning": True,
            "supportsToolCall": True,
        })
    return out


# ---------------------------------------------------------------------------
# 推理入口（实测确认）
# ---------------------------------------------------------------------------
#
# 注意别和上面的 GATEWAY_HOST 搞混——那是**权益**网关（免费额度 / claim / config），
# 推理走的是另一个基址。扩展里拼的是 `${agentChatDomain}/api/v2/`，
# 而 agentChatDomain 在 prod 下就是 snap-engine 那台主机。
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
CHAT_MODELS = ("deepseek-v4.1-flash",
               "GLM-5.2", "Qwen3-VL-235B", "kimi-k2.6-vl",
               "openpangu-2.0-flash", "openpangu-2.0-pro",
               "glm-5.2-sft-harmony")


# ---------------------------------------------------------------------------
# 模型清单：限时福利 + 内置
# ---------------------------------------------------------------------------
#
# 客户端 UI 里模型分两组显示，网关必须同时覆盖 —— 之前只取「限时福利」那一组，
# 面板上会缺掉整个「内置」。两组来自两个接口、形状完全不同：
#
#   限时福利  权益网关 /api/v1/gateway/config      —— 给 id / 名字 / 上下文 / 最大输出
#   内置      PromptCenter /v1/model/builtin      —— 给 id / 名字 / 分类 / 多模态标记 /
#                                                   计费档（含 UI 上那个 0.7x 倍率）
#
# 曾经把内置这一组判成「IDE 聊天目录、不是网关推理目录」直接排除，那是错的：
# 实测 7 个内置模型在推理入口**全部真的能跑通**（GLM-5.2 返回真实回复、多模态
# Qwen3-VL-235B 能真的读图）。唯一例外是 `glm-5.3`：它在推理入口稳定 400 且响应体
# 为空 —— 内置的 glm-5.3 与限时福利的 glm-5.3-flash 是两个不同的东西，别混。
#
# 一条容易踩的口径：`model_id` 与 `model_name` 不一致。界面显示的是 **model_name**
# （如 glm-5.2-sft-harmony 显示成「GLM-5.2-ArkTS-SPARK」），而请求要发的是
# **model_id**。归一时两者都要留。

BUILTIN_MODELS_PATH = "/v1/model/builtin"

#: PromptCenter 所在的主机，与推理入口同一台（agentChatDomain 在 prod 下就是它）
SNAP_HOST = CHAT_HOST

#: 推理入口实测不可路由的内置模型（原因见上）。保留在清单里但标成不可用，
#: 这样面板能看到「服务端报了它、但打不通」，而不是让它静默消失。
BUILTIN_UNROUTABLE = {"glm-5.3"}

#: UI 的两分组，与客户端侧一致。
GROUP_BENEFIT = "benefit"
GROUP_BUILTIN = "builtin"
MODEL_GROUPS = (GROUP_BENEFIT, GROUP_BUILTIN)


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


def normalize_builtin(raw_list):
    """内置模型 → 网关内部统一的模型对象形状。

    与 ``normalize_models`` 的区别是这里有真实的能力标签与计费信息：
    ``supportsImages`` 取服务端的 ``supports_images``（实测多模态那三个确实能读图），
    计费倍率原样带出，供面板显示 0.7x 之类。
    """
    out = []
    for raw in raw_list or []:
        mid = str(raw.get("model_id") or "").strip()
        if not mid:
            continue
        ratio, in_price, out_price = _credit_tier(raw)
        out.append({
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
            # 服务端没给上下文窗口，两组模型里只有限时福利那份有
            "maxInputTokens": 0,
            "maxOutputTokens": 0,
            "supportsReasoning": True,
            "supportsToolCall": True,
        })
    return out


def model_catalog(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """两组模型合到一份清单里，限时福利在前、内置按服务端顺序。

    任何一组取数失败都不让整份清单失败 —— 面板显示能拿到的那组，并在
    ``errors`` 里说明缺了哪组。模型目录是展示性功能，为它整体挂掉不划算。
    """
    groups = {GROUP_BENEFIT: [], GROUP_BUILTIN: []}
    errors = {}

    try:
        cfg = gateway_config(access_key, secret_key, security_token, timeout=timeout)
        benefit = normalize_models(cfg.get("models") or [])
        for item in benefit:
            item["group"] = GROUP_BENEFIT
        groups[GROUP_BENEFIT] = benefit
    except Exception as exc:
        errors[GROUP_BENEFIT] = str(exc)

    try:
        groups[GROUP_BUILTIN] = normalize_builtin(
            builtin_models(access_key, secret_key, security_token, timeout=timeout))
    except Exception as exc:
        errors[GROUP_BUILTIN] = str(exc)

    return {"models": groups[GROUP_BENEFIT] + groups[GROUP_BUILTIN],
            "groups": groups, "errors": errors}


def chat_headers(access_key, secret_key, security_token, payload_hash,
                 stream=False):
    """推理请求头：与网关配置同一套签名，只是多一个 Accept。"""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
        "Accept": "text/event-stream" if stream else "application/json",
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    return aksk_sign(access_key, secret_key, "POST", CHAT_PATH, {}, headers,
                     payload_hash=payload_hash)


# ---------------------------------------------------------------------------
# 每日福利领取
# ---------------------------------------------------------------------------
#
# 这就是码道客户端「限时福利 → 每日领取」的落点，也是「签到」在码道这边
# 的对应物：每个账号每天可以领一份当日有效的推理额度（实测 daily_token_limit
# 为 1000 万 token，0 点清零、不累计）。领取接口本身**幂等** —— 同一天重复调
# 都返回 error_code 0000，不会叠加额度，所以不需要客户端自己去重；「今天领没领」
# 要靠余额接口的发放时间来判断，见 balance_summary。
#
# 端点取自 vscode-codebot/out/extension.js 的 Uce()：
#   非 gamma 版（isGammaVersion=false，普通用户走这条）
#     claim   = opengw.developer.huaweicloud.com/api/v1/benefit/claim
#     balance = opengw.developer.huaweicloud.com/api/v1/user/tokens/balance
#   gamma 版则是 snapengine-apig.cn-north-7.myhuaweicloud.com 下的同名路径，
#   且**必须**额外带 x-auth-token（普通版走 AK/SK 签名，不需要那个头）。
#
# 注意两件事，都实测踩过：
#   1. 成功判据是 error_code == "0000"，不是 HTTP 状态码 —— 服务端全程 200，
#      业务失败也回 200，判 status 会把失败当成功。
#   2. POST 同路径是 enableBenefitClaim（开启领取开关），**不是领取**，别混用。

BENEFIT_CLAIM_PATH = "/api/v1/benefit/claim"
TOKENS_BALANCE_PATH = "/api/v1/user/tokens/balance"


def credit_headers(access_key, secret_key, security_token, path, method="GET",
                   body=None):
    """权益接口（领取 / 余额）的请求头。

    POST 时 body 会参与签名：payload hash 必须算进 body 的 SHA-256。漏掉这一项
    报的是 APIG.0301「verify ak sk signature fail」，看起来像 AK/SK 错了，实际
    是签名串里少了 payload hash。
    """
    url = GATEWAY_HOST + path
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": GATEWAY_USER_AGENT,
        "x-snap-traceid": secrets.token_hex(16),
    }
    if security_token:
        headers["X-Security-Token"] = security_token
    return aksk_sign(access_key, secret_key, method, url, {}, headers,
                     payload_hash=hashlib.sha256(payload).hexdigest())


def claim_benefit(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """领取当日额度。

    返回 {"ok": bool, "msg": str, "user_name": str, "raw": dict}。
    幂等：当天已领过也返回 ok=True，所以这里的 ok 只说明「领取动作被接受」，
    至于额度有没有涨，要用 balance_summary 交叉核对。
    """
    headers = credit_headers(access_key, secret_key, security_token,
                             BENEFIT_CLAIM_PATH, "GET")
    payload = _http("GET", GATEWAY_HOST + BENEFIT_CLAIM_PATH, headers=headers,
                    timeout=timeout)
    # _http 已经在 error_code 非空时报错；能走到这里就是业务成功
    result = payload.get("result") or {}
    return {
        "ok": True,
        "msg": payload.get("error_msg") or "ok",
        "user_name": result.get("user_name") or "",
        "domain_id": result.get("domain_id") or "",
        "raw": result,
    }


def enable_benefit_claim(access_key, secret_key, security_token,
                         timeout=DEFAULT_TIMEOUT):
    """开启「登录后自动领取」的开关（客户端点「开启领取」时调的那个）。"""
    headers = credit_headers(access_key, secret_key, security_token,
                             BENEFIT_CLAIM_PATH, "POST", body={})
    payload = _http("POST", GATEWAY_HOST + BENEFIT_CLAIM_PATH, headers=headers,
                    body=b"{}", timeout=timeout)
    return {"ok": True, "msg": payload.get("error_msg") or "ok",
            "raw": payload.get("result") or {}}


def tokens_balance(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT):
    """额度余额（只读）。返回服务端 result 原样。"""
    headers = credit_headers(access_key, secret_key, security_token,
                             TOKENS_BALANCE_PATH, "GET")
    payload = _http("GET", GATEWAY_HOST + TOKENS_BALANCE_PATH, headers=headers,
                    timeout=timeout)
    return payload.get("result") or {}


def _ms_to_iso(value):
    if not value:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(value) / 1000))
    except (TypeError, ValueError, OSError):
        return ""


def balance_summary(access_key, secret_key, security_token,
                    timeout=DEFAULT_TIMEOUT):
    """余额 → 面板直接显示的形状。

    ``updated_at`` 来自服务端的 update_time。它在连续领取时**不刷新**（实测是
    账号开通那一刻的时间），所以只作展示，不能拿它判「今天领没领」—— 判据见
    claim_and_verify 的 ``_is_full``。
    """
    result = tokens_balance(access_key, secret_key, security_token, timeout=timeout)
    stamp = _ms_to_iso(result.get("update_time"))
    limit = result.get("daily_token_limit") or 0
    total = result.get("total_balance") or 0
    used_today = result.get("daily_tokens_used") or 0
    return {
        "channel": result.get("channel") or "",
        "user_name": result.get("user_name") or "",
        "domain_id": result.get("domain_id") or "",
        "daily_limit": limit,
        "total_balance": total,
        "used_today": used_today,
        "remaining": max(0, limit - used_today) if limit else 0,
        # expire_time 为 0 表示「当日有效、0 点清零」，不是一个具体时刻
        "expires_at_today": result.get("expire_time") == 0,
        "updated_at": stamp,
        "used_percent": round(100.0 * used_today / limit, 2) if limit else None,
    }


def _is_full(balance):
    """额度是否已经满额且今日未动过 —— 也就是「今天的已经领了」。"""
    limit = balance.get("daily_limit") or 0
    return bool(limit) and balance.get("total_balance") >= limit \
        and not (balance.get("used_today") or 0)


def record_claim(session, result, trigger="unknown"):
    """把一次领取尝试记进活动历史，形状与旧的 WorkBuddy 签到一致。

    会话不是 Account 实例，所以这里自己拼那几项而不是复用
    wb_activity.record_attempt（那个按属性取值，码道会话的属性名对不上）。
    写失败不会改变领取结论 —— 记录只是审计，不是控制流。
    """
    try:
        import wb_activity
        account = session.get("account") or {}
        balance = (result or {}).get("balance") or {}
        ok = bool((result or {}).get("ok"))
        message = ((result or {}).get("msg") or ("成功" if ok else "失败"))
        if balance.get("total_balance") is not None:
            message = "%s（余额 %s / %s）" % (
                message, balance.get("total_balance"), balance.get("daily_limit"))
        return wb_activity.record(
            uid=account.get("id") or "",
            nickname=account.get("label") or "",
            realm="cn",
            task=wb_activity.TASK_CHECKIN,
            trigger=trigger,
            ok=ok,
            message=message)
    except Exception:
        return None


def claim_and_verify(access_key, secret_key, security_token, timeout=DEFAULT_TIMEOUT,
                     session=None, trigger="unknown"):
    """领取 → 回查余额，返回一条可直接落进活动历史的记录。

    「今天领没领」的判据是**余额是否满额**，不是服务端的时间戳：实测 update_time
    在连续领取的情况下并不刷新（账号开通后一直是同一个值），拿它当判据会把
    「今天还没领」误判成「已领」，于是永远领不到。满额（余额 == 每日上限且今日
    消耗为 0）就意味着今天的额度已在手上且还没动过，重复领取是空操作。

    给了 session 就顺手写一行活动历史（trigger 沿用旧的 scheduler / manual
    口径），没给就不写 —— 这样纯单元测试不必准备历史目录。
    """
    before = balance_summary(access_key, secret_key, security_token,
                             timeout=timeout)
    if _is_full(before):
        result = {"ok": True, "skipped": True,
                  "msg": "今日已领取（余额 %s / %s，未消耗）" % (
                      before["total_balance"], before["daily_limit"]),
                  "balance": before}
    else:
        try:
            claimed = claim_benefit(access_key, secret_key, security_token,
                                    timeout=timeout)
        except Exception as exc:
            # 上游抛错也要留一行：否则「今天没领到」在历史里是空白，
            # 事后分不清是没跑还是跑了但失败。
            result = {"ok": False, "skipped": False, "msg": "领取失败: %s" % exc}
            if session is not None:
                record_claim(session, result, trigger=trigger)
            raise
        after = balance_summary(access_key, secret_key, security_token,
                               timeout=timeout)
        result = {
            "ok": True,
            "skipped": False,
            "msg": "%s，余额 %s → %s（今日已用 %s）" % (
                claimed["msg"], before["total_balance"], after["total_balance"],
                after["used_today"]),
            "grew": after["total_balance"] > before["total_balance"],
            "user_name": claimed.get("user_name") or after.get("user_name") or "",
            "balance": after,
        }
    if session is not None:
        record_claim(session, result, trigger=trigger)
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
    """原子落盘。返回文件路径。"""
    directory = session_dir(accounts_dir)
    os.makedirs(directory, exist_ok=True)
    account_id = (session.get("account") or {}).get("id") or "unknown"
    target = path or session_path(accounts_dir, account_id)
    tmp = "%s.%d.%d.tmp" % (target, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(session, fh, ensure_ascii=False, indent=2)
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


def refresh_session(accounts_dir, account_id):
    """用存档里的 DPoP 私钥 + refresh_token 续一次 STS，并覆盖存档。

    注意：refresh_token 是**一次性轮换**的，换成功会拿到新的 refresh_token。
    换失败（1806）说明被别的客户端用掉了或已过期，只能重新走浏览器登录。
    """
    sessions = {((s.get("account") or {}).get("id")): s for s in load_sessions(accounts_dir)}
    session = sessions.get(account_id)
    if not session:
        raise CodeArtsError("找不到该码道账号的存档")
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
    save_session(accounts_dir, renewed)
    return renewed


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
        """回调不带 state，只能按「唯一 pending」定位。"""
        with self._lock:
            live = [r for r in self._pending.values() if r["status"] == "pending"]
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
                "account": record.get("account"),
            }
        if snapshot["account"]:
            snapshot["summary"] = summarize(snapshot["account"])
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


def callback_page(ok, title, detail):
    """回调落地页。浏览器里直接看到，所以要写成人话。"""
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
</div></body></html>""" % (title, color, icon, title, detail or "", hint)


# -*- coding: utf-8 -*-
"""码道测试的共享夹具：确定性密钥对 / PKCE / 罐装 IAM 响应 / 换码桩。

2026-10-24 自 _test_codearts.py 按域拆分时落位：session / models /
billing 三个套件都要这组夹具，但套件之间不互相 import（各自由
run_all 起独立进程），所以共享物住在这里。数值是金标准样本 ——
改了就等于改了被钉住的行为。
"""
import json

import ca_codearts as C

_key = C.generate_keypair()
_pkce = C.generate_pkce()
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

SESSION = C.session_from_iam_response(RESPONSE, _key, _pkce)

SEEN = {"exchanges": 0, "fail": None}


def _stub_exchange(key, code, pkce, port):
    SEEN["exchanges"] += 1
    SEEN["port"] = port
    SEEN["code"] = code
    if SEEN["fail"]:
        raise C.CodeArtsError(SEEN["fail"], code="STS5.1806")
    return RESPONSE



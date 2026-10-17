"""区域归属：桌面凭据、手动导入的 JSON 与账号文件都只能落到国内版。

    python tests/_test_desktop_realm.py

背景一：国内版出口换过几轮（copilot.tencent.com → codebuddy.cn → workbuddy.cn），
旧识别只认前两个，于是 workbuddy.cn 的国内账号被判成国际版。

背景二：国际版（www.workbuddy.ai / ~/.workbuddy-ai）已整体删除。本版本只剩
一个出口，所以「认不出来」不再有第二个去处——任何来源的区域（老账号文件里写的
intl、桌面凭据文件名里的 -ai、导入行里的过期字段、接口上显式传的 intl）都必须
归一到 cn。这条是数据迁移的底线：漏一处，那个账号就会从池子里消失，而列表里
还看得见它。
"""
import base64
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import wb_accounts as A  # noqa: E402

CN_ISS = "https://www.workbuddy.cn/auth/realms/copilot"
CN_ISS_LEGACY = "https://www.codebuddy.cn/auth/realms/copilot"
CN_ISS_TENCENT = "https://copilot.tencent.com/auth/realms/copilot"
INTL_ISS = "https://www.workbuddy.ai/auth/realms/copilot"


def jwt(iss, sub="u-1"):
    def part(obj):
        raw = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")
        return raw.rstrip("=")
    return "%s.%s.sig" % (part({"alg": "RS256", "typ": "JWT"}),
                          part({"iss": iss, "sub": sub, "exp": 4102444800}))


CN_TOKEN = jwt(CN_ISS)
CN_TOKEN_LEGACY = jwt(CN_ISS_LEGACY)
CN_TOKEN_TENCENT = jwt(CN_ISS_TENCENT)
INTL_TOKEN = jwt(INTL_ISS)
OPAQUE_TOKEN = jwt("https://example.invalid/realms/x")   # 看不出区域


class RealmEvidenceTests(unittest.TestCase):
    def test_cn_markers(self):
        for token, domain in ((CN_TOKEN, ""), (CN_TOKEN_LEGACY, ""), (CN_TOKEN_TENCENT, ""),
                              (OPAQUE_TOKEN, "www.workbuddy.cn"),
                              (OPAQUE_TOKEN, "copilot.tencent.com"),
                              (OPAQUE_TOKEN, "www.codebuddy.cn")):
            self.assertEqual(A.realm_evidence(token, domain), "cn",
                             "should read as CN: %s / %s" % (token[-8:], domain))

    def test_the_removed_realm_has_no_markers_left(self):
        """国际版那一串域名不再被认出来——它的标记集合已随区域删除。"""
        self.assertIsNone(A.realm_evidence(INTL_TOKEN, ""))
        self.assertIsNone(A.realm_evidence(OPAQUE_TOKEN, "www.workbuddy.ai"))

    def test_unknown_is_none(self):
        """看不出区域要老实返回 None，由上层决定怎么兜底。"""
        self.assertIsNone(A.realm_evidence(OPAQUE_TOKEN, ""))
        self.assertIsNone(A.realm_evidence("", ""))

    def test_detect_realm_defaults_to_cn(self):
        """对外的 detect_realm_from_token：认不出来就归国内版（唯一出口）。"""
        self.assertEqual(A.detect_realm_from_token(OPAQUE_TOKEN), "cn")
        self.assertEqual(A.detect_realm_from_token(INTL_TOKEN), "cn")
        self.assertEqual(A.detect_realm_from_token(CN_TOKEN), "cn")

    def test_workbuddy_cn_is_not_confused(self):
        self.assertEqual(A.realm_evidence(OPAQUE_TOKEN, "www.workbuddy.cn"), "cn")


class NormaliseTests(unittest.TestCase):
    def test_every_realm_spelling_collapses_to_cn(self):
        for value in ("cn", "intl", "global", "INTL", "  intl  ", "bogus", "", None):
            self.assertEqual(A.normalize_realm(value), "cn", repr(value))

    def test_match_realm_keeps_the_no_filter_case(self):
        for value in (None, ""):
            self.assertIsNone(A.match_realm(value), repr(value))
        # "all" 是「不过滤」的哨兵，原样留给调用方判断，不是转成 cn。
        self.assertEqual(A.match_realm("all"), "all")
        for value in ("intl", "bogus", "cn"):
            self.assertEqual(A.match_realm(value), "cn", repr(value))

    def test_realm_config_only_knows_cn(self):
        self.assertEqual(A.KNOWN_REALMS, ("cn",))
        self.assertEqual(A.get_realm_config("intl")["domain"],
                         A.get_realm_config("cn")["domain"])


class DesktopRealmTests(unittest.TestCase):
    """桌面凭据：token 说了算，文件名只兜底。"""

    def test_token_wins_over_filename(self):
        # 国内账号登录在国际版那套客户端里（切区登录），文件名叫 -ai.info
        self.assertEqual(A.desktop_effective_realm("intl", CN_TOKEN, "www.workbuddy.cn"), "cn")
        # 反过来：国际版签发的 token 也只是「认不出来」，照样归国内版。
        self.assertEqual(A.desktop_effective_realm("cn", INTL_TOKEN, "www.workbuddy.ai"), "cn")

    def test_filename_hint_collapses_to_cn(self):
        self.assertEqual(A.desktop_effective_realm("cn", OPAQUE_TOKEN), "cn")
        self.assertEqual(A.desktop_effective_realm("intl", OPAQUE_TOKEN), "cn")

    def test_unknown_hint_is_cn(self):
        self.assertEqual(A.desktop_effective_realm(None, OPAQUE_TOKEN), "cn")


class ImportRowRealmTests(unittest.TestCase):
    """手动导入 JSON：区域同样只能落到国内版。"""

    def row(self, token, **extra):
        row = {"uid": "u-1", "accessToken": token, "refreshToken": "r.r.r"}
        row.update(extra)
        return A.normalise_import_row(row)

    def test_cn_account_with_workbuddy_cn_domain(self):
        """报的那个 bug：域名是 workbuddy.cn 的国内账号不能再被判成国际版。"""
        self.assertEqual(self.row(OPAQUE_TOKEN, domain="www.workbuddy.cn")["realm"], "cn")

    def test_stale_realm_field_does_not_win(self):
        """行里带着过期的 realm（当初就存错了）时，按 token 纠正回来。"""
        out = self.row(CN_TOKEN, realm="intl", domain="www.workbuddy.cn")
        self.assertEqual(out["realm"], "cn")

    def test_intl_row_collapses_to_cn(self):
        out = self.row(INTL_TOKEN, domain="www.workbuddy.ai")
        self.assertEqual(out["realm"], "cn")

    def test_row_without_domain_uses_issuer(self):
        self.assertEqual(self.row(CN_TOKEN)["realm"], "cn")
        self.assertEqual(self.row(INTL_TOKEN)["realm"], "cn")

    def test_forced_realm_collapses_to_cn(self):
        """接口上的 realm 参数仍是显式指定，但指定的已删区域只能归一到现存出口。"""
        self.assertEqual(A.normalise_import_row(
            {"uid": "u-1", "accessToken": CN_TOKEN}, realm="intl")["realm"], "cn")

    def test_row_realm_used_when_token_is_opaque(self):
        self.assertEqual(self.row(OPAQUE_TOKEN, realm="cn")["realm"], "cn")
        self.assertEqual(self.row(OPAQUE_TOKEN, realm="intl")["realm"], "cn")
        self.assertEqual(self.row(OPAQUE_TOKEN)["realm"], "cn")

    def test_domain_follows_realm(self):
        """区域定了，X-Domain 就不能还指着别的地方。"""
        cn_domain = A.get_realm_config("cn")["domain"]
        self.assertEqual(self.row(CN_TOKEN, domain="www.workbuddy.ai")["domain"], cn_domain)
        self.assertEqual(self.row(INTL_TOKEN, domain="www.codebuddy.cn")["domain"],
                         "www.codebuddy.cn")

    def test_matching_domain_is_kept(self):
        self.assertEqual(self.row(CN_TOKEN, domain="www.codebuddy.cn")["domain"],
                         "www.codebuddy.cn")

    def test_exported_account_survives_round_trip(self):
        """导出再导入，区域不能漂移。"""
        for token in (CN_TOKEN, INTL_TOKEN):
            account = A.Account({"uid": "u-1", "accessToken": token, "refreshToken": "r.r.r"})
            self.assertEqual(account.realm, "cn")
            doc = A.build_export_document([account])
            rows, problem = A._coerce_account_rows(doc)
            self.assertEqual(problem, "")
            self.assertEqual(A.normalise_import_row(rows[0])["realm"], "cn")


class AccountRealmTests(unittest.TestCase):
    def test_account_realm_from_token(self):
        self.assertEqual(A.Account({"accessToken": CN_TOKEN}).realm, "cn")
        self.assertEqual(A.Account({"accessToken": INTL_TOKEN}).realm, "cn")

    def test_explicit_realm_in_data_collapses(self):
        """老账号文件里的 "realm": "intl" 读回来必须是 cn，否则池里找不到它。"""
        self.assertEqual(A.Account({"accessToken": CN_TOKEN, "realm": "intl"}).realm, "cn")
        self.assertEqual(A.Account({"accessToken": OPAQUE_TOKEN,
                                    "realm": "intl"}).realm, "cn")

    def test_domain_is_backfilled_from_the_only_config(self):
        account = A.Account({"accessToken": CN_TOKEN})
        self.assertEqual(account.domain, A.get_realm_config("cn")["domain"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

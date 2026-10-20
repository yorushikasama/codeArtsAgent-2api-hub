"""Web-console nickname sync (B6).

Run with: python _test_profile_sync.py
No upstream credentials or outbound network are used.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

_startup_dir = tempfile.TemporaryDirectory(prefix="profile-sync-")
os.environ["ACCOUNTS_DIR"] = _startup_dir.name
os.environ["WB_PROXY_USAGE_DIR"] = _startup_dir.name
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_accounts
import ca_proxy


class FakeResponse(object):
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FetchProfileTests(unittest.TestCase):
    def test_web_origin_is_the_china_site_for_every_realm(self):
        # 国际版删除后只剩国内版出口；已删/未知区域（老代码还会传 intl、
        # global）一律回落到国内站，而不是拿到一个不存在的站点。
        for realm in ("cn", "intl", "global", "", None, "bogus"):
            self.assertEqual(ca_accounts.web_origin_for(realm),
                             "https://www.workbuddy.cn", realm)

    def test_fetch_parses_only_uid_and_nickname(self):
        captured = {}

        def fake_urlopen(req, timeout=30, proxy=""):
            captured["url"] = req.full_url
            captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
            return FakeResponse({"uid": "uid-1", "nickname": "  New Nick  ",
                                 "phoneNumber": "+86-13800000000",
                                 "email": "secret@example.com"})

        account = ca_accounts.Account(
            {"uid": "uid-1", "accessToken": "tok", "realm": "cn"})
        old = ca_accounts.urlopen
        ca_accounts.urlopen = fake_urlopen
        try:
            uid, nickname = ca_accounts.fetch_account_profile(account)
        finally:
            ca_accounts.urlopen = old
        self.assertEqual((uid, nickname), ("uid-1", "New Nick"))
        self.assertNotIn("13800000000", str((uid, nickname)))
        self.assertEqual(captured["url"],
                         "https://www.workbuddy.cn/console/account")
        self.assertEqual(captured["headers"].get("x-client-platform"), "web")
        self.assertEqual(captured["headers"].get("authorization"), "Bearer tok")

    def test_uid_mismatch_is_rejected(self):
        def fake_urlopen(req, timeout=30, proxy=""):
            return FakeResponse({"uid": "uid-other", "nickname": "X"})

        account = ca_accounts.Account(
            {"uid": "uid-1", "accessToken": "tok", "realm": "intl"})
        old = ca_accounts.urlopen
        ca_accounts.urlopen = fake_urlopen
        try:
            with self.assertRaises(RuntimeError):
                ca_accounts.fetch_account_profile(account)
        finally:
            ca_accounts.urlopen = old

    def test_non_object_response_is_rejected(self):
        def fake_urlopen(req, timeout=30, proxy=""):
            return FakeResponse(["not", "an", "object"])

        account = ca_accounts.Account(
            {"uid": "uid-1", "accessToken": "tok", "realm": "intl"})
        old = ca_accounts.urlopen
        ca_accounts.urlopen = fake_urlopen
        try:
            with self.assertRaises(RuntimeError):
                ca_accounts.fetch_account_profile(account)
        finally:
            ca_accounts.urlopen = old


class SyncNicknameTests(unittest.TestCase):
    def test_sync_updates_and_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            account = ca_accounts.Account(
                {"uid": "uid-1", "accessToken": "tok", "realm": "cn",
                 "nickname": "Old"},
                os.path.join(directory, "uid-1.json"))
            with mock.patch.object(ca_accounts, "fetch_account_profile",
                                   return_value=("uid-1", "New Nick")):
                nickname = account.sync_nickname()
            self.assertEqual(nickname, "New Nick")
            self.assertEqual(account.nickname, "New Nick")
            with open(os.path.join(directory, "uid-1.json"), encoding="utf-8") as fh:
                stored = json.load(fh)
            self.assertEqual(stored.get("nickname"), "New Nick")


class SyncProfileRouteTests(unittest.TestCase):
    def make_handler(self):
        class Handler(ca_proxy.Handler):
            def __init__(self):
                self.captured = None

            def _json(self, code, obj):
                self.captured = (code, obj)

        return Handler()

    def make_pool(self, account):
        class Pool(object):
            accounts = [account]

            def get(self, uid):
                return account if uid == account.uid else None

            def list_public(self, realm=None):
                return [account.public()]

        return Pool()

    def test_route_reports_the_new_nickname(self):
        with tempfile.TemporaryDirectory() as directory:
            account = ca_accounts.Account(
                {"uid": "uid-1", "accessToken": "tok", "realm": "cn"},
                os.path.join(directory, "uid-1.json"))
            old_pool = ca_proxy.POOL
            ca_proxy.POOL = self.make_pool(account)
            try:
                with mock.patch.object(ca_accounts, "fetch_account_profile",
                                       return_value=("uid-1", "Fresh")):
                    handler = self.make_handler()
                    handler._route_accounts_sync_profile({"uid": "uid-1"})
            finally:
                ca_proxy.POOL = old_pool
            code, obj = handler.captured
            self.assertEqual(code, 200)
            self.assertEqual(obj["updated"][0]["nickname"], "Fresh")
            self.assertEqual(obj["failed"], [])

    def test_route_reports_failures_without_failing_the_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            account = ca_accounts.Account(
                {"uid": "uid-1", "accessToken": "tok", "realm": "cn"},
                os.path.join(directory, "uid-1.json"))
            old_pool = ca_proxy.POOL
            ca_proxy.POOL = self.make_pool(account)
            try:
                with mock.patch.object(ca_accounts, "fetch_account_profile",
                                       side_effect=RuntimeError("boom")):
                    handler = self.make_handler()
                    handler._route_accounts_sync_profile({"uid": "uid-1"})
            finally:
                ca_proxy.POOL = old_pool
            code, obj = handler.captured
            self.assertEqual(code, 200)
            self.assertEqual(obj["updated"], [])
            self.assertEqual(obj["failed"][0]["uid"], "uid-1")


if __name__ == "__main__":
    unittest.main()

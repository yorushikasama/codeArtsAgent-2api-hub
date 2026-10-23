"""The three daily guards share one grouped shape: one global value each.

The per-realm override belonged to the two-egress era and is gone; the panel
and the pool now read and write a single number per guard. Pinned here: the
grouped store, the one-time fold of the flat pre-grouping keys, the values the
pool hands each account, and the shapes /settings/save accepts. A per-realm
key in an old payload is ignored rather than resurrecting the removed scope.
No network access required.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_accounts
import ca_settings
import ca_proxy as proxy


def account(uid, realm):
    return ca_accounts.Account(
        {"uid": uid, "accessToken": "t-" + uid, "realm": realm})


class LimitStorageTests(unittest.TestCase):
    def test_the_global_value_is_the_only_scope(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.set_daily_token_limit(d, 1000)
            self.assertEqual(ca_settings.daily_token_limit(d), 1000)
            # realm is accepted for old callers and ignored.
            self.assertEqual(ca_settings.daily_token_limit(d, "cn"), 1000)
            self.assertEqual(ca_settings.daily_token_limit(d, "intl"), 1000)
            self.assertEqual(ca_settings.limit_values(d, "daily_token_limit"),
                             {"global": 1000})

    def test_snapshot_covers_every_guard(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.set_limit(d, "daily_credit_limit", "global", 5)
            ca_settings.set_limit(d, "model_daily_token_limit", "global", 7)
            snapshot = ca_settings.limits_snapshot(d)
            self.assertEqual(set(snapshot), set(ca_settings.LIMIT_KEYS))
            for key, entry in snapshot.items():
                self.assertEqual(set(entry), {"global"}, key)
            self.assertEqual(snapshot["daily_credit_limit"]["global"], 5)
            self.assertEqual(snapshot["model_daily_token_limit"]["global"], 7)

    def test_junk_and_negatives_collapse(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            stored = ca_settings.set_limit(d, "daily_token_limit", "global", "abc")
            self.assertEqual(stored["global"], 0)
            stored = ca_settings.set_limit(d, "daily_token_limit", "global", -5)
            self.assertEqual(stored["global"], 0)
            # An explicit 0 is a real "off" and stays one.
            stored = ca_settings.set_limit(d, "daily_token_limit", "global", 0)
            self.assertEqual(stored["global"], 0)
            stored = ca_settings.set_limit(d, "daily_token_limit", "global", 7)
            self.assertEqual(stored["global"], 7)

    def test_unknown_key_or_scope_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            with self.assertRaises(ValueError):
                ca_settings.set_limit(d, "nope", "global", 1)
            with self.assertRaises(ValueError):
                ca_settings.set_limit(d, "daily_token_limit", "cn", 1)

    def test_legacy_flat_keys_fold_into_limits_once(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.save(d, {
                "panel_password_hash": "x",
                "daily_token_limit": 1000,
                "daily_credit_limit": 3,
                "model_daily_token_limit": 500,
            })
            self.assertEqual(ca_settings.daily_token_limit(d), 1000)
            stored = ca_settings.load(d)
            # The flat keys are folded away, so a rollback cannot read a stale
            # number from beside the grouped copy.
            for key in ca_settings.LIMIT_KEYS:
                self.assertNotIn(key, stored)
            self.assertEqual(stored["panel_password_hash"], "x")
            self.assertEqual(stored["limits"]["daily_token_limit"]["global"], 1000)
            self.assertEqual(stored["limits"]["daily_credit_limit"]["global"], 3)
            self.assertEqual(
                stored["limits"]["model_daily_token_limit"]["global"], 500)

    def test_a_file_without_any_guard_is_not_rewritten(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.save(d, {"panel_password_hash": "x"})
            self.assertEqual(ca_settings.daily_token_limit(d), 0)
            self.assertNotIn("limits", ca_settings.load(d))

    def test_flat_setters_write_the_global_slot(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            self.assertEqual(ca_settings.set_daily_token_limit(d, 12), 12)
            self.assertEqual(ca_settings.daily_token_limit(d), 12)
            self.assertEqual(ca_settings.daily_token_limit(d, "cn"), 12)
            self.assertEqual(
                ca_settings.limits_snapshot(d)["daily_token_limit"]["global"], 12)


class LimitPoolTests(unittest.TestCase):
    def _pool(self, directory, realms):
        pool = ca_accounts.AccountPool(directory, log=lambda _m: None)
        accounts = []
        for realm in realms:
            entry = account("uid-" + (realm or "none"), realm)
            # Account() falls back to a detected realm, so pin the one this
            # case is actually about.
            entry.realm = realm
            accounts.append(entry)
        pool.accounts = accounts
        return pool

    def test_the_global_applies_to_every_realm(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.set_limit(d, "daily_token_limit", "global", 100)
            pool = self._pool(d, ["cn", "intl", ""])
            pool.apply_daily_token_limit()
            got = {a.realm: a.daily_token_limit for a in pool.accounts}
            self.assertEqual(got, {"cn": 100, "intl": 100, "": 100})

    def test_pool_still_accepts_one_number_for_everyone(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            pool = self._pool(d, ["cn"])
            pool.apply_daily_token_limit(250, {"uid-cn": 0})
            self.assertEqual({a.daily_token_limit for a in pool.accounts}, {250})

    def test_each_guard_lands_on_its_own_field(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.set_limit(d, "daily_token_limit", "global", 11)
            ca_settings.set_limit(d, "daily_credit_limit", "global", 22)
            ca_settings.set_limit(d, "model_daily_token_limit", "global", 33)
            pool = self._pool(d, ["cn"])
            pool.apply_daily_token_limit()
            pool.apply_daily_credit_limit()
            pool.apply_model_daily_token_limit()
            cn, = pool.accounts
            self.assertEqual(cn.daily_token_limit, 11)
            self.assertEqual(cn.daily_credit_limit, 22)
            self.assertEqual(cn.model_daily_token_limit, 33)

    def test_the_global_limit_parks_every_account(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.set_limit(d, "daily_token_limit", "global", 1000)
            pool = self._pool(d, ["intl", "cn"])
            pool.apply_daily_token_limit(None, {"uid-intl": 1500, "uid-cn": 1500})
            self.assertTrue(all(a.daily_limit_blocked() for a in pool.accounts))
            pool.apply_daily_token_limit(None, {"uid-intl": 100, "uid-cn": 100})
            self.assertFalse(any(a.daily_limit_blocked() for a in pool.accounts))


class SettingsSaveTests(unittest.TestCase):
    class Request(object):
        _handle_settings_save = proxy.Handler._handle_settings_save

        def __init__(self, payload):
            self.payload = payload
            self.status = None
            self.reply = None

        def _payload_or_error(self, allow_list=False):
            return self.payload

        def _error(self, status, message, kind=""):
            self.status = status
            self.reply = message
            return status, message

        def _json(self, status, payload):
            self.status = status
            self.reply = payload
            return status, payload

    def _save(self, directory, payload):
        request = self.Request(payload)
        with mock.patch.multiple(proxy, ACCOUNTS_DIR=directory, POOL=None,
                                 SCHEDULER=None, PRICING=None):
            request._handle_settings_save()
        return request

    def test_grouped_payload_round_trips(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            request = self._save(d, {"limits": {
                "daily_credit_limit": {"global": 5},
                "daily_token_limit": {"global": 1000},
            }})
            self.assertEqual(request.status, 200)
            self.assertEqual(ca_settings.daily_credit_limit(d), 5)
            self.assertEqual(ca_settings.daily_token_limit(d), 1000)
            self.assertEqual(request.reply["daily_credit_limit"], 5)
            self.assertEqual(
                request.reply["limits"]["daily_credit_limit"],
                {"global": 5})

    def test_flat_payload_still_sets_the_global(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            request = self._save(d, {"daily_credit_limit": 42})
            self.assertEqual(request.status, 200)
            self.assertEqual(ca_settings.daily_credit_limit(d), 42)
            self.assertEqual(ca_settings.daily_credit_limit(d, "cn"), 42)

    def test_a_per_realm_override_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            request = self._save(d, {"limits": {
                "daily_token_limit": {"global": 7, "cn": 3}}})
            self.assertEqual(request.status, 200)
            self.assertEqual(ca_settings.daily_token_limit(d), 7)
            self.assertEqual(ca_settings.limits_snapshot(d)["daily_token_limit"],
                             {"global": 7})

    def test_bad_values_are_refused(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            cases = [
                {"limits": []},
                {"limits": {"daily_token_limit": {"global": "abc"}}},
                {"limits": {"daily_token_limit": {"global": -1}}},
                {"limits": {"daily_token_limit": {"global": True}}},
                {"daily_token_limit": "abc"},
                {"daily_token_limit": -1},
            ]
            for payload in cases:
                request = self._save(d, payload)
                self.assertEqual(request.status, 400, payload)
            # Nothing was written by the refused payloads.
            self.assertEqual(ca_settings.daily_token_limit(d), 0)

    def test_unknown_guard_in_the_payload_is_ignored(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            request = self._save(d, {"limits": {"not_a_guard": {"global": 5}}})
            self.assertEqual(request.status, 200)
            self.assertEqual(ca_settings.daily_token_limit(d), 0)

    def test_settings_view_exposes_the_grouped_map(self):
        with tempfile.TemporaryDirectory(prefix="limits-") as d:
            ca_settings.set_limit(d, "daily_token_limit", "global", 7)
            with mock.patch.object(proxy, "ACCOUNTS_DIR", d):
                view = proxy.runtime_settings_view()
            self.assertEqual(view["limits"]["daily_token_limit"],
                             {"global": 7})
            # The flat keys stay for older panel builds; they read the global.
            self.assertEqual(view["daily_token_limit"], 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Pin the egress-level transient backoff (issue #271).

Account-level governance punishes the *account* for three consecutive hard
failures (30 minutes, doubling to 6h). When the failure is a transport blip on
the outbound path, that accounting charges every account sharing the path: the
incident behind issue #271 saw 196 `URLError`s over four hours park 13 accounts
for up to ~3h. With the switch on, transport failures and 502/503/504 are
charged to the *egress* instead - one shared counter, seconds-level backoff,
cleared by a served request - and the account's fails/degrade counters are left
alone. A 500 stays on the account (it can be a real fault tied to the
credential); 401/403/429 already have their own paths.

No network: accounts are built from dicts, the upstream call is stubbed, and
time.sleep is recorded instead of slept.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_egress
import ca_proxy
import ca_settings
import ca_upstream_pool


class EgressKeyTests(unittest.TestCase):
    """The egress identity must match the connection pool's key exactly."""

    URL = "https://www.workbuddy.ai/v2/chat/completions"

    def test_direct_is_one_shared_egress(self):
        # No proxy: every account goes out the same way, so they share a key.
        self.assertEqual(ca_upstream_pool.egress_key(self.URL, ""),
                         ("https", "www.workbuddy.ai", 443, ""))

    def test_proxy_string_is_the_identity_not_the_slot(self):
        key = ca_upstream_pool.egress_key(self.URL, "http://10.0.0.9:8080")
        self.assertEqual(key, ("https", "www.workbuddy.ai", 443,
                               "http://10.0.0.9:8080"))

    def test_two_slots_pointing_at_one_address_share_a_bucket(self):
        # Two slots with the same address must not be split into two counters.
        self.assertEqual(
            ca_upstream_pool.egress_key(self.URL, "http://10.0.0.9:8080"),
            ca_upstream_pool.egress_key(self.URL, " http://10.0.0.9:8080 "))

    def test_bypassed_proxy_folds_to_direct(self):
        # The pool folds a system-bypassed proxy back to direct; accounting must
        # fold it the same way or one physical path becomes two counters.
        with mock.patch.object(ca_upstream_pool, "_proxy_bypassed",
                               return_value=True):
            key = ca_upstream_pool.egress_key(self.URL, "http://10.0.0.9:8080")
        self.assertEqual(key, ("https", "www.workbuddy.ai", 443, ""))

    def test_non_http_proxy_keeps_its_own_identity(self):
        # socks5 does not go through the pool, but it is still a distinct egress.
        key = ca_upstream_pool.egress_key(self.URL, "socks5://10.0.0.9:1080")
        self.assertEqual(key[3], "socks5://10.0.0.9:1080")


class EgressBackoffTests(unittest.TestCase):
    """The seconds-level ladder and the shared counter."""

    def setUp(self):
        ca_egress.reset()

    def test_ladder_is_seconds_and_capped(self):
        self.assertEqual(ca_egress.transient_backoff(1), 1.0)
        self.assertEqual(ca_egress.transient_backoff(2), 2.0)
        self.assertEqual(ca_egress.transient_backoff(3), 4.0)
        self.assertEqual(ca_egress.transient_backoff(9),
                         ca_egress.EGRESS_BACKOFF_MAX)

    def test_backoff_stays_in_the_seconds_range(self):
        # 账号级熔断（30 分钟起）随账号池一起删掉了；这条仍要钉住尺度：
        # 出口退避必须停留在秒级，封顶不能滑到分钟级。
        self.assertLessEqual(ca_egress.EGRESS_BACKOFF_MAX, 60.0)
        self.assertGreaterEqual(ca_egress.EGRESS_BACKOFF_BASE, 0.5)

    def test_note_transient_grows_one_shared_counter(self):
        key = ("https", "www.workbuddy.ai", 443, "")
        first = ca_egress.note_transient(key)
        second = ca_egress.note_transient(key)
        self.assertEqual(ca_egress.streak(key), 2)
        # Jitter keeps the two apart, but the ladder underneath must have grown.
        self.assertGreaterEqual(first, 1.0 * ca_egress.EGRESS_JITTER_LOW)
        self.assertLessEqual(first, 1.0 * ca_egress.EGRESS_JITTER_HIGH)
        self.assertGreaterEqual(second, 2.0 * ca_egress.EGRESS_JITTER_LOW)
        self.assertLessEqual(second, 2.0 * ca_egress.EGRESS_JITTER_HIGH)

    def test_success_clears_the_streak(self):
        key = ("https", "www.workbuddy.ai", 443, "")
        ca_egress.note_transient(key)
        ca_egress.note_transient(key)
        self.assertEqual(ca_egress.streak(key), 2)
        ca_egress.note_success(key)
        self.assertEqual(ca_egress.streak(key), 0)
        # ...and the ladder restarts at its base, not at the old rung.
        wait = ca_egress.note_transient(key)
        self.assertLessEqual(wait, 1.0 * ca_egress.EGRESS_JITTER_HIGH)

    def test_quiet_window_starts_a_new_ladder(self):
        key = ("https", "www.workbuddy.ai", 443, "")
        now = 1000.0
        ca_egress.note_transient(key, now=now)
        ca_egress.note_transient(key, now=now + 1)
        self.assertEqual(ca_egress.streak(key, now=now + 1), 2)
        later = now + ca_egress.EGRESS_STREAK_RESET + 5
        self.assertEqual(ca_egress.streak(key, now=later), 0)


if __name__ == "__main__":
    unittest.main()

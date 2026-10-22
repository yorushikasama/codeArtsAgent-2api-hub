"""Once the panel holds keys, it is the only source of /v1 credentials.

The launcher key (--api-key / .credentials API_KEY) exists for deployments
whose panel was never configured - a headless box started from a script. It is
a fallback, not a second credential: while the panel manages keys, a key left
in an old launcher file must not keep working after the panel was locked down.

The dangerous edge is the last key being deleted. `configured_keys()` then
returns nothing, which used to read as "no keys, auth off" and turned the
gateway into an open relay that also spent the accounts' quota. These cases pin
the fail-closed rule: any stored row - enabled, disabled, or soft-deleted -
keeps auth on, and deleting the last row does not revive the launcher key.
Turning checking off stays the explicit `auth_disabled` switch.

No network access required.

    python tests/_test_auth_required.py
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_proxy as proxy
import ca_settings as S

LAUNCHER_KEY = "launcher-key"
PANEL_KEY = "panel-key"


class AuthSourceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wb-authreq-")
        proxy.ACCOUNTS_DIR = self.dir
        proxy.API_KEY = None
        proxy.API_KEY_FILE_SET = False

    def save(self, data):
        S.save(self.dir, data)

    # [1] fresh install, nothing configured
    def test_fresh_install_is_open(self):
        self.assertFalse(proxy.auth_required())
        self.assertIsNone(proxy.identify_key("anything"))

    # [2] headless deployment: launcher key, panel never configured
    def test_launcher_key_auths_fresh_install(self):
        proxy.API_KEY = LAUNCHER_KEY
        self.assertTrue(proxy.auth_required())
        entry = proxy.identify_key(LAUNCHER_KEY)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["source"], "launcher")
        self.assertIsNone(proxy.identify_key("wrong"))

    # [3] panel key wins; launcher key is not a second credential
    def test_panel_key_replaces_launcher_key(self):
        S.set_api_keys(self.dir, [{"name": "panel", "key": PANEL_KEY,
                                   "enabled": True}])
        proxy.API_KEY = LAUNCHER_KEY
        self.assertTrue(proxy.auth_required())
        entry = proxy.identify_key(PANEL_KEY)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["source"], "panel")
        self.assertIsNone(proxy.identify_key(LAUNCHER_KEY))

    # [4] a disabled row still switches checking on, but matches nothing
    def test_disabled_key_keeps_auth_on(self):
        S.set_api_keys(self.dir, [{"name": "panel", "key": PANEL_KEY,
                                   "enabled": False}])
        proxy.API_KEY = LAUNCHER_KEY
        self.assertTrue(proxy.auth_required())
        self.assertIsNone(proxy.identify_key(PANEL_KEY))
        self.assertIsNone(proxy.identify_key(LAUNCHER_KEY))

    # [5] deleting the last key must fail closed, not fall back to the launcher
    def test_deleted_last_key_does_not_revive_launcher(self):
        S.set_api_keys(self.dir, [{"name": "panel", "key": PANEL_KEY,
                                   "enabled": True}])
        S.set_api_keys(self.dir, [])  # replace semantics: retire every row
        proxy.API_KEY = LAUNCHER_KEY
        self.assertTrue(proxy.auth_required())
        self.assertIsNone(proxy.identify_key(LAUNCHER_KEY))
        self.assertIsNone(proxy.identify_key(PANEL_KEY))

    # [6] the same holds for a settings file from an older build
    def test_legacy_single_key_counts_as_panel_managed(self):
        self.save({"api_key_set": True, "api_key": PANEL_KEY})
        proxy.API_KEY = LAUNCHER_KEY
        self.assertTrue(proxy.auth_required())
        entry = proxy.identify_key(PANEL_KEY)
        self.assertIsNotNone(entry)
        self.assertIsNone(proxy.identify_key(LAUNCHER_KEY))

    # [7] an explicit off switch is still the only way to open the gateway
    def test_auth_disabled_switch_still_opens(self):
        S.set_api_keys(self.dir, [{"name": "panel", "key": PANEL_KEY,
                                   "enabled": True}])
        data = S.load(self.dir)
        data["auth_disabled"] = True
        self.save(data)
        self.assertFalse(proxy.auth_required())


if __name__ == "__main__":
    unittest.main(verbosity=2)

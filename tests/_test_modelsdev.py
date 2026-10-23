"""Model metadata lookup chain (M5 E1) and cache alias normalization (E3).

Run with: python _test_modelsdev.py
No upstream credentials or outbound network are used (models.dev is stubbed).
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

_startup_dir = tempfile.TemporaryDirectory(prefix="modelsdev-")
os.environ["ACCOUNTS_DIR"] = _startup_dir.name
os.environ["WB_PROXY_USAGE_DIR"] = _startup_dir.name
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_modelsdev
import ca_proxy


class FakeResponse(object):
    def __init__(self, payload):
        self.payload = payload

    def read(self, limit=None):
        return self.payload[:limit] if limit else self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def reset_module():
    with ca_modelsdev._lock:
        ca_modelsdev._index = None
        ca_modelsdev._index_loaded = False
        ca_modelsdev._last_fetch = 0.0
        ca_modelsdev._fetching = False


class KnowledgeTableTests(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(ca_modelsdev.CONTEXT_FALLBACK["glm-5.2"], (1000000, 131072))
        self.assertEqual(ca_modelsdev.CONTEXT_FALLBACK["auto"], (168000, 0))
        self.assertEqual(ca_modelsdev.DEFAULT_CONTEXT, 1000000)


class BuildIndexTests(unittest.TestCase):
    def test_vendor_beats_aggregator(self):
        doc = {
            "zai": {"models": {"glm-5.2": {"limit": {"context": 1000000, "output": 131072}}}},
            "some-gateway": {"models": {"glm-5.2": {"limit": {"context": 200000, "output": 65536}}}},
        }
        index = ca_modelsdev.build_index(doc)
        self.assertEqual(index["glm-5.2"], (1000000, 131072))

    def test_majority_wins_without_a_vendor(self):
        doc = {
            "gateway-a": {"models": {"m1": {"limit": {"context": 100, "output": 10}}}},
            "gateway-b": {"models": {"m1": {"limit": {"context": 100, "output": 10}}}},
            "gateway-c": {"models": {"m1": {"limit": {"context": 200, "output": 20}}}},
        }
        self.assertEqual(ca_modelsdev.build_index(doc)["m1"], (100, 10))

    def test_namespaced_ids_use_the_bare_tail(self):
        doc = {"openai": {"models": {"openai/gpt-5.5": {
            "limit": {"context": 1050000, "output": 128000}}}}}
        self.assertEqual(ca_modelsdev.build_index(doc)["gpt-5.5"], (1050000, 128000))

    def test_invalid_values_are_dropped(self):
        doc = {"p": {"models": {
            "bad": {"limit": {"context": 0, "output": 0}},
            "huge": {"limit": {"context": 10 ** 12, "output": 1}},
            "ok": {"limit": {"context": 1000, "output": 100}},
        }}}
        index = ca_modelsdev.build_index(doc)
        self.assertNotIn("bad", index)
        self.assertNotIn("huge", index)
        self.assertEqual(index["ok"], (1000, 100))


class LocalCacheTests(unittest.TestCase):
    def setUp(self):
        reset_module()

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_modelsdev.save_index(directory, {"m1": (1000, 100)})
            index = ca_modelsdev.load_index(directory, force=True)
        self.assertEqual(index["m1"], (1000, 100))

    def test_corrupt_cache_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(ca_modelsdev.cache_path(directory), "w", encoding="utf-8") as fh:
                fh.write("{not json")
            index = ca_modelsdev.load_index(directory, force=True)
        self.assertEqual(index, {})


class LookupTests(unittest.TestCase):
    def setUp(self):
        reset_module()

    def test_remote_wins(self):
        context, output, source = ca_modelsdev.lookup(
            "glm-5.2", 555, 55, directory=tempfile.gettempdir())
        self.assertEqual((context, output), (555, 55))
        self.assertEqual(source["context"], "remote")

    def test_table_beats_cache_and_default(self):
        context, output, source = ca_modelsdev.lookup(
            "glm-5.2", 0, 0, directory=tempfile.gettempdir(),
            index={"glm-5.2": (123, 12)})
        self.assertEqual((context, output), (1000000, 131072))
        self.assertEqual(source["context"], "table")

    def test_cache_used_when_table_misses(self):
        context, output, source = ca_modelsdev.lookup(
            "some-new-model", 0, 0, directory=tempfile.gettempdir(),
            index={"some-new-model": (777, 77)})
        self.assertEqual((context, output), (777, 77))
        self.assertEqual(source["context"], "cache")

    def test_unknown_model_defaults_to_1m_and_no_output(self):
        context, output, source = ca_modelsdev.lookup(
            "totally-unknown", 0, 0, directory=tempfile.gettempdir(), index={})
        self.assertEqual(context, 1000000)
        self.assertIsNone(output)
        self.assertEqual(source["output"], "unknown")

    def test_unknown_output_is_omitted_even_with_context(self):
        context, output, _source = ca_modelsdev.lookup(
            "auto", 0, 0, directory=tempfile.gettempdir(), index={})
        self.assertEqual(context, 168000)
        self.assertIsNone(output)


class RefreshTests(unittest.TestCase):
    def setUp(self):
        reset_module()

    def test_refresh_writes_the_cache(self):
        doc = {"zai": {"models": {"glm-5.2": {
            "limit": {"context": 1000000, "output": 131072}}}}}
        payload = json.dumps(doc).encode("utf-8")

        def fake_urlopen(req, timeout=5):
            return FakeResponse(payload)

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(ca_modelsdev.urllib.request, "urlopen",
                                   side_effect=fake_urlopen):
                started = ca_modelsdev.refresh_async(directory)
                deadline = time.time() + 5
                while time.time() < deadline:
                    with ca_modelsdev._lock:
                        if not ca_modelsdev._fetching:
                            break
                    time.sleep(0.02)
            self.assertTrue(started)
            index = ca_modelsdev.load_index(directory, force=True)
        self.assertEqual(index["glm-5.2"], (1000000, 131072))

    def test_offline_refresh_is_silent(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(ca_modelsdev.urllib.request, "urlopen",
                                   side_effect=OSError("offline")):
                ca_modelsdev.refresh_async(directory)
                deadline = time.time() + 5
                while time.time() < deadline:
                    with ca_modelsdev._lock:
                        if not ca_modelsdev._fetching:
                            break
                    time.sleep(0.02)
            index = ca_modelsdev.load_index(directory, force=True)
        self.assertEqual(index, {})


class CatalogEntryTests(unittest.TestCase):
    def setUp(self):
        reset_module()

    def test_model_entry_uses_the_table(self):
        entry = ca_proxy.model_entry("glm-5.2", {})
        self.assertEqual(entry["context_length"], 1000000)
        self.assertEqual(entry["max_output_tokens"], 131072)

    def test_unknown_model_gets_1m_context_and_no_output(self):
        entry = ca_proxy.model_entry("totally-unknown", {})
        self.assertEqual(entry["context_length"], 1000000)
        self.assertNotIn("max_output_tokens", entry)

    def test_remote_values_still_win(self):
        entry = ca_proxy.model_entry("glm-5.2", {"maxInputTokens": 12345,
                                                 "maxOutputTokens": 678})
        self.assertEqual(entry["context_length"], 12345)
        self.assertEqual(entry["max_output_tokens"], 678)

    def test_v1_models_triggers_the_background_refresh(self):
        class Handler(ca_proxy.Handler):
            def __init__(self):
                self.captured = None

            def _authorized(self):
                return True

            def _request_realm(self):
                return "intl"

            def _json(self, code, obj):
                self.captured = (code, obj)

        handler = Handler()
        # 清单只来自码道目录（WorkBuddy 池已移除），桩换成 codearts_catalog。
        catalog = {"models": [{"id": "glm-5.2", "name": "glm-5.2",
                               "group": "builtin", "supportsImages": False,
                               "supportsReasoning": True,
                               "supportsToolCall": True}],
                   "errors": {}}
        with mock.patch.object(ca_proxy, "codearts_catalog",
                               return_value=catalog), \
                mock.patch.object(ca_proxy, "codearts_deployed",
                                  return_value=True), \
                mock.patch.object(ca_proxy, "model_aliases", return_value={}), \
                mock.patch.object(ca_modelsdev, "refresh_async") as refresh:
            handler._get_v1_models()
        code, obj = handler.captured
        self.assertEqual(code, 200)
        refresh.assert_called_once()
        self.assertEqual(obj["data"][0]["id"], "glm-5.2")




if __name__ == "__main__":
    unittest.main()

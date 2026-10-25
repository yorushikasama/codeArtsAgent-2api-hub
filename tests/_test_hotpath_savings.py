"""热路径每请求固定开销的削减：等价性对拍与缓存失效回归。

这个套件钉住三项热路径改动（PR: 代理请求热路径削开销）的正确性：

  1. estimate_tokens 的单遍实现与原来的逐字符循环逐值相等（含 CJK 边界、代理对、
     非字符串输入）；
  2. ca_settings.load 的 (path, mtime, size) 缓存：外部改写后失效、save() 写后
     立即可见（含 limits_data 首读迁移的写）、返回的是顶层拷贝；
  3. 模块级 _usage 只剩进程启动时刻：record_usage/record_error 不再累加没人读的
     requests/ttft/gen/wall/by_model，快照的 started/since 仍从它取。
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _isolated_dirs import isolated_data_dirs  # noqa: E402  (its own data root)

_TMP = isolated_data_dirs("wb-hotpath-")

import ca_proxy as P
import ca_protocol as Q  # noqa: E402
import ca_settings  # noqa: E402


def old_estimate_tokens(text):
    """改动前的实现（等价性基准）：逐字符 Python 循环。"""
    if not text:
        return 0
    if not isinstance(text, str):
        text = str(text)
    cjk = sum(1 for c in text
              if '\u4e00' <= c <= '\u9fff' or '\u3400' <= c <= '\u4dbf')
    other = len(text) - cjk
    return cjk + max(1, int(other / 3.6)) if text else 0


class EstimateTokensTests(unittest.TestCase):
    def test_matches_the_character_loop(self):
        samples = [
            "", None, 0, False, 123, 12.5, ["a"], {"a": 1},
            "hello world", "你好世界", "mixed 中文 and english",
            # CJK 区段边界：3400/4DBF/4E00/9FFF 在内，33FF/4DC0/A000 在外
            "\u3400\u4dbf\u4e00\u9fff", "\u33ff\u4dc0\ua000",
            "\u9fff" * 10 + "a" * 10, "a\u0301b", "🙂🙂",
            "x" * 4096, "汉" * 4096, "abc中文def" * 1000,
        ]
        for s in samples:
            self.assertEqual(Q.estimate_tokens(s), old_estimate_tokens(s),
                             repr(s)[:60])

    def test_cjk_re_covers_exactly_the_loop_ranges(self):
        inside = "\u3400\u4dbf\u4e00\u9fff"
        outside = "\u33ff\u4dc0\ua000 ab"
        self.assertEqual(len(Q.CJK_RE.sub("", inside)), 0)
        self.assertEqual(Q.CJK_RE.sub("", outside), outside)


class UsageCounterTests(unittest.TestCase):
    """_usage 只剩进程启动时刻：请求路径不再维护没人读的进程级累计。

    record_usage/record_error 曾经每请求往模块级 _usage 里累加 requests /
    令牌 / ttft / gen / wall / by_model，而全仓唯一的读者是快照的
    _usage["started"]。钉住：只留 started、请求不改它、快照的 started/since
    仍然从它取（口径一行未变）。
    """

    def test_usage_holds_only_the_start_marker(self):
        started = P._usage["started"]
        P.record_usage("m-1", {"prompt_tokens": 10, "completion_tokens": 5,
                               "total_tokens": 15}, stream=True, elapsed_ms=1200,
                       ttft_ms=300, gen_ms=900, account=None)
        P.record_error("m-1", 500, "boom", elapsed_ms=200)
        self.assertEqual(P._usage, {"started": started})

    def test_snapshot_started_and_since_come_from_it(self):
        P._usage["started"] = 1791445200.0
        snap = P.usage_snapshot(realm=None, ttl=0)
        self.assertEqual(snap["started"], 1791445200.0)
        self.assertEqual(snap["since"],
                         time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(1791445200.0)))


class JsonSpy(object):
    """Counts json.load calls while passing everything else through."""

    def __init__(self, real):
        self.real = real
        self.loads = 0

    def load(self, fh):
        self.loads += 1
        return self.real.load(fh)

    def dump(self, *args, **kwargs):
        return self.real.dump(*args, **kwargs)


class SettingsCacheTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wb-hotpath-settings-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = ca_settings.settings_path(self.dir)

    def test_repeated_loads_parse_once(self):
        ca_settings.save(self.dir, {"ui_language": "en"})
        real_json = ca_settings.json
        spy = JsonSpy(real_json)
        ca_settings.json = spy
        try:
            first = ca_settings.load(self.dir)
            second = ca_settings.load(self.dir)
        finally:
            ca_settings.json = real_json
        self.assertEqual(first, {"ui_language": "en"})
        self.assertEqual(second, first)
        self.assertEqual(spy.loads, 1, "第二次 load 应命中缓存，不再解析")

    def test_save_invalidates_the_cache(self):
        ca_settings.save(self.dir, {"ui_language": "en"})
        real_json = ca_settings.json
        spy = JsonSpy(real_json)
        ca_settings.json = spy
        try:
            ca_settings.load(self.dir)              # 1 次解析
            ca_settings.load(self.dir)              # 命中缓存
            ca_settings.save(self.dir, {"ui_language": "zh"})
            self.assertEqual(ca_settings.load(self.dir)["ui_language"], "zh")
            ca_settings.load(self.dir)              # 再次命中
        finally:
            ca_settings.json = real_json
        self.assertEqual(spy.loads, 2, "save() 之后必须重新解析一次，且只一次")

    def test_external_rewrite_is_seen(self):
        ca_settings.save(self.dir, {"ui_language": "en"})
        self.assertEqual(ca_settings.load(self.dir)["ui_language"], "en")
        # 模拟面板之外的进程改写（尺寸不同 -> 缓存键必变）
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"ui_language": "zh-Hant", "extra": "x" * 64}, fh)
        self.assertEqual(ca_settings.load(self.dir)["ui_language"], "zh-Hant")

    def test_write_through_even_when_mtime_is_forced_back(self):
        # 极端情况：新内容与旧文件同尺寸、mtime 又被强行改回旧值（FAT 只有 2s
        # 精度）。save() 的主动失效必须保证下一个 load() 读到新内容。
        ca_settings.save(self.dir, {"k": "aaaa"})
        old_info = os.stat(self.path)
        ca_settings.load(self.dir)
        ca_settings.save(self.dir, {"k": "bbbb"})   # 同尺寸改写
        os.utime(self.path, (old_info.st_atime, old_info.st_mtime))
        self.assertEqual(ca_settings.load(self.dir)["k"], "bbbb")

    def test_limits_migration_write_is_visible(self):
        # limits_data 首读迁移会写文件：迁移后 load() 必须看到新形状。
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"daily_token_limit": 5}, fh)
        self.assertNotIn("limits", ca_settings.load(self.dir))
        limits = ca_settings.limits_data(self.dir)
        self.assertEqual(limits["daily_token_limit"]["global"], 5)
        stored = ca_settings.load(self.dir)
        self.assertIn("limits", stored)
        self.assertNotIn("daily_token_limit", stored)

    def test_missing_file_reads_empty_and_creation_is_seen(self):
        self.assertEqual(ca_settings.load(self.dir), {})
        ca_settings.save(self.dir, {"a": 1})
        self.assertEqual(ca_settings.load(self.dir), {"a": 1})

    def test_returned_dict_is_a_copy(self):
        ca_settings.save(self.dir, {"a": 1})
        first = ca_settings.load(self.dir)
        first["a"] = 999
        first["b"] = "new"
        self.assertEqual(ca_settings.load(self.dir), {"a": 1})

    def test_corrupt_file_reads_empty(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(ca_settings.load(self.dir), {})


if __name__ == "__main__":
    unittest.main()

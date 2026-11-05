"""账号面板快照：后台物化 + 落盘 + 降级。

## 为什么值得一套专门的用例

这份快照的唯一作用是**让面板不等上游**。它一旦坏了，正确行为是「退回慢
路径」而不是「面板打不开」—— 这个降级只有测得到才有意义。同样要钉住的：

  - 写盘必须原子：面板进程可能在任意时刻读这个文件，半截 JSON 就是坏
    数据；用临时文件 + os.replace 是唯一说得过去做法。
  - 上游数字没变时**不落盘**：路由器上的 flash 经不起每分钟一次无意义写。
  - schema 不认识就当没有：以后字段变了，旧面板读到新文件不该解析出错。
  - 单个账号失败不拆整份快照：其余账号的数字仍然是新鲜的。
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ca_account_snapshot as snap


class SnapshotIoTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        snap.reset()

    def tearDown(self):
        snap.reset()

    def test_roundtrip(self):
        snap.write_snapshot(self.dir, {"acct-1": {"credit": {"used": 1.0},
                                                 "welfare": None}})
        snap.reset()                     # 丢掉内存副本，强制读盘
        raw = snap.load_snapshot(self.dir)
        self.assertIsNotNone(raw)
        entry = snap.account_entry(raw, "acct-1")
        self.assertEqual(entry["credit"]["used"], 1.0)
        self.assertIsNone(entry["welfare"])

    def test_missing_file_returns_none(self):
        self.assertIsNone(snap.load_snapshot(self.dir))

    def test_corrupt_file_returns_none(self):
        """半截 JSON 必须当成「没有」，而不是抛给调用方。"""
        path = snap.snapshot_path(self.dir)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"schema": 1, "accounts": {')
        snap.reset()
        self.assertIsNone(snap.load_snapshot(self.dir))

    def test_unknown_schema_is_ignored(self):
        """以后改了字段，旧代码读到新文件要安全地退回慢路径。"""
        path = snap.snapshot_path(self.dir)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema": 999, "accounts": {"a": {}}}, fh)
        snap.reset()
        self.assertIsNone(snap.load_snapshot(self.dir))

    def test_write_is_atomic(self):
        """写完后不能留下 .tmp，且文件内容完整可解析。"""
        snap.write_snapshot(self.dir, {"a": {"credit": None, "welfare": None}})
        names = os.listdir(self.dir)
        self.assertIn(snap.SNAPSHOT_FILE, names)
        self.assertNotIn(snap.SNAPSHOT_FILE + ".tmp", names)
        with open(snap.snapshot_path(self.dir), encoding="utf-8") as fh:
            json.load(fh)

    def test_unchanged_payload_does_not_rewrite(self):
        """数字没变就不落盘 —— 用 mtime 验证。"""
        entries = {"a": {"credit": {"used": 5.0}, "welfare": None}}
        snap.write_snapshot(self.dir, entries)
        path = snap.snapshot_path(self.dir)
        first = os.stat(path).st_mtime_ns
        import time
        time.sleep(0.02)
        snap.write_snapshot(self.dir, entries)      # 一模一样
        self.assertEqual(os.stat(path).st_mtime_ns, first,
                         "内容没变却又写了一次盘")

    def test_changed_payload_does_rewrite(self):
        snap.write_snapshot(self.dir, {"a": {"credit": {"used": 5.0}}})
        path = snap.snapshot_path(self.dir)
        first = os.stat(path).st_mtime_ns
        import time
        time.sleep(0.02)
        snap.write_snapshot(self.dir, {"a": {"credit": {"used": 6.0}}})
        self.assertNotEqual(os.stat(path).st_mtime_ns, first)

    def test_age_advances_even_when_upstream_did_not_change(self):
        """`at` 是「上次刷新成功的时间」，不是「上次写盘的时间」。

        上游余额经常几分钟不动。如果 `at` 跟着「有没有落盘」走，面板就会
        误报「N 分钟前的快照」——而后台其实一次都没漏。这条用例钉住这个
        语义：不落盘，但内存副本的时间戳照样往前推。
        """
        entries = {"a": {"credit": {"used": 5.0}, "welfare": None}}
        snap.write_snapshot(self.dir, entries, now=1000.0)
        first = snap.load_snapshot(self.dir)
        self.assertAlmostEqual(snap.snapshot_age(first, now=1000.0), 0.0)

        # 60 秒后再刷一次，数字一模一样（不落盘）
        snap.write_snapshot(self.dir, entries, now=1060.0)
        second = snap.load_snapshot(self.dir)
        self.assertAlmostEqual(snap.snapshot_age(second, now=1060.0), 0.0,
                               msg="刷新成功但时间戳没往前推，面板会误报陈旧")

    def test_account_entry_tolerates_junk(self):
        self.assertIsNone(snap.account_entry(None, "a"))
        self.assertIsNone(snap.account_entry({}, "a"))
        self.assertIsNone(snap.account_entry({"accounts": []}, "a"))
        self.assertIsNone(snap.account_entry({"accounts": {}}, "a"))
        self.assertIsNone(snap.account_entry({"accounts": {"a": "nope"}}, "a"))


class SnapshotAgeTests(unittest.TestCase):
    def test_age(self):
        self.assertAlmostEqual(snap.snapshot_age({"at": 100.0}, now=160.0), 60.0)

    def test_age_missing_or_junk(self):
        self.assertIsNone(snap.snapshot_age(None))
        self.assertIsNone(snap.snapshot_age({}))
        self.assertIsNone(snap.snapshot_age({"at": 0}))
        self.assertIsNone(snap.snapshot_age({"at": "yesterday"}))

    def test_future_timestamp_clamps_to_zero(self):
        # 系统时间被往回调过：不能算出负数年龄。
        self.assertEqual(snap.snapshot_age({"at": 500.0}, now=100.0), 0.0)


class SnapshotRefreshTests(unittest.TestCase):
    """refresh_once：单账号失败不拆整份、无账号也能落盘。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        snap.reset()
        import ca_codearts
        self.ca_codearts = ca_codearts
        self._orig = (ca_codearts.load_sessions, ca_codearts.credit_package,
                      ca_codearts.welfare_daily)

    def tearDown(self):
        (self.ca_codearts.load_sessions, self.ca_codearts.credit_package,
         self.ca_codearts.welfare_daily) = self._orig
        snap.reset()

    def _session(self, account_id):
        return {"account": {"id": account_id, "label": "L-" + account_id},
                "accessKey": "AK" + account_id, "secretKey": "s",
                "securitytoken": "t"}

    def test_one_account_failing_keeps_the_others(self):
        sessions = [self._session("ok1"), self._session("bad"),
                    self._session("ok2")]
        self.ca_codearts.load_sessions = lambda _d: list(sessions)

        def credit(ak, *_a, **_k):
            if ak == "AKbad":
                raise RuntimeError("APIG.0301")
            return {"used": 1.0, "total": 10.0}

        self.ca_codearts.credit_package = credit
        self.ca_codearts.welfare_daily = lambda *_a, **_k: {"status": "ELIGIBLE"}

        raw = snap.refresh_once(self.dir)
        self.assertIsNotNone(raw)
        self.assertEqual(set(raw["accounts"]), {"ok1", "bad", "ok2"})
        self.assertEqual(raw["accounts"]["ok1"]["credit"]["used"], 1.0)
        self.assertIsNone(raw["accounts"]["bad"]["credit"])
        self.assertIn("APIG.0301", raw["accounts"]["bad"]["creditError"])
        # 积分失败不影响签到那一路
        self.assertEqual(raw["accounts"]["bad"]["welfare"]["status"], "ELIGIBLE")

    def test_no_accounts_writes_empty_snapshot(self):
        self.ca_codearts.load_sessions = lambda _d: []
        raw = snap.refresh_once(self.dir)
        self.assertIsNotNone(raw)
        self.assertEqual(raw["accounts"], {})

    def test_load_failure_returns_none_without_writing(self):
        def boom(_d):
            raise RuntimeError("accounts dir gone")
        self.ca_codearts.load_sessions = boom
        self.assertIsNone(snap.refresh_once(self.dir))
        self.assertFalse(os.path.exists(snap.snapshot_path(self.dir)))

    def test_uses_account_id_not_access_key_as_the_key(self):
        """索引用 account id：AK 是凭据，不该成为落盘索引（哪怕截断）。"""
        self.ca_codearts.load_sessions = lambda _d: [self._session("acct-9")]
        self.ca_codearts.credit_package = lambda *_a, **_k: {"used": 2.0}
        self.ca_codearts.welfare_daily = lambda *_a, **_k: None
        raw = snap.refresh_once(self.dir)
        self.assertIn("acct-9", raw["accounts"])
        self.assertNotIn("AKacct-9", raw["accounts"])


class SnapshotStalenessTests(unittest.TestCase):
    """阈值常量本身要自洽，否则面板的「过期」提示永远不触发。"""

    def test_stale_threshold_is_larger_than_tick(self):
        self.assertGreater(snap.ACCOUNT_SNAPSHOT_STALE,
                           snap.ACCOUNT_SNAPSHOT_TICK)

    def test_tick_is_not_aggressive(self):
        # 比一分钟更快地轮询上游余额只会让上游以为我们在压测。
        self.assertGreaterEqual(snap.ACCOUNT_SNAPSHOT_TICK, 30.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

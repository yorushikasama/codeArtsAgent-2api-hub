"""国内版每日对话活跃上报与连登（issue #250 / 连续打卡）。

包含行为级测试：
1. can_report_activity 判定：仅限 cn 账号，按本地日期闸门（当天做过则不重复）。
2. report_activity 行为：
   - 非 cn 账号直接拒绝；
   - 构造 chat 事件上报并校验上游 code=0；
   - 上报成功后更新 last_activity_report 并落盘；
   - 只读读取 streak days 带回 msg / streak_days 结构；
   - 模拟上游静默丢弃 (streak days<=0) 的提示与正常递增提示。
3. 调度器巡检链路：
   - 针对 cn 账号执行活跃上报；
   - 第二轮不重复上报；
   - 计数器与汇总日志正确统计上报个数。

Run with: python tests/run_all.py streak
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_accounts
import ca_scheduler
import ca_tasks


def make_account(uid="u1", realm="cn", **extra):
    data = {
        "uid": uid,
        "realm": realm,
        "accessToken": "token-" + uid,
        "nickname": "test-" + uid,
        "expiresAt": int(time.time()) + 3600,
    }
    data.update(extra)
    return ca_accounts.Account(data)


class CanReportActivityTests(unittest.TestCase):
    def test_can_report_activity_skips_enterprise(self):
        acc = make_account(uid="ent-rep", realm="cn", enterpriseId="ent-1")
        self.assertFalse(acc.can_report_activity())
        res = acc.report_activity()
        self.assertFalse(res.get("ok"))
        self.assertIn("enterprise", res.get("error", ""))

    def test_a_removed_realm_account_reads_as_cn(self):
        # 国际版删除后，账号文件里写死 intl 的读回来就是 cn：它属于唯一出口，
        # 于是照常可以上报（不再有「国际版永不打卡」这条分支）。
        acc = make_account(realm="intl")
        self.assertEqual(acc.realm, "cn")
        self.assertTrue(acc.can_report_activity())

    def test_cn_account_without_record_can_report(self):
        acc = make_account(realm="cn")
        self.assertTrue(acc.can_report_activity())

    def test_cn_account_with_today_record_cannot_report(self):
        acc = make_account(realm="cn", lastActivityReport=time.strftime("%Y-%m-%d %H:%M:%S"))
        self.assertFalse(acc.can_report_activity())

    def test_cn_account_with_yesterday_record_can_report(self):
        acc = make_account(realm="cn", lastActivityReport="2026-10-09 10:00:00")
        self.assertTrue(acc.can_report_activity())


class ReportActivityTests(unittest.TestCase):
    def test_the_region_guard_is_unreachable_now(self):
        """上报的区域闸门仍写着「只给 cn」，但账号读回来一定是 cn。

        这条钉住的是「闸门没被顺手删掉」：真要有非 cn 的账号进来（将来换上游
        划界时），它必须仍然拒绝，而不是悄悄发出去。
        """
        acc = make_account(realm="cn")
        acc.realm = "intl"          # 绕过构造期的归一，模拟未来多出口的情形
        res = acc.report_activity()
        self.assertFalse(res.get("ok"))
        self.assertIn("only for CN", res.get("error", ""))

    def test_fails_when_report_events_rejected(self):
        acc = make_account(realm="cn")
        with mock.patch.object(ca_tasks, "report_events", return_value=False):
            res = acc.report_activity()
            self.assertFalse(res.get("ok"))
            self.assertIn("拒绝", res.get("error", ""))
            self.assertIsNone(acc.last_activity_report)

    def test_success_with_positive_streak_days(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            acc = make_account(realm="cn")
            acc.path = acc.save(tmpdir)

            with mock.patch.object(ca_tasks, "report_events", return_value=True), \
                 mock.patch.object(ca_tasks, "fetch_streak_days", return_value=5):
                res = acc.report_activity()
                self.assertTrue(res.get("ok"))
                self.assertEqual(res.get("streak_days"), 5)
                self.assertIn("连续打卡 5 天", res.get("msg", ""))
                self.assertIsNotNone(acc.last_activity_report)

                # 确认持久化落盘
                with open(acc.path, encoding="utf-8") as f:
                    reloaded = ca_accounts.Account(json.load(f), acc.path)
                self.assertEqual(reloaded.last_activity_report, acc.last_activity_report)

    def test_success_with_unknown_streak_days(self):
        acc = make_account(realm="cn")
        with mock.patch.object(ca_tasks, "report_events", return_value=True), \
             mock.patch.object(ca_tasks, "fetch_streak_days", return_value=None):
            res = acc.report_activity()
            self.assertTrue(res.get("ok"))
            self.assertIn("连登天数未知", res.get("msg", ""))

    def test_success_with_zero_streak_days_warns(self):
        acc = make_account(realm="cn")
        with mock.patch.object(ca_tasks, "report_events", return_value=True), \
             mock.patch.object(ca_tasks, "fetch_streak_days", return_value=0):
            res = acc.report_activity()
            self.assertTrue(res.get("ok"))
            self.assertEqual(res.get("streak_days"), 0)
            self.assertIn("连登仍是 0 天", res.get("msg", ""))


class SchedulerActivityReportTests(unittest.TestCase):
    def test_scheduler_runs_report_for_cn_accounts(self):
        # 单出口：池里只会有 cn 账号（写死 intl 的读回来也是 cn）。
        cn_acc = make_account(uid="cn-due", realm="cn")

        pool = type("Pool", (), {"accounts": [cn_acc]})()
        scheduler = ca_scheduler.Scheduler(pool)
        scheduler.cat_hours = []

        report_calls = []

        def fake_report(self):
            report_calls.append(self.uid)
            self.last_activity_report = time.strftime("%Y-%m-%d %H:%M:%S")
            return {"ok": True, "streak_days": 2, "msg": "对话活跃上报成功（连续打卡 2 天）"}

        with mock.patch.object(ca_accounts.Account, "report_activity", fake_report), \
             mock.patch.object(ca_scheduler, "do_cat_travel", lambda acc: {"action": None}), \
             mock.patch.object(ca_scheduler.time, "sleep", lambda *_: None):
            scheduler._run_cycle("测试第一轮")
            self.assertEqual(report_calls, ["cn-due"])
            self.assertTrue(any("活跃上报 1 个" in log for log in scheduler.logs))

            # 第二轮不重复跑
            scheduler._run_cycle("测试第二轮")
            self.assertEqual(report_calls, ["cn-due"])
            self.assertTrue(any("活跃上报 0 个" in log for log in scheduler.logs))





class StreakBonusTests(unittest.TestCase):
    def test_skips_a_non_cn_account(self):
        """区域闸门仍写着「仅限国内版」：绕过构造期归一才构造得出来。

        单出口下正常账号一定是 cn，这条守住的是「闸门别被顺手删掉」。
        """
        acc = make_account(uid="intl-bonus", realm="cn")
        acc.realm = "intl"
        res = ca_tasks.run_streak_bonus(acc)
        self.assertFalse(res.get("ok"))
        self.assertIn("仅限国内版", res.get("msg"))

    def test_skips_enterprise_account(self):
        acc = make_account(uid="ent-bonus", realm="cn", enterpriseId="ent-123")
        res = ca_tasks.run_streak_bonus(acc)
        self.assertTrue(res.get("ok"))
        self.assertIn("企业版", res.get("msg"))

    def test_streak_bonus_executes_safely(self):
        acc = make_account(uid="cn-bonus", realm="cn")
        with mock.patch.object(ca_tasks._accounts, "urlopen") as mock_url:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = json.dumps({"code": 0, "data": {}}).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            mock_url.return_value = mock_resp

            res = ca_tasks.run_streak_bonus(acc)
            self.assertTrue(res.get("ok"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


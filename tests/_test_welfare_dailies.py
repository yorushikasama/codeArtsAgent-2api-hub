"""每日签到：清单里**多条 USER_LOGIN** 时必须逐条领，且金额只算真领到的。

2026-11-24 线上实测的清单（/v1/ops/delivery?channel=IDE，共 6 条）：

    campaignId=42  USER_LOGIN  2000  CONFIRMED  claimable=False  Skill创新赛报名礼
    campaignId=40  USER_LOGIN  1000  ELIGIBLE   claimable=True   Skill创新赛每日签到礼
    campaignId=34  USER_LOGIN   100  ELIGIBLE   claimable=True   每日签到领100积分
    campaignId=39  STUDENT_CERTIFIED 5000 None  claimable=False 2026年学生专属福利
    campaignId=4   NEW_USER_REGISTER 4000 CONSUMED              新用户注册送 4000 积分
    campaignId=2   STUDENT_CERTIFIED 4000 None  claimable=False 学生认证领积分

旧实现 `next(it for it in items if it["type"] == "USER_LOGIN")` 只取第一条，
而那恰好是**已领过的一次性报名礼 42**。于是每天判「今日已签到（2000 积分）」
直接返回：一分没进账，34 和 40 期期漏领。生产日志里那一串
`checkin: [hid_bgat...] 今日已签到（2000 积分）` 就是铁证。

本套件钉住四件事：
  1. select_dailies 只挑「真的还能领」的（type + 未领 + claimable）；
  2. 一条都不能漏 —— 34 和 40 都要进列表，且大额优先；
  3. 金额只累计**这次真领到**的，不能拿清单里别人的额度充数；
  4. 单条失败不影响其余，且失败要如实挂出来。

    python tests/_test_welfare_dailies.py
"""
import os
import sys
import json
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _isolated_dirs import isolated_data_dirs  # noqa: E402

_TMP = isolated_data_dirs("wb-welfare-daily-")

import ca_codearts as C  # noqa: E402
import ca_proxy as P  # noqa: E402


def _raw(campaign_id, title, type_, amount, status, claimable, unit="CREDIT",
         description=None):
    """按上游 /v1/ops/delivery 的真实形状造一条（displayConfig 是嵌套 JSON 串）。"""
    display = {"title": title}
    if description:
        display["description"] = description
    return {
        "campaignId": campaign_id,
        "title": title,
        "type": type_,
        "benefitAmount": amount,
        "benefitUnit": unit,
        "status": status,
        "claimable": claimable,
        "displayConfig": json.dumps(display, ensure_ascii=False),
        "pageUrl": "/v1/ops/pages/%d" % campaign_id,
    }


#: 线上 2026-11-24 的真实清单，逐字复刻（顺序也保持 campaignId 倒序）。
LIVE_ITEMS = [
    _raw(42, "Skill创新赛报名礼", "USER_LOGIN", 2000, "CONFIRMED", False,
         description="报名参赛一次性领取2000积分"),
    _raw(40, "Skill创新赛每日签到礼", "USER_LOGIN", 1000, "ELIGIBLE", True,
         description="参加Skill创新赛，每日签到领取1000积分"),
    _raw(39, "2026年学生专属福利", "STUDENT_CERTIFIED", 5000, None, False,
         description="在校大学生每月可领取 5000 积分"),
    _raw(34, "每日签到领100积分", "USER_LOGIN", 100, "ELIGIBLE", True),
    _raw(4, "新用户注册送 4000 积分", "NEW_USER_REGISTER", 4000, "CONSUMED",
         False),
    _raw(2, "学生认证领积分", "STUDENT_CERTIFIED", 4000, None, False),
]


def _items():
    return [C._welfare_item(raw) for raw in LIVE_ITEMS]


class SelectDailiesTests(unittest.TestCase):
    def test_only_claimable_unclaimed_user_login_survives(self):
        picked = C.select_dailies(_items())
        self.assertEqual([it["campaign_id"] for it in picked], [40, 34])

    def test_one_time_registration_gift_is_not_a_daily(self):
        # 缺陷核心：42 type 同为 USER_LOGIN，但已 CONFIRMED 且 claimable=False。
        # 只按 type 过滤会把它选成「今日签到」，从此天天报「已签到（2000 积分）」。
        picked = C.select_dailies(_items())
        self.assertNotIn(42, [it["campaign_id"] for it in picked])

    def test_unclaimable_but_unclaimed_is_skipped(self):
        # 过期 / 未开始 / 认证未完成：status 空、claimable=False。
        picked = C.select_dailies([C._welfare_item(LIVE_ITEMS[2])])
        self.assertEqual(picked, [])

    def test_larger_amount_is_claimed_first(self):
        picked = C.select_dailies(_items())
        self.assertEqual(picked[0]["amount"], 1000)
        self.assertEqual(picked[-1]["amount"], 100)

    def test_all_claimed_yields_empty(self):
        claimed = [
            _raw(40, "Skill创新赛每日签到礼", "USER_LOGIN", 1000, "CONFIRMED",
                 False),
            _raw(34, "每日签到领100积分", "USER_LOGIN", 100, "CLAIMED", False),
        ]
        self.assertEqual(C.select_dailies([C._welfare_item(r) for r in claimed]),
                         [])


class RepresentativeDailyTests(unittest.TestCase):
    """面板那一栏显示哪一条。``daily`` 必须始终是「签到」，不能是报名礼。"""

    def test_prefers_a_claimable_one(self):
        items = _items()
        daily = C._representative_daily(items, C.select_dailies(items))
        self.assertEqual(daily["campaign_id"], 40)   # 1000 那条，额度最大的可领

    def test_after_all_claimed_still_shows_a_checkin_row(self):
        # 全部领完后 dailies 为空，但面板那一栏不能变空 → 回落到签到条目本身。
        done = [
            _raw(40, "Skill创新赛每日签到礼", "USER_LOGIN", 1000, "CONFIRMED",
                 False, description="每日签到领取1000积分"),
            _raw(34, "每日签到领100积分", "USER_LOGIN", 100, "CONFIRMED", False),
            _raw(42, "Skill创新赛报名礼", "USER_LOGIN", 2000, "CONFIRMED", False,
                 description="报名参赛一次性领取2000积分"),
        ]
        normalized = [C._welfare_item(r) for r in done]
        daily = C._representative_daily(normalized, C.select_dailies(normalized))
        self.assertIsNotNone(daily)
        # 必须是签到那条，不能是 2000 的报名礼 —— 否则面板又把一次性额度当签到额。
        self.assertIn("签到", daily["title"])

    def test_registration_gift_never_impersonates_the_daily(self):
        only_gift = [C._welfare_item(LIVE_ITEMS[0])]   # 只有 42
        self.assertIsNone(C._representative_daily(only_gift, []))

    def test_shows_most_recently_claimed_when_all_done(self):
        # 线上实况（2026-11-24 领完 34 之后）：34 和 40 都 CONFIRMED，
        # 兜底不能退回到 42。按 claimed_at 取最近的那条签到。
        items = [
            _raw(40, "Skill创新赛每日签到礼", "USER_LOGIN", 1000, "CONFIRMED",
                 False, description="每日签到领取1000积分"),
            C._welfare_item(dict(
                _raw(34, "每日签到领100积分", "USER_LOGIN", 100, "CONFIRMED",
                     False),
                claimedAt="2026-11-24T08:28:17.235Z")),
            _raw(42, "Skill创新赛报名礼", "USER_LOGIN", 2000, "CONFIRMED",
                 False, description="报名参赛一次性领取2000积分"),
        ]
        items = [it if isinstance(it, dict) and "campaign_id" in it
                 else C._welfare_item(it) for it in items]
        daily = C._representative_daily(items, C.select_dailies(items))
        self.assertIsNotNone(daily)
        self.assertEqual(daily["campaign_id"], 34)   # 最新领取的那条签到
        self.assertNotEqual(daily["campaign_id"], 42)


class WelfareItemTests(unittest.TestCase):
    def test_display_config_is_unwrapped(self):
        # 顶层没有 description，它藏在 displayConfig（嵌套 JSON 字符串）里。
        item = C._welfare_item(LIVE_ITEMS[1])
        self.assertEqual(item["description"], "参加Skill创新赛，每日签到领取1000积分")
        self.assertEqual(item["title"], "Skill创新赛每日签到礼")

    def test_broken_display_config_does_not_raise(self):
        raw = dict(LIVE_ITEMS[3])
        raw["displayConfig"] = "{not json"
        item = C._welfare_item(raw)
        self.assertEqual(item["title"], "每日签到领100积分")
        self.assertEqual(item["description"], "")

    def test_claimable_is_preserved(self):
        self.assertTrue(C._welfare_item(LIVE_ITEMS[1])["claimable"])
        self.assertFalse(C._welfare_item(LIVE_ITEMS[0])["claimable"])


class ClaimDailyTests(unittest.TestCase):
    """welfare_claim_daily 在多条可领时的整链行为（上游全部打桩）。"""

    def setUp(self):
        self.claimed = []
        self.fail_ids = set()
        self.log = []

    def _patch(self, items_after=None):
        items = [dict(raw) for raw in LIVE_ITEMS]

        def fake_delivery(ak, sk, tok, **kw):
            normalized = [C._welfare_item(r) for r in (items_after or items)]
            dailies = C.select_dailies(normalized)
            # 镜像真实实现：daily 是「签到条目本身」，dailies 才是「还能领的」。
            return {"channel": "IDE",
                    "items": normalized,
                    "dailies": dailies,
                    "daily": C._representative_daily(normalized, dailies)}

        def fake_claim(ak, sk, tok, campaign_id, timeout=None):
            if campaign_id in self.fail_ids:
                raise C.CodeArtsError("活动火爆，福利领取失败")
            self.claimed.append(campaign_id)
            amount = next((r["benefitAmount"] for r in items
                           if r["campaignId"] == campaign_id), None)
            return {"ok": True, "campaign_id": campaign_id, "status": "CONFIRMED",
                    "title": "t%d" % campaign_id, "amount": amount,
                    "claimed_at": "2026-11-24T00:10:00Z", "raw": {}}

        return mock.patch.multiple(
            C, welfare_activities=fake_delivery, welfare_claim=fake_claim)

    def test_claims_every_claimable_daily(self):
        with self._patch():
            res = C.welfare_claim_daily("AK", "SK", "ST")
        self.assertEqual(sorted(self.claimed), [34, 40])
        self.assertEqual(res["amount"], 1100)      # 1000 + 100，不是清单里的 2000
        self.assertFalse(res["already"])
        self.assertEqual(len(res["claimed"]), 2)

    def test_amount_reflects_only_what_was_actually_claimed(self):
        # 回归钉：旧实现把清单第一条（2000 报名礼）的额度当成签到额上报。
        with self._patch():
            res = C.welfare_claim_daily("AK", "SK", "ST")
        self.assertNotEqual(res["amount"], 2000)
        self.assertEqual(res["amount"], 1100)

    def test_single_failure_does_not_abort_the_rest(self):
        self.fail_ids = {40}          # 大额那条被秒光
        with self._patch():
            res = C.welfare_claim_daily("AK", "SK", "ST")
        self.assertEqual(self.claimed, [34])       # 小的照样领到
        self.assertEqual(res["amount"], 100)
        self.assertTrue(res.get("partial"))
        self.assertEqual([f["campaign_id"] for f in res["failed"]], [40])

    def test_all_failures_raise(self):
        self.fail_ids = {34, 40}
        with self._patch():
            with self.assertRaises(C.CodeArtsError):
                C.welfare_claim_daily("AK", "SK", "ST")

    def test_nothing_claimable_reports_already(self):
        done = [
            _raw(40, "Skill创新赛每日签到礼", "USER_LOGIN", 1000, "CONFIRMED",
                 False),
            _raw(34, "每日签到领100积分", "USER_LOGIN", 100, "CONFIRMED", False),
        ]
        with self._patch(items_after=done + [LIVE_ITEMS[0]]):
            res = C.welfare_claim_daily("AK", "SK", "ST")
        self.assertTrue(res["already"])
        self.assertEqual(res["amount"], 0)         # 没领到就是 0，不是别人的额度
        self.assertEqual(self.claimed, [])

    def test_no_daily_campaign_at_all_raises(self):
        only_other = [LIVE_ITEMS[4], LIVE_ITEMS[5]]   # 注册礼 + 学生认证
        with self._patch(items_after=only_other):
            with self.assertRaises(C.CodeArtsError):
                C.welfare_claim_daily("AK", "SK", "ST")


class CheckinSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.day = "2026-11-28"
        self.items = []
        self.attempted = []
        self.fail_once = set()
        sess = {"account": {"id": "test", "label": "test"}}
        self.enterContext(mock.patch.multiple(
            P, _CHECKIN_STATE={}, _checkin_local_day=lambda: self.day,
            _sts_dead_by_external=lambda _: False, log=mock.Mock()))
        self.activity = self.enterContext(mock.patch.object(P.ca_activity, "record"))
        self.enterContext(mock.patch.multiple(
            C, load_sessions=lambda _: [sess], ensure_fresh_session=lambda *_: sess,
            welfare_activities=self.delivery, welfare_claim=self.claim))

    def delivery(self, *_args, **_kwargs):
        items = [C._welfare_item(raw) for raw in self.items]
        dailies = C.select_dailies(items)
        return {"items": items, "dailies": dailies,
                "daily": C._representative_daily(items, dailies)}

    def claim(self, _ak, _sk, _tok, campaign_id, **_kwargs):
        self.attempted.append(campaign_id)
        if campaign_id in self.fail_once:
            self.fail_once.remove(campaign_id)
            raise C.CodeArtsError("temporary failure")
        item = next(raw for raw in self.items if raw["campaignId"] == campaign_id)
        item.update(status="CONFIRMED", claimable=False)
        return {"status": "CONFIRMED"}

    def test_partial_retries_only_unclaimed_and_resets_next_day(self):
        self.items = [dict(LIVE_ITEMS[1]), dict(LIVE_ITEMS[3])]
        self.fail_once = {40}
        P._checkin_once()
        self.assertEqual(self.attempted, [40, 34])
        self.assertIn("+100 积分", self.activity.call_args.args[6])
        self.assertIn("下轮补试", self.activity.call_args.args[6])
        P._checkin_once()
        self.assertEqual(self.attempted, [40, 34, 40])
        self.assertIn("+1000 积分", self.activity.call_args.args[6])
        P._checkin_once()
        self.assertEqual(self.attempted, [40, 34, 40])
        self.day = "2026-11-29"
        self.items = [dict(LIVE_ITEMS[3])]
        P._checkin_once()
        self.assertEqual(self.attempted, [40, 34, 40, 34])

    def test_pending_not_already_even_with_another_claimed_campaign(self):
        self.items = [dict(LIVE_ITEMS[1], claimable=False),
                      dict(LIVE_ITEMS[3], status="CONFIRMED", claimable=False)]
        result = C.welfare_claim_daily("AK", "SK", "ST")
        self.assertTrue(result["pending"])
        self.assertFalse(result["already"])
        self.assertEqual(result["amount"], 0)
        P._checkin_once()
        self.assertEqual(self.attempted, [])
        self.assertIn("当前暂无可领签到", self.activity.call_args.args[6])
        self.items[0]["claimable"] = True
        P._checkin_once()
        self.assertEqual(self.attempted, [40])
        P._checkin_once()
        self.assertEqual(self.attempted, [40])


if __name__ == "__main__":
    unittest.main(verbosity=2)
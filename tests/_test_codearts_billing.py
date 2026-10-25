# -*- coding: utf-8 -*-
"""码道计费与每日任务：积分静态兜底 / 体验版积分解析 / 每日签到 / 积分计费规则 / 登录补签。_FakeResponsesHandler 与 _TOOLS 复制自 bridge 套件（两边都要，套件间不互相 import）

不联网。2026-10-24 自 _test_codearts.py 按域拆出；共享夹具在
_codearts_fixtures.py。跑法：python tests/_test_codearts_billing.py
"""
import calendar
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from _codearts_fixtures import (  # noqa: E402
    PROFILE, RESPONSE, SEEN, _fake_jwt, _key, _pkce,
    _stub_exchange)
from _isolated_dirs import isolated_data_dirs  # noqa: E402
isolated_data_dirs("wb-codearts-codearts-billing-")

import ca_proxy as P  # noqa: E402
import ca_stream as S2  # noqa: E402
from ca_proxy import Handler  # noqa: E402
import ca_codearts as C  # noqa: E402

PASS = FAIL = 0

class _FakeResponsesHandler(P.Handler):
    def __init__(self):
        self.path = "/v1/responses"
        self.wfile = io.BytesIO()
        self.status = None
        self.payload = None

    def _client_disconnected(self):
        # 桩没有真实 socket；基类实现读 self.connection 会抛 AttributeError，
        # 被当成「客户端已断开」，码道链路于是在第一次尝试前就退出。
        return False

    def _json(self, code, obj):
        self.status = code
        self.payload = obj
        return code, obj

    def send_response(self, code):
        self.status = code

    def send_header(self, key, value):
        pass

    def end_headers(self):
        pass

    def _key_id(self):
        return "test-key"

    def _anthropic_error(self, code, message, err_type=None):
        self.status = code
        self.payload = {"type": "error",
                        "error": {"type": err_type or "api_error",
                                  "message": message}}
        return code, self.payload


_TOOLS = [{"type": "function", "function": {"name": "get_date",
                                          "description": "d",
                                          "parameters": {"type": "object"}}}]


def check(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] " + label)
    else:
        FAIL += 1
        print("  [FAIL] " + label + ("  " + str(extra) if extra else ""))


def section(name):
    print("\n" + name)


# ---------------------------------------------------------------------------
# 8. 积分计费：倍率 × 单价（逆向自客户端 calculateTurnCredits）
# ---------------------------------------------------------------------------
#
# 下面这两条 ``credit`` 原样抄自 2026-10-21 抓的 /v1/model/builtin 快照
# （.workbuddy/tmp/codearts_builtin_models.json），不是编的：
#   GLM-5.2          ratio 0.05   8 / 2 / 28 元每百万，ratio_display 0.7x
#   openpangu-2.0-pro 两段：0-32000 用 3.2/0.8/14.5，32001+ 用 4.8/1.2/17.6
# 第二段的存在正是必须按 input 取档、不能只取第一段的理由。

section("8. 积分计费规则")

GLM52_RAW = {"model_id": "GLM-5.2", "model_name": "GLM-5.2",
             "model_category": "文本生成", "provider": "internal",
             "supports_images": False,
             "credit": [{"input_from": 0, "input_to": -1,
                         "output_from": 0, "output_to": -1,
                         "ratio": "0.05", "input_price": "8",
                         "cache_price": "2", "output_price": "28",
                         "status": "0", "ratio_display": "0.7x"}]}

PRO_RAW = {"model_id": "openpangu-2.0-pro", "model_name": "OpenPangu-2.0-Pro",
           "credit": [{"input_from": 0, "input_to": 32000,
                       "ratio": "0.028", "input_price": "3.2",
                       "cache_price": "0.8", "output_price": "14.5",
                       "ratio_display": "0.7x"},
                      {"input_from": 32001, "input_to": -1,
                       "ratio": "0.028", "input_price": "4.8",
                       "cache_price": "1.2", "output_price": "17.6",
                       "ratio_display": "0.7x"}]}

FREE_RAW = {"model_id": "Qwen3-VL-235B", "credit": []}

tier = C._credit_tier_raw(GLM52_RAW)
check("GLM-5.2 倍率 = 0.05", tier and tier["ratio"] == 0.05, tier)
check("GLM-5.2 三档单价 8/2/28",
      tier and (tier["input_price"], tier["cache_price"],
                tier["output_price"]) == (8.0, 2.0, 28.0), tier)
check("GLM-5.2 只有一段", len(tier["tiers"]) == 1, tier["tiers"])
check("空 credit 返回 None（不假装免费）", C._credit_tier_raw(FREE_RAW) is None)
check("ratio 为 0 返回 None", C._credit_tier_raw(
    {"credit": [{"ratio": "0", "input_price": "1"}]}) is None)

# 公式：(8*(1000-0) + 2*0 + 28*200) / 1e6 / 0.05 = 0.272
C.CREDIT_TIERS.clear()
C.normalize_builtin([GLM52_RAW, PRO_RAW, FREE_RAW])
check("normalize_builtin 填了 CREDIT_TIERS",
      set(C.CREDIT_TIERS) == {"GLM-5.2", "openpangu-2.0-pro"}, list(C.CREDIT_TIERS))

check("GLM-5.2 1000 入 / 200 出 = 0.272 积分",
      C.credit_for_usage("GLM-5.2", 1000, 0, 200) == 0.272,
      C.credit_for_usage("GLM-5.2", 1000, 0, 200))
# (8*200 + 2*800 + 28*200) / 1e6 / 0.05 = 0.176 —— 缓存命中走 cache_price
check("缓存命中按 cache_price 计（800/1000 命中 = 0.176）",
      C.credit_for_usage("GLM-5.2", 1000, 800, 200) == 0.176,
      C.credit_for_usage("GLM-5.2", 1000, 800, 200))
check("未定价模型返回 None", C.credit_for_usage("Qwen3-VL-235B", 1000, 0, 100) is None)
check("未知模型返回 None", C.credit_for_usage("no-such-model", 1000, 0, 100) is None)
check("cached > prompt 时被夹到 prompt（不产生负价）",
      C.credit_for_usage("GLM-5.2", 100, 500, 0) == round(2.0 * 100 / 1e6 / 0.05, 4),
      C.credit_for_usage("GLM-5.2", 100, 500, 0))

# 分段计价：32K 是分界，越过它单价从 3.2 跳到 4.8
pro = C.CREDIT_TIERS["openpangu-2.0-pro"]
check("32000 输入落在第一段", C._pick_credit_tier(pro, 32000)["input_price"] == 3.2)
check("32001 输入落在第二段", C._pick_credit_tier(pro, 32001)["input_price"] == 4.8)
check("1 输入落在第一段", C._pick_credit_tier(pro, 1)["input_price"] == 3.2)
check("无上限段吃住超大输入",
      C._pick_credit_tier(pro, 10 ** 7)["input_price"] == 4.8)
check("两段单价确实不同（不是重复档）",
      C.credit_for_usage("openpangu-2.0-pro", 40000, 0, 0)
      != C.credit_for_usage("openpangu-2.0-pro", 10000, 0, 0))

# 人话版规则：每百万 token 扣多少积分 = 单价 / ratio
pv = C.credit_pricing_view(C.CREDIT_TIERS["GLM-5.2"])
check("百万输入 = 160 积分", pv["credits_per_mtok_input"] == 160.0, pv)
check("百万输出 = 560 积分", pv["credits_per_mtok_output"] == 560.0, pv)
check("百万缓存 = 40 积分", pv["credits_per_mtok_cache"] == 40.0, pv)
check("单段模型不带 tiers 数组", "tiers" not in pv, list(pv))
pv_pro = C.credit_pricing_view(C.CREDIT_TIERS["openpangu-2.0-pro"])
check("多段模型带出 tiers（2 段）", len(pv_pro.get("tiers") or []) == 2, pv_pro)
check("公式写明是除以 ratio", "/ 1e6 / ratio" in pv["formula"], pv["formula"])

# ---- deepseek 错峰档：按时间而不是按 token 长度选段 ----
# 上游把 default（0.18x）与 off_peak（0.09x）写成完全相同的 input 区间，
# 只按 token 数选段会永远命中 default，夜间账目翻倍。时段 21:00 起 11 小时，
# 即 21:00–07:59 Asia/Shanghai（UTC+8，无夏令时）。
DS_RAW = {
    "model_id": "deepseek-v4.1-flash", "model_name": "DeepSeek-V4.1-Flash",
    "credit": [
        {"input_from": 0, "input_to": -1, "ratio": "0.05",
         "ratio_display": "0.18x", "time_slot_id": "default",
         "input_price": "2", "cache_price": "0.2", "output_price": "8"},
        {"input_from": 0, "input_to": -1, "ratio": "0.05",
         "ratio_display": "0.09x", "time_slot_id": "off_peak",
         "input_price": "1", "cache_price": "0.1", "output_price": "4"},
    ],
    "time_slots": {
        "off_peak": {
            "timezone": "Asia/Shanghai", "schedule": "0 0 21 * * *",
            "duration": 11, "timeunit": "hour",
            "notice": {"zh_cn": "错峰时段5折优惠（每晚21:00-次日7:59）",
                       "en_us": "Off-peak 50% discount"},
        },
        # 上游还会给一个 schedule=null 的 default 槽：它只是把说明重复一遍，
        # 不是时段，展示时不能当成第二档。
        "default": {
            "timezone": "Asia/Shanghai", "schedule": None,
            "duration": None, "timeunit": "hour",
        },
    },
}
ds_raw = C._credit_tier_raw(DS_RAW)
check("两档时段都保留，没有被拍平",
      [r["time_slot_id"] for r in ds_raw["tiers"]] == ["default", "off_peak"],
      ds_raw["tiers"])
check("时段定义随档位带出",
      ds_raw["time_slots"]["off_peak"]["schedule"] == "0 0 21 * * *",
      ds_raw["time_slots"])
C.normalize_builtin([DS_RAW])
ds = C.CREDIT_TIERS["deepseek-v4.1-flash"]

# 北京时间 → epoch（UTC = 北京 - 8h）
def bj(hour, minute=0, second=0, day=22):
    return calendar.timegm((2026, 10, day, hour - 8, minute, second))


day = bj(10)                    # 10:00 白天
night = bj(22)                  # 22:00 夜间
check("白天选默认档 0.18x",
      C._pick_credit_tier(ds, 100, day)["ratio_display"] == "0.18x",
      C._pick_credit_tier(ds, 100, day))
check("夜间选错峰档 0.09x",
      C._pick_credit_tier(ds, 100, night)["ratio_display"] == "0.09x",
      C._pick_credit_tier(ds, 100, night))
check("20:59:59 仍按默认档",
      C._pick_credit_tier(ds, 100, bj(20, 59, 59))["ratio_display"] == "0.18x")
check("21:00 整进入错峰",
      C._pick_credit_tier(ds, 100, bj(21))["ratio_display"] == "0.09x")
check("07:59:59 仍在错峰",
      C._pick_credit_tier(ds, 100, bj(7, 59, 59, day=23))["ratio_display"] == "0.09x")
check("08:00 整退出错峰",
      C._pick_credit_tier(ds, 100, bj(8, day=23))["ratio_display"] == "0.18x")
check("未知时区不打折",
      C._time_slot_active({"timezone": "UTC", "schedule": "0 0 21 * * *",
                           "duration": 11, "timeunit": "hour"}, night) is False)

# 积分：白天 2/0.05 = 40 积分每百万输入；夜间 1/0.05 = 20，正好减半
check("白天百万输入 = 40 积分",
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=day) == 40.0,
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=day))
check("夜间百万输入 = 20 积分",
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=night) == 20.0,
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 0, 0, when=night))
check("夜间百万输出 = 80 积分",
      C.credit_for_usage("deepseek-v4.1-flash", 0, 0, 1000000, when=night) == 80.0,
      C.credit_for_usage("deepseek-v4.1-flash", 0, 0, 1000000, when=night))
check("夜间缓存价同步减半",
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 1000000, 0,
                         when=night) == 2.0,
      C.credit_for_usage("deepseek-v4.1-flash", 1000000, 1000000, 0, when=night))

# 展示：默认档的代表值不变，错峰档单独给出可读规则，且不混进 tiers
pv_ds = C.credit_pricing_view(ds)
check("错峰视图带倍率 0.09x",
      pv_ds["time_slots"]["off_peak"]["ratio_display"] == "0.09x", pv_ds)
check("错峰视图带时段说明",
      pv_ds["time_slots"]["off_peak"]["schedule"] == "0 0 21 * * *", pv_ds)
check("错峰视图带上游中文说明",
      pv_ds["time_slots"]["off_peak"]["notice"]
      == "错峰时段5折优惠（每晚21:00-次日7:59）", pv_ds)
check("default 槽不算错峰档", "default" not in pv_ds["time_slots"], pv_ds)
check("错峰档百万输入 = 20 积分",
      pv_ds["time_slots"]["off_peak"]["credits_per_mtok_input"] == 20.0, pv_ds)
check("错峰档百万输出 = 80 积分",
      pv_ds["time_slots"]["off_peak"]["credits_per_mtok_output"] == 80.0, pv_ds)
check("错峰行不算进分段 tiers（区间不会重复）", "tiers" not in pv_ds, list(pv_ds))
check("默认档仍是 0.18x / 40 积分",
      pv_ds["ratio_display"] == "0.18x"
      and pv_ds["credits_per_mtok_input"] == 40.0, pv_ds)

# 模型对象上要带出可读规则，面板才有东西显示
objs = C.normalize_builtin([GLM52_RAW])
check("模型对象带 creditPricing",
      objs[0]["creditPricing"]["credits_per_mtok_output"] == 560.0, objs[0])
check("模型对象带 creditRatio 原文（0.7x）",
      objs[0]["creditRatio"] == "0.7x", objs[0]["creditRatio"])

# 反向校准：0.02 / 0.15 / 0.51 是客户端「总已用积分」上实测到的三次增量
# （短/中/长各一次提问）。用公式反推需要的 token 量级，确认数量级没有差 10 倍。
for want, (pin, pout) in ((0.02, (100, 10)), (0.15, (300, 180)),
                          (0.51, (1000, 625))):
    got = C.credit_for_usage("GLM-5.2", pin, 0, pout)
    check("反推 %s 积分（%d 入 / %d 出）→ %.2f" % (want, pin, pout, got),
          abs(got - want) < 0.005, got)


# ---------------------------------------------------------------------------
# 真流式转发的两个地基：open_chat（只建连不读）与 iter_sse（逐行吐出）
# ---------------------------------------------------------------------------
# 为什么单独测这两个：流式路径一旦把「响应头」先发给客户端就没有退路了，
# 所以正确性全靠这两个函数 —— 建连失败必须能拿到错误体去判重试，
# 逐行读取必须能扛住「多字节字符正好被切在两块之间」和「客户端已经走了」。

class _FakeResp:
    """按给定字节块依次吐出，模拟上游 SSE 分段到达。"""

    def __init__(self, pieces, status=200):
        self.pieces = list(pieces)
        self.status = status
        self.closed = False

    def read1(self, size=8192):
        return self.pieces.pop(0) if self.pieces else b""

    def close(self):
        self.closed = True


_TEXT = "data: {\"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\ndata: [DONE]\n\n"
_RAW = _TEXT.encode("utf-8")
# 在「你」的三字节中间切开：逐块 decode 会吐替换字符，增量解码不会
_cut = _RAW.index("你".encode("utf-8")) + 1
_lines = list(C.iter_sse(_FakeResp([_RAW[:_cut], _RAW[_cut:]])))
# 4 行：data 行、空行、[DONE] 行、空行 —— SSE 的空行分隔符也要原样吐出去
check("iter_sse 跨块拼行", len(_lines) == 4, len(_lines))
check("iter_sse 不产生替换字符（多字节未被切断）",
      "\ufffd" not in "".join(_lines), "".join(_lines)[:80])
check("iter_sse 第一行完整",
      json.loads(_lines[0][5:])["choices"][0]["delta"]["content"] == "你好",
      _lines[0])

_calls = {"n": 0}


def _die():
    _calls["n"] += 1
    return True


try:
    list(C.iter_sse(_FakeResp([_RAW]), _die))
    _aborted = False
except C.ChatAborted:
    _aborted = True
check("iter_sse 客户端断开时抛 ChatAborted", _aborted)

# 尾部没有换行的残行也要吐出来，否则最后一帧会被吞掉
_tail = list(C.iter_sse(_FakeResp([b"data: {}\n", b"data: [DONE]"])))
check("iter_sse 吐出没有行尾的残行", _tail[-1] == "data: [DONE]", _tail)

# open_chat：200 要交回未读句柄，错误要把响应体读完交给重试判定
_REAL_URLOPEN = C.urllib.request.urlopen


class _OkResp(_FakeResp):
    status = 200


def _fake_open_ok(*a, **kw):
    return _OkResp([_RAW])


C.urllib.request.urlopen = _fake_open_ok
try:
    _st, _resp, _txt = C.open_chat("a", "b", "c", "glm-5.3", [], max_tokens=16)
finally:
    C.urllib.request.urlopen = _REAL_URLOPEN
check("open_chat 成功时返回未读句柄", _st == 200 and _resp is not None and _txt == "",
      (_st, type(_resp).__name__))


def _fake_open_429(*a, **kw):
    raise C.urllib.error.HTTPError(
        "u", 429, "too many", {}, io.BytesIO(b'{"error_msg":"queue full"}'))


C.urllib.request.urlopen = _fake_open_429
try:
    _st2, _resp2, _txt2 = C.open_chat("a", "b", "c", "glm-5.3", [], max_tokens=16)
finally:
    C.urllib.request.urlopen = _REAL_URLOPEN
check("open_chat 失败时返回状态码+错误体、不给句柄",
      _st2 == 429 and _resp2 is None and "queue full" in _txt2,
      (_st2, _resp2, _txt2[:60]))

# 并发判定：1041 走短退避，别混进 82 秒的 TPM 节奏
check("TM.00001041 认作并发已满",
      S2.concurrency_full(400, '{"error_code":"TM.00001041"}'))
check("TPM 81114 不算并发已满",
      not S2.concurrency_full(429, '{"error_code":"ModelArts.81114"}'))
# 81111 和 81114 是同一种瞬时限流（前者按 TPM，后者按请求数），
# 上游有时把它塞在 HTTP 400 的 body 里，只看状态码会掉进「参数错」分支
# 回 400 —— 客户端于是把一条本来等几秒就好的请求当成坏请求丢掉。
check("81114 映射成 429",
      S2.fail_spec(429, "ModelArts.81114", "")[0] == 429,
      S2.fail_spec(429, "ModelArts.81114", ""))
check("81111 即使包在 400 里也映射成 429",
      S2.fail_spec(400, "InferHub.ModelArts.81111.429",
                            "TPM limit")[0] == 429,
      S2.fail_spec(400, "InferHub.ModelArts.81111.429", "TPM limit"))
check("并发满的退避明显短于 TPU 限流",
      sum(P.CODEARTS_BUSY_DELAYS) < sum(P.CODEARTS_RETRY_DELAYS),
      (P.CODEARTS_BUSY_DELAYS, P.CODEARTS_RETRY_DELAYS))

# 网关自己只放 1 个进上游，等于让第二个客户端等第一个生成完 —— 那是
# 「发出去几分钟没反应」的另一半原因。默认必须大于 1，且不超账号上限 3。
check("码道并发默认 2（账号给 3，留一个给别人）",
      P.CODEARTS_CONCURRENCY == 2, P.CODEARTS_CONCURRENCY)
check("真流式转发默认开启",
      P.CODEARTS_STREAM_PASSTHROUGH is True, P.CODEARTS_STREAM_PASSTHROUGH)


# ---------------------------------------------------------------------------
# 多账号：每号独立名额、按空闲挑号、冷却跳过、故障转移
# ---------------------------------------------------------------------------
#
# 上游的并发上限是**账号级**的 3 个会话。旧实现只有一个全局信号量，多账号时
# 两个问题：总容量不随账号数增长（3 个号也只能跑 2 条），以及轮转挑号不看谁
# 在忙（第 3 条可能压到已满的号上，另一个号闲着）。


def _sess(aid):
    return {"accessKey": "AK-" + aid, "secretKey": "SK", "securitytoken": "TK",
            "account": {"id": aid, "label": aid},
            "expires_at": "2099-01-01T00:00:00.000Z"}


# 池的容量来自 codearts_concurrency()（面板值 > 环境变量 > 默认 2）。在面板
# 改过并发的机器上（生产服务器是 3）这套断言会全部漂移 —— 钉死成 2 再测。
_saved_cap_fn = P.codearts_concurrency
P.codearts_concurrency = lambda: 2
_pool = P._CodeartsAccountPool()
_pool._usable = lambda: [_sess("a"), _sess("b")]
_got = [_pool.acquire(0)[1] for _ in range(4)]
check("两个账号各给一份名额（不是全局共享一个）",
      sorted(_got) == ["a", "a", "b", "b"], _got)
check("每账号容量 = CODEARTS_CONCURRENCY",
      _got.count("a") == P.CODEARTS_CONCURRENCY, _got)
_sess5, _key5 = _pool.acquire(0.05)
check("全部占满时明确返回空（调用方据此回 429）",
      _sess5 is None and _key5 is None, (_sess5, _key5))
check("在跑数按账号记", _pool.snapshot()["a"]["in_flight"] == 2, _pool.snapshot())
for _k in _got:
    _pool.release(_k)
check("还名额后在跑数归零", _pool.snapshot()["a"]["in_flight"] == 0,
      _pool.snapshot())

# 冷却中的号要被跳过；全在冷却时挑最早解冻的，别饿死
_pool2 = P._CodeartsAccountPool()
_pool2._usable = lambda: [_sess("a"), _sess("b")]
_pool2.penalize("a", 60)
_pick2, _pk2 = _pool2.acquire(0)
check("冷却中的账号被跳过（换另一个号）", _pk2 == "b", _pk2)
_pool2.release(_pk2)

_pool3 = P._CodeartsAccountPool()
_pool3._usable = lambda: [_sess("a"), _sess("b")]
_pool3.penalize("a", 30)
_pool3.penalize("b", 60)
# 全在冷却时**不再直接拿最早解冻的那个**：那等于冷却没作用（单账号部署里
# 就是每次都撞同一堵墙）。等不到就如实返回「没有可用号」，由调用方回 429。
_pick3, _pk3 = _pool3.acquire(0)
check("全在冷却时如实返回没有可用号（不再硬塞一个进冷却的号）",
      _pick3 is None and _pk3 is None, (_pick3, _pk3))
# 预算够长时会等到最早的那条解冻
_pool4 = P._CodeartsAccountPool()
_pool4._usable = lambda: [_sess("a"), _sess("b")]
_pool4.penalize("a", 0.1)
_pool4.penalize("b", 60)
_pick4, _pk4 = _pool4.acquire(2.0)
check("预算够长时等到解冻再用（不饿死）", _pk4 == "a", _pk4)
_pool4.release(_pk4)
P.codearts_concurrency = _saved_cap_fn

# 故障转移：A 号报「并发会话已满」→ 给 A 打冷却、立刻换 B
_saved_pool, _saved_open, _saved_hb2 = P._CODEARTS_POOL, C.open_chat, C.heartbeat
_saved_delays, _saved_err = P.CODEARTS_BUSY_DELAYS, P.record_error
try:
    _fx = P._CodeartsAccountPool()
    _fx._usable = lambda: [_sess("a"), _sess("b")]
    P._CODEARTS_POOL = _fx
    P.CODEARTS_BUSY_DELAYS = (0.0,)
    P.record_error = lambda *a, **k: None
    C.heartbeat = lambda *a, **k: (True, "ok")
    _calls = []

    def _open_by_account(ak, sk, tk, model, messages, **kw):
        _calls.append(ak)
        if ak == "AK-a":
            return (400, None,
                    '{"error_code":"TM.00001041",'
                    '"error_msg":"并发会话数已达上限(3个)"}')
        return 200, _FakeResp([b""]), ""

    C.open_chat = _open_by_account
    _h = _FakeResponsesHandler()
    _err, _lease = _h._codearts_open_lease(
        {"model": "glm-5.3", "messages": []}, "glm-5.3", [], 64)
    check("撞并发满会换号重试（多账号故障转移）",
          _err is None and _lease is not None and _lease.account_key == "b",
          (_err, getattr(_lease, "account_key", None)))
    check("换号前先试了原账号", _calls[:2] == ["AK-a", "AK-b"], _calls)
    check("失败的账号被打上冷却",
          _fx.snapshot().get("a", {}).get("cooling_s", 0) > 0, _fx.snapshot())
    check("租约持有的是成功账号的名额",
          _fx.snapshot().get("b", {}).get("in_flight") == 1, _fx.snapshot())
    if _lease is not None:
        _lease.close()
    check("租约关闭后名额归还",
          _fx.snapshot().get("b", {}).get("in_flight") == 0, _fx.snapshot())
finally:
    P._CODEARTS_POOL = _saved_pool
    C.open_chat = _saved_open
    C.heartbeat = _saved_hb2
    P.CODEARTS_BUSY_DELAYS = _saved_delays
    P.record_error = _saved_err


print()
print("[官方形状镜像 2026-10-24] max_tokens 双向钳制 / tool_choice 缺省 / user_prompt")

# 官方 kernel 日志（27 条请求体）：glm-5.3 与 openpangu-2.0-pro 一律
# max_tokens="32000"。双向钳制：小值（思考吃光额度 → 200 OK 0 正文）和
# 超大值（拉长上游排队）都钳到官方值；没实证的模型原样放行。
check("glm-5.3 小值上钳到官方 32000",
      C.cap_output_tokens("glm-5.3", 800) == 32000,
      C.cap_output_tokens("glm-5.3", 800))
check("glm-5.3 超大值下钳到官方 32000",
      C.cap_output_tokens("glm-5.3", 128000) == 32000)
check("openpangu-2.0-pro 同值双向钳",
      C.cap_output_tokens("openpangu-2.0-pro", 100) == 32000)
check("没实证的模型原样放行",
      C.cap_output_tokens("kimi-k3", 800) == 800)
check("非 int 原样放行",
      C.cap_output_tokens("glm-5.3", "32000") == "32000")

# 官方带 tools 时无条件 tool_choice:"auto"；客户端显式 none 仍尊重。
_body = C.chat_body("glm-5.3", [], max_tokens=256, tools=_TOOLS)
check("tools 存在而 tool_choice 缺省时补 auto",
      _body.get("tool_choice") == "auto", _body)
_body = C.chat_body("glm-5.3", [], max_tokens=256, tools=_TOOLS,
                    tool_choice="none")
check("显式 tool_choice=none 不被覆盖",
      _body.get("tool_choice") == "none", _body)

# user_prompt：倒着找最近一条有正文的 user 消息；tool_result 回合跳过。
_MS = [{"role": "user", "content": "第一句"},
       {"role": "assistant", "content": "好的"},
       {"role": "user", "content": [{"type": "tool_result", "id": "t1"}]},
       {"role": "user", "content": [{"type": "text", "text": "最新正问"}]}]
check("取最近一条有正文的 user 消息",
      C.last_user_prompt_text(_MS) == "最新正问",
      C.last_user_prompt_text(_MS))
check("全是 tool_result 时继续往前找",
      C.last_user_prompt_text(_MS[:3]) == "第一句")
check("没有用户正文返回空串", C.last_user_prompt_text([]) == "")
check("超长正文截到 2000 字符",
      len(C.last_user_prompt_text(
          [{"role": "user", "content": "x" * 9999}])) == 2000)

print()
print("[手动回调 2026-10-24] /accounts/codearts/login/callback 逃生通道")


class _FakeLogin:
    def __init__(self, kind="ok", detail="hid_new"):
        self.kind, self.detail = kind, detail
        self.calls = []

    def accept_callback(self, code=None, secret=None, state=None):
        self.calls.append((code, secret))
        return (self.kind, self.detail)


class _FakeCbHandler:
    def __init__(self):
        self.sent = []

    def _error(self, status, message, *_a):
        self.sent.append(("error", status, message))
        return ("error", status, message)

    def _json(self, status, obj):
        self.sent.append(("json", status, obj))
        return obj

    def _codearts_redirect_ok(self, target):
        return P.Handler._codearts_redirect_ok(target)


def _run_cb(payload, kind="ok", detail="hid_new"):
    fake = _FakeLogin(kind, detail)
    saved_login, saved_clear = P.CODEARTS_LOGIN, P.codearts_clear_cooldown_for
    cleared = []
    P.CODEARTS_LOGIN = fake
    P.codearts_clear_cooldown_for = lambda aid: cleared.append(aid)
    h = _FakeCbHandler()
    try:
        P.Handler._route_codearts_login_callback(h, payload)
    finally:
        P.CODEARTS_LOGIN = saved_login
        P.codearts_clear_cooldown_for = saved_clear
    return h.sent, fake.calls, cleared


_sent, _calls, _cleared = _run_cb(
    {"url": "http://127.0.0.1:9000/oauth/callback?code=l3m32XZK&state=ad22bb"})
check("完整 URL：code 提取并送进 accept_callback",
      _calls == [("l3m32XZK", "")] and _sent[0][0] == "json" and _sent[0][2].get("ok") is True,
      (_calls, _sent))
check("成功路径清掉该账号的冷却", _cleared == ["hid_new"], _cleared)

_sent, _calls, _cleared = _run_cb({"url": "?code=abc&state=xyz"})
check("裸查询串同样可用", _calls == [("abc", "")], _calls)
_sent, _calls, _cleared = _run_cb({"url": "code=abc&state=xyz"})
check("不带 ? 前缀的查询串同样可用", _calls == [("abc", "")], _calls)

_sent, _calls, _cleared = _run_cb({"url": "http://127.0.0.1:9000/oauth/callback?state=xyz"})
check("缺 code/secret 报 400", _sent[0][0] == "error" and _sent[0][1] == 400, _sent)
_sent, _calls, _cleared = _run_cb({"url": ""})
check("空 url 报 400", _sent[0][0] == "error" and _sent[0][1] == 400, _sent)
_sent, _calls, _cleared = _run_cb(
    {"url": "http://127.0.0.1:9000/oauth/callback?code=x"}, kind="error", detail="STS5.1806")
check("accept_callback 失败回 400 带原因",
      _sent[0][0] == "error" and "STS5.1806" in _sent[0][2], _sent)

# old_login 的中间一跳：secret-only → redirect，把 redirect 参数校验后还给面板
_sent, _calls, _cleared = _run_cb(
    {"url": "https://login.huaweicloud.com/oauth2/continue?secret=abc"
            "&redirect=https://snap-access.cn-north-4.myhuaweicloud.com/next"},
    kind="redirect", detail="abc")
check("redirect 一跳：可信域名的续走链接还给面板",
      _sent[0][0] == "json" and _sent[0][2].get("status") == "redirect"
      and _sent[0][2].get("url", "").startswith("https://snap-access."),
      _sent)
_sent, _calls, _cleared = _run_cb(
    {"url": "https://x/oauth2/continue?secret=abc&redirect=https://evil.example.com/next"},
    kind="redirect", detail="abc")
check("redirect 目标不可信时拒绝", _sent[0][0] == "error" and _sent[0][1] == 400, _sent)

print()
print("[state 比对 / 登录补签 2026-10-25]")

_root3 = tempfile.mkdtemp(prefix="wb-codearts-state-")
_real_exchange3 = C.exchange_code
C.exchange_code = _stub_exchange          # 复用第 7 节的桩：换 token 不出网
try:
    SEEN["fail"] = None
    _LM = C.LoginManager(_root3, log=lambda *a, **k: None)
    _st = _LM.start(9000)["state"]
    _r1 = _LM.accept_callback(code="c1", state=_st)
    check("state 匹配时正常走换 token（这里被桩成成功）",
          _r1[0] == "ok", _r1)

    _LM2 = C.LoginManager(_root3, log=lambda *a, **k: None)
    _LM2.start(9000)
    _r2 = _LM2.accept_callback(code="c1", state="wrong-state-xyz")
    check("state 不匹配直接拒绝，不消耗当前 pending",
          _r2[0] == "error" and "state 不匹配" in _r2[1], _r2)
    _r3 = _LM2.accept_callback(code="c3")
    check("state 为空（老链路）跳过比对",
          _r3[0] == "ok", _r3)
finally:
    SEEN["fail"] = None
    C.exchange_code = _real_exchange3

# 登录成功 → 顺手补签当天积分（异步外壳下面的同步主体）
_welcome_hits = []
_saved_wc, _saved_load = C.welfare_claim_daily, C.load_sessions
C.welfare_claim_daily = lambda ak, sk, st: _welcome_hits.append((ak, sk, st)) or {
    "ok": True, "already": False, "amount": 1000}
C.load_sessions = lambda _d: [{
    "accessKey": "AK-1", "secretKey": "SK-1", "securitytoken": "ST-1",
    "account": {"id": "acc-1", "label": "acc-1"}}]
try:
    P._codearts_welcome_claim_sync("acc-1")
    P._codearts_welcome_claim_sync("no-such")
    P._codearts_welcome_claim_sync("")
finally:
    C.welfare_claim_daily, C.load_sessions = _saved_wc, _saved_load
check("登录补签：按账号 id 找到会话并签了一次",
      len(_welcome_hits) == 1 and _welcome_hits[0][0] == "AK-1", _welcome_hits)
check("补签找不到账号 / 空 id 时静默（不抛不签）", len(_welcome_hits) == 1)

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

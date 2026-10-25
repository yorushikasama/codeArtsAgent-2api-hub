# -*- coding: utf-8 -*-
"""模型清单：内置目录 / /v1/models 形状适配 / 只列码道 / 封锁不被分流绕过

不联网。2026-10-24 自 _test_codearts.py 按域拆出；共享夹具在
_codearts_fixtures.py。跑法：python tests/_test_codearts_models.py
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

from _codearts_fixtures import SESSION as _session  # noqa: E402
from _isolated_dirs import isolated_data_dirs  # noqa: E402
isolated_data_dirs("wb-codearts-codearts-models-")

import ca_proxy as P  # noqa: E402
import ca_stream as S2  # noqa: E402
from ca_proxy import Handler  # noqa: E402
import ca_codearts as C  # noqa: E402

PASS = FAIL = 0


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
# 模型清单：只剩内置一组（福利渠道已由官方下线）
# ---------------------------------------------------------------------------

print()
print("== 模型清单（内置）==")
check("内置目录在 PromptCenter 那台主机上",
      C.BUILTIN_MODELS_PATH == "/v1/model/builtin", C.BUILTIN_MODELS_PATH)

# 这几行曾经两次判错过，都是被**假信号**带偏的：
#   · 限时福利 4 个全 404/429 → 被判「不在推理入口注册」，其实是限流不是不支持
#   · glm-5.3 连续 400 且响应体为空 → 被判「真的不通」，其实它只收 stream=true
# 所以不只钉「谁在清单里」，还要把这两个判据本身钉住。
check("清单 9 个模型（12 减掉 3 个纯福利模型）",
      len(C.CHAT_MODELS) == 9
      and "deepseek-v4.1-flash" in C.CHAT_MODELS
      and "GLM-5.2" in C.CHAT_MODELS
      and "glm-5.3" in C.CHAT_MODELS
      and "kimi-k3" in C.CHAT_MODELS,
      C.CHAT_MODELS)
# kimi-k3 是 2026-10-23 才补的：上游内置目录里有、`display_enabled=true`，
# 但没进这张表 —— 表现不是「少一个可选模型」，而是请求被判成「不是码道模型」
# 掉进 WorkBuddy 池，只配码道账号的部署回 503，报错和模型名毫无关系。
check("kimi-k3 在可推理名单里（上游展示它，网关不能装作没有）",
      "kimi-k3" in C.CHAT_MODELS, C.CHAT_MODELS)
# 2026-10-23：福利渠道由官方下线（opengw gateway/config 回
# `[4000] invalid channel, group not found`）。那 3 个纯福利模型两条通道都
# 打不通，已从名单移除 —— 留着它们只会让清单广告一个必错的选项。
check("纯福利模型已从名单移除",
      not any(m in C.CHAT_MODELS for m in
              ("deepseek-v4-flash-0731", "glm-5.3-flash",
               "deepseek-v4-pro-0813")),
      [m for m in C.CHAT_MODELS if "deepseek" in m or m.startswith("glm")])
# deepseek-v4.1-flash 是例外：上游已把它内置化，不带 maas_type 实测 200 出字。
check("deepseek-v4.1-flash 留在名单里（已内置化）",
      "deepseek-v4.1-flash" in C.CHAT_MODELS, C.CHAT_MODELS)
check("glm-5.3 不再被标为不可路由（它只收流式，不是死的）",
      "glm-5.3" not in C.BUILTIN_UNROUTABLE, C.BUILTIN_UNROUTABLE)

# 请求体默认必须流式 —— glm-5.3 传非流式回 400 空响应体，看着像模型不存在
_body = C.chat_body("glm-5.3", [{"role": "user", "content": "hi"}])
check("chat_body 默认流式", _body["stream"] is True, _body)
check("chat_body 带模型名与消息", _body["model"] == "glm-5.3" and _body["messages"],
      _body)
check("chat_body 可显式关掉流式",
      C.chat_body("x", [], stream=False)["stream"] is False)
check("chat_body 的 max_tokens 默认 256", C.chat_body("x", [])["max_tokens"] == 256,
      C.chat_body("x", []))

# maas_type 曾是福利组的开关（2026-10-17 全套头对照实验得出）。福利渠道
# 下线后它不该再出现在任何请求里 —— 带上就是 `InferHub.4004.200 benefit
# not found`，deepseek-v4.1-flash 就是这么被误伤的（已内置化却仍被判成福利组）。
check("请求头不再带 maas_type",
      "maas_type" not in C.chat_headers("AK", "SK", "TOK", "0" * 64),
      C.chat_headers("AK", "SK", "TOK", "0" * 64))

# credit 是按 token 数分段的价格表，面板只要一个代表值
check("分段计费取第一档",
      C._credit_tier({"credit": [{"ratio_display": "0.7x", "input_price": "3.2",
                                  "output_price": "14.5"},
                                 {"ratio_display": "0.7x", "input_price": "4.8"}]})
      == ("0.7x", "3.2", "14.5"))
check("未定价的模型返回三个 None",
      C._credit_tier({"credit": []}) == (None, None, None))
check("credit 缺失也不炸", C._credit_tier({}) == (None, None, None))
check("credit 不是列表时不当成有价", C._credit_tier({"credit": {}}) == (None, None, None))

BUILTIN_SAMPLE = [
    {"model_id": "glm-5.2-sft-harmony", "model_name": "GLM-5.2-ArkTS-SPARK",
     "model_category": "文本生成", "model_desc": "鸿蒙代码增训", "provider": "zhipu",
     "supports_images": False,
     "credit": [{"ratio_display": "0.7x", "input_price": "8",
                 "output_price": "28"}]},
    {"model_id": "Qwen3-VL-235B", "model_name": "Qwen3-VL-235B",
     "model_category": "图片理解", "supports_images": True, "credit": []},
    {"model_id": "glm-5.3", "model_name": "GLM-5.3",
     "supports_images": False,
     "credit": [{"ratio_display": "0.79x"}]},
    {"model_id": "", "model_name": "没有 id 的条目"},
]
norm = C.normalize_builtin(BUILTIN_SAMPLE)
check("丢掉没有 id 的条目", len(norm) == 3, [m["id"] for m in norm])
# 界面上显示的是 model_name，发请求要发 model_id，两者常常不一样
check("展示名取 model_name 而非 model_id",
      norm[0]["name"] == "GLM-5.2-ArkTS-SPARK", norm[0])
check("请求名仍是 model_id", norm[0]["id"] == "glm-5.2-sft-harmony", norm[0])
check("标记为内置分组", norm[0]["group"] == C.GROUP_BUILTIN, norm[0])
check("倍率原样带出", norm[0]["creditRatio"] == "0.7x", norm[0])
check("输入输出价带出", norm[0]["inputPrice"] == "8" and norm[0]["outputPrice"] == "28",
      norm[0])
check("多模态标记取服务端而非猜",
      norm[1]["supportsImages"] is True and norm[0]["supportsImages"] is False,
      [norm[1]["supportsImages"], norm[0]["supportsImages"]])
check("未定价时倍率是 None 而不是 0",
      norm[1]["creditRatio"] is None, norm[1])
check("routable 由 BUILTIN_UNROUTABLE 决定",
      all(m["routable"] is True for m in norm), norm[2])
# 集合本身当前是空的：清单里 11 个模型实测全通。留个断言钉住「现在是空的」，
# 以后真出现不通的模型时这条会失败、提醒更新注释里的说明。
check("当前没有已知不通的内置模型", C.BUILTIN_UNROUTABLE == set(),
      C.BUILTIN_UNROUTABLE)
check("分类与描述带出",
      norm[0]["category"] == "文本生成" and norm[0]["provider"] == "zhipu", norm[0])
# 上下文窗口：上游 /v1/model/builtin 不给这两个值，改用实测表兜底
# （2026-10-20 从 AgentCenter 取得）。表里没有的模型仍然留 0 —— 不编数字。
_LIMITS = C.BUILTIN_MODEL_LIMITS
check("上下文窗口按实测表兜底",
      (norm[0]["maxInputTokens"], norm[0]["maxOutputTokens"])
      == _LIMITS.get(norm[0]["id"], (0, 0)), norm[0])
check("实测表里没有的模型留 0，不编造",
      all(m["maxInputTokens"] == 0 and m["maxOutputTokens"] == 0
          for m in norm if m["id"] not in _LIMITS),
      [m["id"] for m in norm if m["id"] not in _LIMITS])

# 默认采样参数同样来自 AgentCenter detail 的实测值（2026-10-22）。
# 有实测值的模型带 temperature / top_p；没测过的不能凭空补一个默认值。
_SAMPLING = C.BUILTIN_MODEL_SAMPLING
check("采样参数按实测表带出",
      (norm[0].get("temperature"), norm[0].get("top_p"))
      == _SAMPLING["glm-5.2-sft-harmony"], norm[0])
check("采样参数对每个模型各自取值",
      (norm[2].get("temperature"), norm[2].get("top_p"))
      == _SAMPLING["glm-5.3"], norm[2])
check("没有实测值的模型不带采样参数键",
      "temperature" not in norm[1] and "top_p" not in norm[1], norm[1])
check("未实测的多模态模型不猜采样参数",
      "Qwen3-VL-235B" not in _SAMPLING and "kimi-k2.6-vl" not in _SAMPLING,
      sorted(_SAMPLING))


THINK_CALLS = []


def with_catalog(builtin_exc=None, variants=None, variants_exc=None):
    """跑一次 model_catalog：内置取数与思考档位全部打桩。

    思考档位也必须打桩：它是清单构建里唯一一个「顺手多问一次」的接口，
    忘了桩就会真的发出网络请求 —— 这个测试文件的前提是**不联网**，
    真发出去的结果只是随机失败（实测 APIG.0613 IAM unavailable）。
    """
    saved = (C.builtin_models, C.thinking_variants)

    def _fake_variants(*a, **k):
        names = a[3] if len(a) > 3 else k.get("model_names")
        THINK_CALLS.append(list(names or []))
        return dict(variants or {})

    C.builtin_models = (lambda *a, **k: (_ for _ in ()).throw(builtin_exc)) \
        if builtin_exc else (lambda *a, **k: list(BUILTIN_SAMPLE))
    C.thinking_variants = (lambda *a, **k: (_ for _ in ()).throw(variants_exc)) \
        if variants_exc else _fake_variants
    try:
        return C.model_catalog("AK", "SK", "TOK")
    finally:
        C.builtin_models, C.thinking_variants = saved


# 上游思考档位接口的键是 **model_name**，不是 model_id：
# glm-5.2-sft-harmony 的展示名是 GLM-5.2-ArkTS-SPARK。这里按真实形状打桩，
# 只按 id 查的实现会把它的 high/max 丢掉、面板错显示「原生」。
THINK_VARIANTS = {
    "GLM-5.2-ArkTS-SPARK": {"strengths": ["high", "max"], "default": "high"},
    "GLM-5.2": {"strengths": ["high", "max"], "default": "high"},
    "GLM-5.3": {"strengths": [], "default": ""},
}

cat = with_catalog(variants=THINK_VARIANTS)
check("清单只来自内置目录", len(cat["models"]) == 3, len(cat["models"]))
check("取数无错时 errors 为空", cat["errors"] == {}, cat["errors"])
# 请求侧同样要发展示名：上游只按 model_name 匹配，发 id 的模型问不到档位。
check("档位接口按展示名请求",
      THINK_CALLS[-1] == ["GLM-5.2-ArkTS-SPARK", "Qwen3-VL-235B", "GLM-5.3"],
      THINK_CALLS[-1])
_think = [m for m in cat["groups"][C.GROUP_BUILTIN]
          if m["id"] == "glm-5.2-sft-harmony"][0]
check("思考档位贴到模型上", _think.get("thinkingStrengths") == ["high", "max"],
      _think.get("thinkingStrengths"))
check("思考默认档位带出", _think.get("thinkingDefault") == "high", _think)
check("档位接口按展示名返回时仍按 id 贴对",
      _think.get("thinkingStrengths") == ["high", "max"], _think)
check("THINKING_STRENGTHS 被填上",
      C.THINKING_STRENGTHS.get("glm-5.2-sft-harmony", {}).get("strengths")
      == ["high", "max"], C.THINKING_STRENGTHS)
check("THINKING_STRENGTHS 用 id 作键，不残留展示名",
      "GLM-5.2-ArkTS-SPARK" not in C.THINKING_STRENGTHS, C.THINKING_STRENGTHS)
check("没有档位的模型是空数组而不是缺字段",
      [m for m in cat["groups"][C.GROUP_BUILTIN]
       if m["id"] == "Qwen3-VL-235B"][0]["thinkingStrengths"] == [])
check("有档位但为空时也不编档位",
      [m for m in cat["groups"][C.GROUP_BUILTIN]
       if m["id"] == "glm-5.3"][0]["thinkingStrengths"] == [], cat["models"])

# 档位接口挂了：清单照旧返回，但要记一笔 —— 否则面板上全显示「原生」，
# 分不清是「本来没有档位」还是「这次没问到」。
cat_t = with_catalog(variants_exc=RuntimeError("APIG.0613"))
check("档位失败不影响清单", len(cat_t["models"]) == 3, len(cat_t["models"]))
check("档位失败记进 errors", "thinking" in cat_t["errors"], cat_t["errors"])

# 内置目录取不到：回空清单 + 原因，绝不抛异常（面板靠 errors 说明）。
empty = with_catalog(builtin_exc=RuntimeError("PromptCenter 挂了"))
check("内置取数挂了回空清单而不是抛异常", empty["models"] == [], empty["models"])
check("并说明原因",
      "PromptCenter 挂了" in empty["errors"].get(C.GROUP_BUILTIN, ""),
      empty["errors"])


# ---------------------------------------------------------------------------
# 接进 /v1/models 的形状适配
# ---------------------------------------------------------------------------
#
# model_entry 的 meta 契约里 contextWindow 是**带 supportedLengths 的 dict**，
# 而 ca_codearts 归一出来的是数字。第一版直接把归一结果喂进去，抛
# AttributeError: 'int' object has no attribute 'get'，又被外层 try 吞成
# 「清单里没有码道模型」—— 表现成功能没生效、且不报错。这几条钉住那个适配。

print()
print("== 接进 /v1/models 的形状适配 ==")

import ca_proxy as P  # noqa: E402  (需要它才能验 model_entry 契约)
import ca_stream as S2  # noqa: E402

_META = {
    "id": "deepseek-v4.1-flash", "name": "deepseek-v4.1-flash",
    "group": C.GROUP_BUILTIN, "contextWindow": 1000000,
    "maxInputTokens": 1000000, "maxOutputTokens": 384000,
    "supportsImages": False, "supportsReasoning": True,
    "supportsToolCall": True, "routable": True, "creditRatio": None,
    "temperature": 0.5, "top_p": 0.0,
}

adapt = P.codearts_model_meta(_META)
check("contextWindow 被转成带 supportedLengths 的 dict",
      isinstance(adapt.get("contextWindow"), dict)
      and adapt["contextWindow"].get("supportedLengths") == [1000000], adapt)
check("上下文长度同时给了 maxInputTokens",
      adapt.get("maxInputTokens") == 1000000, adapt)
check("maxOutputTokens 一并带出", adapt.get("maxOutputTokens") == 384000, adapt)
check("厂商标成 codearts", adapt.get("vendor") == "codearts", adapt)
check("默认采样参数进 meta",
      adapt.get("temperature") == 0.5 and adapt.get("top_p") == 0.0, adapt)

# 关键：把适配结果喂给 model_entry 不能炸
try:
    entry = P.model_entry(_META["id"], adapt)
    boom = None
except Exception as exc:                      # noqa: BLE001
    entry, boom = None, exc
check("model_entry 能吃下适配后的 meta（曾经抛 int.get）", boom is None, boom)
if entry:
    check("条目 id 正确", entry.get("id") == _META["id"], entry.get("id"))
    check("条目 object 是 model", entry.get("object") == "model")
    check("条目有 context_length", bool(entry.get("context_length")), entry)
    check("条目带出默认采样参数",
          entry.get("temperature") == 0.5 and entry.get("top_p") == 0.0, entry)

# 没有上下文信息的模型（内置那组服务端不给）也不能炸
bare = dict(_META, id="GLM-5.2", contextWindow=0, maxInputTokens=0,
            maxOutputTokens=0, group=C.GROUP_BUILTIN, supportsImages=True)
bare_adapt = P.codearts_model_meta(bare)
check("缺上下文信息时不编造 contextWindow",
      "contextWindow" not in bare_adapt, bare_adapt)
try:
    P.model_entry("GLM-5.2", bare_adapt)
    bare_boom = None
except Exception as exc:                      # noqa: BLE001
    bare_boom = exc
check("缺上下文信息时 model_entry 也不炸", bare_boom is None, bare_boom)

wrapped = P.codearts_model_entry(_META)
check("包装后 owned_by 是 codearts", wrapped.get("owned_by") == "codearts", wrapped)
check("包装后带出分组", wrapped.get("group") == C.GROUP_BUILTIN, wrapped)

check("分流判定认得码道模型", P.is_codearts_model("deepseek-v4.1-flash"))
check("分流判定认得内置那组", P.is_codearts_model("GLM-5.2"))
check("分流判定不误伤 WorkBuddy 模型", not P.is_codearts_model("hy4-preview-f"))
check("空模型名不误判", not P.is_codearts_model(""))
check("None 不误判", not P.is_codearts_model(None))


# ---------------------------------------------------------------------------
# 模型目录：过期但可续期的账号仍要能刷出清单
# ---------------------------------------------------------------------------
#
# 旧实现只留 STS 未过期的会话，闲置两小时后目录整体变空、看板「刷新榜单」
# 只会回「没有可用码道账号」。refresh_token 明明还能换新 STS，所以判据必须
# 是「未过期 **或** 可续期」。

print()
print("== 模型目录对可续期账号可用 ==")

_cat_dir = tempfile.mkdtemp(prefix="wb-codearts-catalog-")
C.save_session(_cat_dir, dict(_session, expires_at="2020-01-01T00:00:00.000Z"))
_saved_dir = P.ACCOUNTS_DIR
_saved_catalog = dict(P._CODEARTS_CATALOG)
_saved_ensure_cat = C.ensure_fresh_session
_saved_model_catalog = C.model_catalog


def _ensure_cat(accounts_dir, session, margin=None):
    return dict(session, accessKey="FRESHAK", secretKey="S",
                securitytoken="T", expires_at="2099-01-01T00:00:00.000Z")


def _model_catalog_cat(ak, sk, tok, timeout=None):
    return {"models": [{"id": "deepseek-v4.1-flash", "routable": True}],
            "errors": {}}


P.ACCOUNTS_DIR = _cat_dir
C.ensure_fresh_session = _ensure_cat
C.model_catalog = _model_catalog_cat
try:
    _cat_out = dict(P.codearts_catalog(force=True))
finally:
    P.ACCOUNTS_DIR = _saved_dir
    C.ensure_fresh_session = _saved_ensure_cat
    C.model_catalog = _saved_model_catalog
    P._CODEARTS_CATALOG.clear()
    P._CODEARTS_CATALOG.update(_saved_catalog)
    shutil.rmtree(_cat_dir, ignore_errors=True)

check("过期但可续期的会话仍能刷新出模型",
      [m.get("id") for m in _cat_out.get("models") or []]
      == ["deepseek-v4.1-flash"], _cat_out)


# ---------------------------------------------------------------------------
# 分流前提：只有真的配了码道账号，重名模型才归码道
# ---------------------------------------------------------------------------
#
# deepseek-v4.1-flash / glm-5.3 / glm-5.3-flash 两边都有。分流按「码道优先」，
# 但前提是部署真的配了码道账号：纯 WorkBuddy 部署里这些名字在 /v1/models
# 挂的是 WorkBuddy 条目，拐去码道只会让清单里列得出来的模型必然 503。

# ---------------------------------------------------------------------------
# /v1/models：只列码道（WorkBuddy 池已移除）
# ---------------------------------------------------------------------------
#
# 以前这里要验证「重名条目以码道为准」的合并规则。池删掉之后没有重名可合，
# 清单只可能来自码道目录 —— 于是要钉的是三件事：只出码道、没账号时回空表
# （不拿内置快照凑数）、别名照常展开。

print()
print("== /v1/models 只列码道 ==")


class _CatalogHandler(P.Handler):
    def __init__(self):
        self.captured = None

    def _authorized(self):
        return True

    def _request_realm(self):
        return "cn"

    def _json(self, code, obj):
        self.captured = (code, obj)


_CA_DS = {
    "id": "deepseek-v4.1-flash", "name": "deepseek-v4.1-flash",
    "group": C.GROUP_BUILTIN, "supportsImages": False,
    "supportsReasoning": True, "supportsToolCall": True,
    "creditRatio": "0.18x",
    "creditPricing": {"ratio": 0.05, "ratio_display": "0.18x",
                      "credits_per_mtok_output": 160.0, "time_slots": {}},
    "temperature": 0.5, "top_p": 0.0,
    "thinkingStrengths": [], "thinkingDefault": "",
}
_CA_GLM = dict(_CA_DS, id="glm-5.3", name="glm-5.3",
               creditRatio="0.79x",
               thinkingStrengths=["high", "max"], thinkingDefault="high")

_saved_list = (P.codearts_catalog, P.codearts_deployed, P.model_aliases,
               P.ca_modelsdev.refresh_async)
try:
    P.codearts_catalog = lambda: {"models": [dict(_CA_DS), dict(_CA_GLM)],
                                  "errors": {}}
    P.codearts_deployed = lambda: True
    P.model_aliases = lambda: {}
    P.ca_modelsdev.refresh_async = lambda *a, **k: None
    _list_handler = _CatalogHandler()
    _list_handler._get_v1_models()
    _list_code, _list_payload = _list_handler.captured
    _ids = [e["id"] for e in _list_payload["data"]]
    check("清单只出码道模型", sorted(_ids) == ["deepseek-v4.1-flash", "glm-5.3"],
          _ids)
    check("每条都标 owned_by=codearts",
          all(e.get("owned_by") == "codearts" for e in _list_payload["data"]),
          [e.get("owned_by") for e in _list_payload["data"]])
    check("codearts 段带出条数", _list_payload["codearts"]["count"] == 2,
          _list_payload.get("codearts"))
    check("不再有 WorkBuddy 目录来源字段",
          "catalog" not in _list_payload, sorted(_list_payload))

    # 别名：目标在本清单里才展开，且 ownership 跟着目标走。
    P.model_aliases = lambda: {"gpt-5-codex": "glm-5.3",
                               "claude-sonnet-4-5-20250929": "不存在的模型"}
    _alias_handler = _CatalogHandler()
    _alias_handler._get_v1_models()
    _alias_by_id = {e["id"]: e for e in _alias_handler.captured[1]["data"]}
    check("别名指向清单里的模型时展开成独立条目",
          "gpt-5-codex" in _alias_by_id
          and _alias_by_id["gpt-5-codex"].get("alias_of") == "glm-5.3",
          sorted(_alias_by_id))
    check("别名指向不存在的模型时不出现",
          "claude-sonnet-4-5-20250929" not in _alias_by_id, sorted(_alias_by_id))

    # 没有码道账号：回空清单并说明原因，绝不拿 WorkBuddy 快照兜底。
    P.codearts_deployed = lambda: False
    _empty_handler = _CatalogHandler()
    _empty_handler._get_v1_models()
    _empty_payload = _empty_handler.captured[1]
    check("没有码道账号时清单为空", _empty_payload["data"] == [],
          _empty_payload.get("data"))
    check("空清单要说明原因",
          _empty_payload["codearts"]["errors"].get("sessions") is not None,
          _empty_payload.get("codearts"))
finally:
    (P.codearts_catalog, P.codearts_deployed, P.model_aliases,
     P.ca_modelsdev.refresh_async) = _saved_list


# ---------------------------------------------------------------------------
# 模型封锁不能被码道分流绕过去
# ---------------------------------------------------------------------------
#
# /v1/responses 和 /v1/messages 都在分流前判「模型封禁 / 按 key 限模型」，
# 唯独 /v1/chat/completions 原来先分流走码道，封锁判断压根没机会执行 ——
# 面板里封掉的模型照样能通过码道调出去。三个入口必须一个口径。

print()
print("== 模型封锁不被码道分流绕过 ==")


class _FakeBanHandler(object):
    def __init__(self):
        self.path = "/v1/chat/completions"
        self.headers = {}
        self.reached = False

    def _error(self, code, message, err_type=None):
        return {"code": code, "message": message}

    def _banned_model_error(self, model):
        return "model is banned" if model == "deepseek-v4.1-flash" else ""

    def _key_model_error(self, model):
        return "model not allowed for this key" if model == "glm-5.3-flash" else ""

    def _handle_codearts_chat(self, payload):
        self.reached = True
        return {"code": 200}


_ban = _FakeBanHandler()
_banned_out = P.Handler._dispatch_chat_post(
    _ban, "/v1/chat/completions", {"model": "deepseek-v4.1-flash"})
check("封禁的码道模型在分流前就回 400",
      isinstance(_banned_out, dict) and _banned_out.get("code") == 400,
      _banned_out)
check("封禁的模型没走到码道", not _ban.reached, _ban.reached)

_ban2 = _FakeBanHandler()
_keyed_out = P.Handler._dispatch_chat_post(
    _ban2, "/v1/chat/completions", {"model": "glm-5.3-flash"})
check("按 key 限掉的码道模型在分流前就回 400",
      isinstance(_keyed_out, dict) and _keyed_out.get("code") == 400,
      _keyed_out)
check("按 key 限掉的模型没走到码道", not _ban2.reached, _ban2.reached)

_ban3 = _FakeBanHandler()
_ok_out = P.Handler._dispatch_chat_post(
    _ban3, "/v1/chat/completions", {"model": "GLM-5.2"})
check("没被封的码道模型照常走码道",
      _ban3.reached and isinstance(_ok_out, dict)
      and _ok_out.get("code") == 200, (_ban3.reached, _ok_out))

print()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

# -*- coding: utf-8 -*-
"""网路工具的名字与参数解析（供 ca_protocol 的 Responses 事件流注入使用）。

历史：本模块曾经整代跑 web_search / web_fetch（多引擎轮换 + 快取 + SSRF 守卫），
执行器的调用方只有「把客户端宣告换成我们 function 定义」的那条 Responses 转发链。
那条链连同面板开关（local_web_tools）已随 WorkBuddy 上游一起退役
（v1.7 的「顺带删掉两个执行器在 WorkBuddy 那边的功能」，见 docs/CHANGELOG.md）：
留着开关只会注入没人执行的工具定义。2026-10 的死代码清扫把剩下的执行后端
（search / fetch / execute / install_tool_defs / 引擎轮换 / 快取节流 / URL 守卫）
也一并退役——完整实现可从 git 历史（77af496 之前）找回。

保留下来的是 Responses 事件流仍在用的三个纯函数：模型自己带 web_search /
web_fetch 宣告并发起调用时，事件流要把这类调用识别出来、反代吞下并画成
web_search_call 事件（不转发给上游——上游没有执行器，转过去只会空转），
动作里带的那份参数就是用 query_args / url_arg 解出来的。
"""

WEB_SEARCH_NAME = "web_search"
WEB_FETCH_NAME = "web_fetch"


def is_internal_tool(name):
    return str(name or "").strip() in (WEB_SEARCH_NAME, WEB_FETCH_NAME)


def query_args(args):
    """从工具参数取出查询字串。

    旧版只读 args["query"] 这个字串，模型改送 queries 阵列时就会被回一句
    「你没问问题」——issue #43 就是这样一路重试到回合用尽。这里接受
    query / queries / q，阵列会用 " or " 接起来。
    """
    if not isinstance(args, dict):
        return ""
    raw = args.get("query")
    if raw is None:
        raw = args.get("queries")
    if raw is None:
        raw = args.get("q")
    if isinstance(raw, (list, tuple)):
        parts = [str(x).strip() for x in raw if str(x or "").strip()]
        return " or ".join(parts)
    return str(raw or "").strip()


def url_arg(args):
    if not isinstance(args, dict):
        return ""
    raw = args.get("url")
    if raw is None:
        raw = args.get("urls")
    if isinstance(raw, (list, tuple)):
        for x in raw:
            if str(x or "").strip():
                return str(x).strip()
        return ""
    return str(raw or "").strip()

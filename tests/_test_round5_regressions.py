"""2026-10-23 第五轮：新改动引入的回归 + 协议/安全修复。

regen 一：6916c03 的缓冲探测把「静默」看错了
  chunked 每块数据后面跟着 CRLF。那块载荷被 read1 取走之后，缓冲里还剩着
  这两个分帧字节 —— ``peek(0)`` 非空就判「可读」，``read1`` 进去先吃掉
  CRLF、再阻塞在读下一块的长度行上。三个后果：模型长思考时不再发 keepalive、
  客户端断开发现不了、静默上限退化成 socket 读超时。

regen 二：单账号 1041 退避实际不重试
  1041 冷却 5 秒，而新加的「等冷却解冻」预算只有 2 秒，于是第一次退避后
  直接回 429「every account is at capacity」——这条 429 还不记账。401 之后
  的 300 秒里每个请求都收到它，而且重新登录也不清冷却。

其余的按用户给的优先级逐条钉住。

不联网（第 1 组用本地 socket + 真的 http.client 跑 chunked 流）。
"""

import http.client
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_codearts as C    # noqa: E402
import ca_protocol as PR   # noqa: E402
import ca_proxy as P       # noqa: E402
import ca_stream as ST     # noqa: E402

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


_tmp = tempfile.mkdtemp(prefix="round5-")
P.ACCOUNTS_DIR = _tmp
P.USAGE_LOG = os.path.join(_tmp, "usage.jsonl")


# ---------------------------------------------------------------------------
# 1. 回归一：chunked 分帧不能骗过静默判定
# ---------------------------------------------------------------------------

section("1. 分帧字节 ≠ 可读数据（keepalive / 看门狗 / 断开检测）")

CRLF = b"\r\n"
_SESSION = {"account": {"id": "u1", "label": "L"}, "accessKey": "AK",
            "secretKey": "SK", "securitytoken": "TK"}

# 1.1 纯函数：分帧判定
_cases = [
    (b"", None, False, "空缓冲"),
    (CRLF, 0, False, "只有本块的结束 CRLF（回归现场）"),
    (CRLF + b"5" + CRLF, 0, False, "长度行到了、载荷没到"),
    (CRLF + b"5" + CRLF + b"hello", 0, True, "长度行 + 载荷"),
    (b"5" + CRLF + b"hello", None, True, "未进入块：长度行 + 载荷"),
    (b"5" + CRLF, None, False, "只有长度行"),
    (b"0" + CRLF + CRLF, None, True, "末块完整"),
    (b"0" + CRLF, None, False, "末块缺结尾空行"),
    (b"abc", 10, True, "块内还有载荷"),
]
for _data, _cl, _want, _why in _cases:
    check("分帧判定：%s" % _why,
          C._chunk_payload_ready(_data, _cl) is _want,
          (_data, _cl))

# 1.2 真的跑一条 chunked 流：静默期必须有 keepalive
def _serve(srv, hold):
    conn, _ = srv.accept()
    conn.recv(65536)
    body = b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n")
    conn.sendall(("%x\r\n" % len(body)).encode() + body + CRLF)
    time.sleep(hold)
    last = b"data: [DONE]\n\n"
    conn.sendall(("%x\r\n" % len(last)).encode() + last + b"\r\n0\r\n\r\n")
    time.sleep(0.2)
    conn.close()


def _open_chunked(hold):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    threading.Thread(target=_serve, args=(srv, hold), daemon=True).start()
    conn = http.client.HTTPConnection("127.0.0.1", srv.getsockname()[1],
                                      timeout=60)
    conn.request("GET", "/")
    return srv, conn, conn.getresponse()


_srv, _conn, _resp = _open_chunked(3.0)
_pings = 0
_lines = 0
_t0 = time.time()
for _piece in C.iter_sse(_resp, idle_timeout=0.5, max_idle=20):
    if _piece is C.KEEPALIVE:
        _pings += 1
    else:
        _lines += 1
check("**首帧之后的静默期照样发 keepalive**（回归：以前一个都没有）",
      _pings >= 3, _pings)
check("流照常读完（探测没把自己弄断）",
      _lines >= 3 and time.time() - _t0 >= 2.5, _lines)
try:
    _conn.close(); _srv.close()
except Exception:
    pass

# 1.3 客户端断开：静默期必须问得到 abort_check
_srv2, _conn2, _resp2 = _open_chunked(5.0)
_abort_n = {"n": 0}


def _abort():
    _abort_n["n"] += 1
    return _abort_n["n"] >= 3


_t0 = time.time()
_aborted = False
try:
    for _ in C.iter_sse(_resp2, _abort, idle_timeout=0.5, max_idle=20):
        pass
except C.ChatAborted:
    _aborted = True
check("**静默期会问 abort_check**（回归：以前阻塞在 read1 上，问不到）",
      _aborted and _abort_n["n"] >= 3, (_aborted, _abort_n["n"]))
check("客户端断开立刻收手（不等上游发下一块）",
      time.time() - _t0 < 3.0, round(time.time() - _t0, 2))
try:
    _conn2.close(); _srv2.close()
except Exception:
    pass

# 1.4 静默上限不再是「socket 读超时」：连续静默要收敛成 UpstreamBroken
_srv3, _conn3, _resp3 = _open_chunked(30.0)   # 上游一直不说话
_t0 = time.time()
_broke = None
try:
    for _ in C.iter_sse(_resp3, idle_timeout=0.2, max_idle=3):
        pass
except C.UpstreamBroken as exc:
    _broke = exc
check("**静默上限自己触发**（不是等 socket 读超时）",
      _broke is not None and time.time() - _t0 < 5.0,
      (_broke, round(time.time() - _t0, 2)))
try:
    _conn3.close(); _srv3.close()
except Exception:
    pass


# ---------------------------------------------------------------------------
# 2. 回归二：单账号 1041 退避要真的重试
# ---------------------------------------------------------------------------

section("2. 单账号 1041 / 401 冷却不再把请求挡在门外")

_orig_load = C.load_sessions
_orig_pool = P._CODEARTS_POOL
C.load_sessions = lambda _d: [dict(_SESSION)]

_pool = P._CodeartsAccountPool()
P._CODEARTS_POOL = _pool
_pool.penalize("u1", 5.0)                 # 1041 的冷却
check("soonest_ready 看得到账号级冷却（不是恒 0）",
      4.0 < _pool.soonest_ready("glm-5.3") <= 5.0,
      _pool.soonest_ready("glm-5.3"))
check("cooling_for 给出剩余秒数",
      4.0 < _pool.cooling_for("u1") <= 5.0, _pool.cooling_for("u1"))

# _codearts_no_slot：冷却比整套退避短 → 返回 None（调用方退避重试）
class _H:
    headers = {}
    connection = None

    def _key_id(self):
        return None

    def _client_disconnected(self):
        return False

    def _error(self, *a, **k):
        return ("RESP", a)


_no_slot = P.Handler._codearts_no_slot.__get__(_H())
_saved_record = P.record_error
_recorded = []


def _fake_record(*a, **k):
    _recorded.append((a, k))


P.record_error = _fake_record
try:
    _r = _no_slot(_H()._error, "glm-5.3", time.time())
    check("**冷却 5 秒时返回 None（退避重试，不是 429）**", _r is None, _r)
    check("这条判定不记账（还没到终态）", _recorded == [], _recorded)

    _pool.penalize("u1", 999.0)           # 比整套退避还久（凭证失效那种）
    _recorded.clear()
    _r2 = _no_slot(_H()._error, "glm-5.3", time.time())
    check("**冷却比整套退避还久时如实报 429**",
          _r2[1][0] == 429, _r2)
    check("429 的说明指出真实原因是冷却（不是「容量满」）",
          "cooling" in _r2[1][1], _r2[1][1])
    check("**这条 429 记账了**（以前一行都不落）", len(_recorded) == 1, _recorded)

    # 没有可用账号 → 503 且记账
    C.load_sessions = lambda _d: []
    _recorded.clear()
    _r3 = _no_slot(_H()._error, "glm-5.3", time.time())
    check("没有可用账号时回 503 而不是误导性的 429",
          _r3[1][0] == 503, _r3)
    check("503 同样记账", len(_recorded) == 1, _recorded)
    C.load_sessions = lambda _d: [dict(_SESSION)]
finally:
    P.record_error = _saved_record

# 2.2 重新登录 / 续期要清掉冷却
_pool.penalize("u1", 300.0)
_pool.penalize("u1", 300.0, model="glm-5.3")
check("冷却同时记在账号级与模型级",
      _pool.cooling_for("u1", "glm-5.3") > 0, None)
P.codearts_clear_cooldown_for("L")        # 按昵称清
check("**重新登录后按昵称清掉冷却**（不再「刚登录还是 429」）",
      _pool.cooling_for("u1", "glm-5.3") == 0.0,
      _pool.cooling_for("u1", "glm-5.3"))
_pool.penalize("u1", 300.0)
P.codearts_clear_cooldown_for("u1")       # 按 id 清
check("按账号 id 也能清", _pool.cooling_for("u1") == 0.0, None)
_pool.penalize("u1", 300.0)
P.codearts_clear_cooldown_for("")
check("空参数不清任何东西（不会误伤其它号）",
      _pool.cooling_for("u1") > 0, None)

_src = io.open(P.__file__, encoding="utf-8").read()
check("登录成功路径调用了清冷却",
      "codearts_clear_cooldown_for(detail)" in _src, None)
check("手动续期路径也调用了",
      _src.count("codearts_clear_cooldown_for(") >= 3, None)

C.load_sessions = _orig_load
P._CODEARTS_POOL = _orig_pool


# ---------------------------------------------------------------------------
# 3. 高：非流式 Messages 丢工具调用
# ---------------------------------------------------------------------------

section("3. 非流式 Messages 保留工具调用")

_chat_obj = {
    "id": "chatcmpl-x", "model": "glm-5.3",
    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": "",
        "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "read_file",
                                     "arguments": '{"path": "/tmp/a"}'}}]}}],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
}
_msg = PR.chat_to_messages(_chat_obj)
check("返回 content 里有 tool_use 块",
      any(b.get("type") == "tool_use" for b in _msg.get("content") or []),
      _msg.get("content"))
check("**stop_reason 是 tool_use（不是 end_turn）**",
      _msg.get("stop_reason") == "tool_use", _msg.get("stop_reason"))
_use = next((b for b in _msg.get("content") or []
             if b.get("type") == "tool_use"), {})
check("工具名与参数都带出来了",
      _use.get("name") == "read_file"
      and (_use.get("input") or {}).get("path") == "/tmp/a", _use)

_plain = PR.chat_to_messages({
    "choices": [{"index": 0, "finish_reason": "stop",
                 "message": {"role": "assistant", "content": "hello"}}],
    "usage": {}})
check("没有工具调用时 stop_reason 仍是 end_turn",
      _plain.get("stop_reason") == "end_turn", _plain.get("stop_reason"))

_i = _src.find("def _messages_codearts(")
_j = _src.find("def _messages_codearts_stream(")
_branch = _src[_i:_j] if _i >= 0 and _j > _i else ""
check("**非流式分支真的传了 tool_calls**（以前只传 content/reasoning）",
      'message["tool_calls"] = tool_calls' in _branch, None)
check("非流式分支用 _chat_finish_reason 而不是写死 stop",
      "_chat_finish_reason(" in _branch
      and '"finish_reason": "stop"' not in _branch, None)


# ---------------------------------------------------------------------------
# 4. 高：finish_reason=error 在 Messages / Responses 流式里必须算失败
# ---------------------------------------------------------------------------

section("4. finish_reason=error 在三条流式入口都算失败")

check("ca_stream.finish_error 认得 error（大小写无关）",
      ST.finish_error({"finish_reason": "error"})
      and ST.finish_error({"finish_reason": "ERROR"}))
check("正常 finish_reason 不算错误",
      not ST.finish_error({"finish_reason": "stop"}))

_raised = None
try:
    list(ST.tap_lines([b'data: {"choices":[{"delta":{"content":"half"},'
                       b'"finish_reason":"error"}]}\n'], {}))
except ST.UpstreamErrorFrame as exc:
    _raised = exc
check("**tap_lines 在 finish_reason=error 时抛 UpstreamErrorFrame**",
      _raised is not None and "error" in str(_raised), _raised)

_ok_frames = list(PR.stream_responses_events(
    [b'data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n',
     b"data: [DONE]\n"], "m", {}))
check("正常收尾时 Responses 仍然发 response.completed",
      any(b'"response.completed"' in f for f in _ok_frames), len(_ok_frames))
_m_ok = list(PR.stream_messages_events(
    [b'data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n',
     b"data: [DONE]\n"], "m"))
check("正常收尾时 Messages 仍然发 message_stop",
      any(b"event: message_stop" in f for f in _m_ok), len(_m_ok))

for _name in ("_handle_codearts_chat_stream", "_responses_codearts_stream",
              "_messages_codearts_stream"):
    _k = _src.find("def " + _name)
    _nxt = _src.find("\n    def ", _k + 10)
    _body = _src[_k:_nxt if _nxt > 0 else len(_src)]
    # Chat 入口不用 tap_lines，自己逐帧解 JSON 并判 frame_error；另外两个
    # 走 tap_lines，靠 UpstreamErrorFrame 打断翻译器。两者都必须让错误压过
    # 完成 —— 判据是「这条路径认得帧内错误」。
    check("%s 认得帧内错误" % _name,
          ("UpstreamErrorFrame" in _body or "frame_error(" in _body), None)


# ---------------------------------------------------------------------------
# 5. 高：tool_result 里的图片
# ---------------------------------------------------------------------------

section("5. tool_result 的图片不再拼成 base64 文本")

_png = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
        "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
_msgs5 = PR.messages_to_chat({
    "model": "glm-5.3",
    "max_tokens": 1024,
    "messages": [{
        "role": "user",
        "content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [
                 {"type": "text", "text": "screenshot:"},
                 {"type": "image", "source": {"type": "base64",
                                              "media_type": "image/png",
                                              "data": _png}},
             ]},
        ],
    }],
})["messages"]
_flat = json.dumps(_msgs5, ensure_ascii=False)
# 图片本身就该以 image_url 的 data URL 形式交给上游（多模态输入的标准形状）；
# 要钉的是**文本字段**里不再出现那一大坨 base64 —— 以前它被拼进 tool 消息的
# content，模型看不到图，还白占几十万字符的上下文。
_tool_text = next((m.get("content") for m in _msgs5 if m.get("role") == "tool"
                   and isinstance(m.get("content"), str)), "")
check("**tool 消息的文本里没有 base64 图片**",
      "base64" not in _tool_text, _tool_text[:300])
check("图片作为独立的 image_url 分片交给上游", "image_url" in _flat, _flat[:500])
check("文本部分仍然保留", "screenshot:" in _flat, _flat[:300])
check("工具结果里留了一句占位说明（模型知道图在后面）",
      "image omitted" in _flat or "Images returned" in _flat, _flat[:400])


# ---------------------------------------------------------------------------
# 6. 高：非流式丢 finish_reason=length
# ---------------------------------------------------------------------------

section("6. 非流式保留 finish_reason=length")

_tail6 = {}
_content6, _reasoning6, _usage6, _err6, _calls6 = ST.collect_sse(
    'data: {"choices":[{"delta":{"content":"trunc"},"finish_reason":"length"}]}\n'
    'data: [DONE]\n', _tail6)
check("collect_sse 回填 finish_reason",
      _tail6.get("finish_reason") == "length", _tail6)
check("正文照常收集", _content6 == "trunc", _content6)

check("_chat_finish_reason 透传 length（不再一律 stop）",
      P._chat_finish_reason("length", False) == "length",
      P._chat_finish_reason("length", False))
check("有工具调用时归 tool_calls",
      P._chat_finish_reason("stop", True) == "tool_calls", None)
check("空值退回 stop", P._chat_finish_reason("", False) == "stop", None)
check("未知值也退回 stop（不把怪值透给客户端）",
      P._chat_finish_reason("weird_value", False) == "stop", None)

_i = _src.find("def _handle_codearts_chat(")
_j = _src.find("\n    def ", _i + 10)
_chat_branch = _src[_i:_j] if _i >= 0 else ""
check("**非流式 Chat 用 _chat_finish_reason 渲染**",
      "_chat_finish_reason(" in _chat_branch, None)
check("非流式 Chat 不再写死 finish_reason=stop",
      '"finish_reason": "stop"' not in _chat_branch, None)


# ---------------------------------------------------------------------------
# 7. 高：chat 缺省 max_tokens 用目录值，负数不接受
# ---------------------------------------------------------------------------

section("7. max_tokens 缺省 / 负数")

_default7 = P._codearts_max_tokens({"model": "glm-5.3", "messages": []})
check("**缺省值取模型目录（不是写死的 4096）**", _default7 > 4096, _default7)
check("负数被当成缺省，不透传给上游",
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": -5})
      == _default7,
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": -5}))
check("0 同样按缺省（0 个 token 没有意义）",
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": 0})
      == _default7)
check("正常值原样保留",
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": 1234}) == 1234)
check("明确的值即便很大也不截顶",
      P._codearts_max_tokens({"model": "glm-5.3", "max_tokens": 32000}) == 32000)


# ---------------------------------------------------------------------------
# 8. 安全：settings.json 读失败 → 鉴权 fail closed
# ---------------------------------------------------------------------------

section("8. settings.json 读失败不再把鉴权全开")

import ca_settings as SET  # noqa: E402

_dir8 = tempfile.mkdtemp(prefix="round5-settings-")
_orig_dir8 = P.ACCOUNTS_DIR
_orig_api_key8 = P.API_KEY
P.ACCOUNTS_DIR = _dir8
try:
    with io.open(os.path.join(_dir8, "settings.json"), "w",
                 encoding="utf-8") as fh:
        fh.write("{ this is not json")
    SET.load(_dir8)                       # 读一次才谈得上「上一次读失败了」
    check("坏文件被记为读失败", SET.last_load_error() is not None,
          SET.last_load_error())
    check("**读失败时 auth_required 为真（fail closed）**",
          P.auth_required() is True, None)
    check("读失败时默认密码不再算「默认密码」",
          SET.panel_password_is_default(_dir8) is False, None)
    check("读失败时 verify 一律 False",
          SET.verify_panel_password(_dir8, "admin") is False, None)

    with io.open(os.path.join(_dir8, "settings.json"), "w",
                 encoding="utf-8") as fh:
        fh.write('{"api_keys": [{"key": "k1", "enabled": true}]}')
    SET.load(_dir8)
    check("**文件修好之后读失败标记被清掉**",
          SET.last_load_error() is None, SET.last_load_error())
    check("修好之后能读到 key", len(SET.load(_dir8).get("api_keys") or []) == 1)

    _dir8b = tempfile.mkdtemp(prefix="round5-settings-empty-")
    SET.load(_dir8b)
    check("**文件不存在 ≠ 读失败**（全新安装仍然当成没配置）",
          SET.last_load_error() is None, SET.last_load_error())
finally:
    P.ACCOUNTS_DIR = _orig_dir8
    P.API_KEY = _orig_api_key8


# ---------------------------------------------------------------------------
# 9. 安全：/oauth/callback 的 XSS / CRLF / 开放重定向 / pending 过期
# ---------------------------------------------------------------------------

section("9. /oauth/callback 的三个漏洞")

_page = C.callback_page(False, "登录失败",
                        '<script>alert(1)</script><img src=x onerror=alert(2)>')
check("**detail 里的脚本被转义**", "<script>" not in _page, _page[:200])
check("转义后仍然是人话", "&lt;script&gt;" in _page, None)
check("CSS 里的百分号没被转坏（50%% → 50%）",
      "border-radius:50%" in _page and "50%%" not in _page, None)
check("detail 为 None 不炸", bool(C.callback_page(True, "成功", None)))

_ok9 = P.Handler._codearts_redirect_ok
_redir_cases = [
    ("https://auth.huaweicloud.com/x", True),
    ("https://www.myhuaweicloud.com:443/a?b=c", True),
    ("http://127.0.0.1:3000/cb", True),
    ("http://[::1]:9000/cb", True),
    ("http://localhost:8123/", True),
    ("https://evil.com", False),
    ("https://huaweicloud.com.evil.com/", False),
    ("https://evil.com\\@huaweicloud.com/", False),
    ("https://evil.com/@huaweicloud.com", False),
    ("https://user@huaweicloud.com/", False),
    ("https://huaweicloud.com\r\nSet-Cookie: a=b", False),
    ("https://huaweicloud.com\nX: y", False),
    ("https://huaweicloud.com\tevil", False),
    ("javascript:alert(1)", False),
    ("//huaweicloud.com/", False),
    ("", False),
    ("https://huaweicloud.com:99999/", False),
]
for _t9, _want9 in _redir_cases:
    check("redirect 白名单：%r → %s" % (_t9[:44] or "空", _want9),
          _ok9(_t9) is _want9, _ok9(_t9))

_mgr = C.LoginManager(tempfile.mkdtemp(prefix="round5-login-"))
_mgr._pending = {"t1": {"status": "pending",
                        "created": time.time() - C.LOGIN_TTL_SECONDS - 100,
                        "message": ""}}
check("**过期的 pending 不再被 accept_callback 采用**",
      _mgr._current() is None, None)
check("并且被标成 expired", _mgr._pending["t1"]["status"] == "expired", None)
_kind9, _detail9 = _mgr.accept_callback(code="abc")
check("回调得到的是「没有等待中的登录」而不是继续换 token",
      _kind9 == "error" and "没有正在等待" in _detail9, (_kind9, _detail9))

_mgr._pending = {"t2": {"status": "pending", "created": time.time() - 1,
                        "message": ""}}
check("新鲜的 pending 照常可用", _mgr._current() is not None, None)


# ---------------------------------------------------------------------------
# 10. 安全：面板登录限速不能被并发绕过
# ---------------------------------------------------------------------------

section("10. 面板登录限速：并发也数得清")

_i = _src.find('if path == "/panel/login":')
_j = _src.find('if path == "/panel/logout":', _i)
_login_body = _src[_i:_j] if _i >= 0 and _j > _i else ""
check("**计数在放锁之前就占位**（attempts.append(now) 在 with 里）",
      "attempts.append(now)" in _login_body, None)
check("占位之后才验密码",
      _login_body.find("attempts.append(now)")
      < _login_body.find("verify_panel_password"), None)
check("成功时清掉自己刚占的位",
      "_login_attempts.pop(client_ip, None)" in _login_body, None)


# ---------------------------------------------------------------------------
# 11. 中：Responses 不提前发 200 / 心跳不被吞掉
# ---------------------------------------------------------------------------

section("11. Responses 生命周期延后 + 两个入口转发心跳")

_pulled = {"n": 0}


def _counted(lines):
    for _line in lines:
        _pulled["n"] += 1
        yield _line


def _first_frame(lines):
    _pulled["n"] = 0
    _gen = PR.stream_responses_events(_counted(lines), "m", {})
    _first = next(iter(_gen))
    return _pulled["n"], _first


for _label11, _lines11 in [
        ("正常数据帧", [b'data: {"choices":[{"delta":{"content":"hi"}}]}\n']),
        ("只有心跳", [b": keepalive\n"]),
        ("只有 [DONE]", [b"data: [DONE]\n"]),
]:
    _n11, _frame0 = _first_frame(_lines11)
    check("**%s：第一帧产出时上游已经读过（没提前承诺 200）**" % _label11,
          _n11 >= 1, _n11)
    check("%s：产出的第一帧就是 response.created" % _label11,
          b"event: response.created" in _frame0, _frame0[:80])

_R_frames = list(PR.stream_responses_events(
    [b'data: {"choices":[{"delta":{"content":"a"}}]}\n', b": keepalive\n",
     b": keepalive\n", b"data: [DONE]\n"], "m", {}))
_R_notes = [f for f in _R_frames if f.startswith(b":")]
check("**Responses 把心跳转会成 SSE 注释行（以前整行被丢）**",
      len(_R_notes) == 2, len(_R_notes))
check("注释行在开场之后（不会先发字节再失败）",
      _R_frames[0].startswith(b"event: response.created"), _R_frames[0][:40])

_M_frames = list(PR.stream_messages_events(
    [b'data: {"id":"i","model":"m","choices":[{"delta":{"content":"a"}}]}\n',
     b": keepalive\n", b"data: [DONE]\n"], "m"))
_M_heads = [f.split(b"\n", 1)[0] for f in _M_frames]
check("**Messages 用协议内的 ping 事件转发心跳**",
      b"event: ping" in _M_heads, _M_heads)
check("ping 在 message_start 之后",
      _M_heads.index(b"event: ping") > _M_heads.index(b"event: message_start"),
      _M_heads)
check("Messages 的 ping 帧是合法 SSE（有 data 行）",
      any(b"event: ping\ndata: " in f for f in _M_frames), None)

_M_before = list(PR.stream_messages_events([b": keepalive\n", b"data: [DONE]\n"],
                                           "m"))
check("**开场前的心跳不发 ping**（否则 200 被提前承诺）",
      not any(b"event: ping" in f for f in _M_before), _M_before)

_R_empty = [f.split(b"\n", 1)[0] for f in PR.stream_responses_events(
    [b"data: [DONE]\n"], "m", {})]
check("**空流仍然先发 response.created**",
      bool(_R_empty) and _R_empty[0] == b"event: response.created",
      _R_empty[:3])
check("空流最后是 response.completed",
      bool(_R_empty) and _R_empty[-1] == b"event: response.completed",
      _R_empty[-3:])


# ---------------------------------------------------------------------------
# 12. 中：断流重开失败不能往 200 流里写 HTTP 状态行
# ---------------------------------------------------------------------------

section("12. 重开失败只写帧内错误，不再塞整个 HTTP 响应")

_i = _src.find("def _handle_codearts_chat_stream(")
_j = _src.find("\n    def ", _i + 10)
_stream_body = _src[_i:_j] if _i >= 0 else ""
check("**chat 流式的重开轮用 defer_errors=True**（不在流里写 HTTP）",
      "defer_errors=True" in _stream_body, None)
check("拿到 _DeferredHTTPError 后按 headers_sent 二选一",
      "_DeferredHTTPError" in _stream_body
      and "return self._reply_deferred(exc)" in _stream_body, None)
check("发过头时写的是本协议的 error 帧 + [DONE]",
      'emit({"error": {"message": exc.message,' in _stream_body, None)
check("_DeferredHTTPError 只是载体（不自己写响应）",
      "class _DeferredHTTPError" in _src
      and "self.status = int(status)" in _src, None)
check("_reply_deferred 按协议选信封",
      "_reply_deferred" in _src
      and "return self._anthropic_error(exc.status" in _src, None)


# ---------------------------------------------------------------------------
# 13. 中：Messages / Responses 首帧前的泛异常不写裸 SSE
# ---------------------------------------------------------------------------

section("13. 首帧前的异常回干净的 HTTP 错误码")

for _name13 in ("_responses_codearts_stream", "_messages_codearts_stream"):
    _k13 = _src.find("def " + _name13)
    _nxt13 = _src.find("\n    def ", _k13 + 10)
    _body13 = _src[_k13:_nxt13 if _nxt13 > 0 else len(_src)]
    check("%s 的兜底异常分支判了 headers_sent" % _name13,
          "if not headers_sent:" in _body13, None)
    check("%s 首帧前回的是真错误信封而不是裸帧" % _name13,
          ("return self._error(502" in _body13
           or "return anthropic_error(" in _body13), None)


# ---------------------------------------------------------------------------
# 14. 中：Chat 流式名额要等 [DONE] 之后才还
# ---------------------------------------------------------------------------

section("14. 名额与 idle 排在 [DONE] 之后")

_i14 = _src.find("def _handle_codearts_chat_stream(")
_j14 = _src.find("\n    def ", _i14 + 10)
_body14 = _src[_i14:_j14]
check("**正常收尾的标记由本轮自己在 finally 之前算**",
      "finished_normally = (not truncated and not frame_err" in _body14, None)
check("finally 里按这个标记决定要不要先还名额",
      "if not finished_normally:" in _body14, None)
check("**没给客户端发过字节时不算正常收尾**（否则名额永远不还）",
      "and headers_sent)" in _body14, None)
check("[DONE] 之后才 release_slot",
      _body14.find('self.wfile.write(b"data: [DONE]\\n\\n")')
      < _body14.find("done_lease.release_slot()"), None)
check("hold_slot 这个失效的循环外变量已经删掉（以前是死代码）",
      "hold_slot" not in _body14.split("finished_normally")[0]
      or "``hold_slot``" in _body14, None)


# ---------------------------------------------------------------------------
# 15. 中：预算估算要把下一段退避的 sleep 算进去
# ---------------------------------------------------------------------------

section("15. 重试预算把退避 sleep 也算进去")

for _name15 in ("_codearts_chat_result", "_codearts_open_lease"):
    _k15 = _src.find("def " + _name15)
    _nxt15 = _src.find("\n    def ", _k15 + 10)
    _body15 = _src[_k15:_nxt15 if _nxt15 > 0 else len(_src)]
    check("%s 的预算估算里加了下一段退避 delays[attempt]" % _name15,
          "delays[attempt]" in _body15, None)


print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)

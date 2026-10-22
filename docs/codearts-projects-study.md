# 码道（CodeArts Agent）同类项目学习笔记

> 2026-10-22。目的：把六个把 CodeArts 逆向成 OpenAI/Anthropic 兼容网关的项目读一遍，
> 重点看**账号池**、**会话生命周期**、**三个协议的适配**、**流式与断流处理**，
> 再对照我们自己的实现决定哪些该抄。
>
> 所有结论都标注了来源文件；带「实测」的是我在线上账号上真跑过的，不是照抄注释。

## 一、看了哪些

| 项目 | 语言 | 规模 | 有 Responses? | 值得看的地方 |
|---|---|---|---|---|
| [`2951461586/CodeArts2API`](https://github.com/2951461586/CodeArts2API) | Go | `internal/{codearts,server,registry}` | ❌ | `started` 标志、账号失败计数、SSE 聚合 |
| [`RobbsLuo/Coding2API`](https://github.com/RobbsLuo/Coding2API) | Python | `src/engine` + `src/compat/{openai,anthropic,responses}` | ✅ | 调度打分、会话粘性、错误分类冷却、SSE keepalive |
| [`hj01857655/CodeArts2api`](https://github.com/hj01857655/CodeArts2api) | Python(Flask) | `routes/` + `adapters/` + `lanes/session.py` | ✅ | **会话心跳 busy/idle**、断流不补 stop |
| [`knownothing20/agent2api-fix`](https://github.com/knownothing20/agent2api-fix) | Rust(Tauri) | `providers/codearts/session.rs` | ✅ | 心跳五条规则 + 签名带 Host |
| [`cnb.cool/itq5/codearts2api`](https://cnb.cool/itq5/codearts2api) | Go | `internal/{pool,scheduler}` | ❌ | `MaxConcurrent=1`、token 看门狗 |
| [`johnsheng1/codearts2api`](https://github.com/johnsheng1/codearts2api) | Python | 单文件 `server.py` | ❌ | 最小实现，可当协议样板 |

另外 `hj01857655` 仓库里带了官方客户端反编译产物（`re/bun_extract/root_chunk-*.js`），
里面有真实的 `ChatSessionHeartbeat` 插件实现，是上面那套心跳的原始出处。

---

## 二、最重要的发现：上游并发名额要「心跳注销」，关连接不算释放

### 现象

我们的日志（2026-10-22，`~/codearts-hub/logs/gw.log`）：

```
16:02:51 codearts retry 1/3: ... cause={"error_code":"TM.00001041",
         "error_msg":"并发会话数已达上限(3个)，请关闭部分会话后重试。"}
16:02:55 codearts retry 2/3: ... 同样 1041
16:03:03 codearts retry 3/3: ... 同样 1041
```

问题在于：**我们本地同时最多只有 2 条请求**（`CODEARTS_CONCURRENCY=2`），
却撞了「3 个会话已满」。说明上游记着的会话数比我们实际在跑的多。
同一份日志里还有 21 次 `http.client.IncompleteRead` —— 会话被服务端回收时
直接把 TCP 掐了，这就是用户看到的「直接断流」。

### 真相（三个项目独立得出同一结论）

`hj01857655/CodeArts2api/lanes/session.py` 开头写得很直白：

> 上游（snap-access）对每个账号只放 3 路并发对话，放不下时报 TM.00001041（HTTP 400）。
> 这个闸门**不认「请求结束」**，只认
> `PUT /snap-manager/v1/chat-session/heartbeat?status=busy|idle`。
> 我们以前既不发心跳、请求里也不带 user-session-id，于是每个请求都让上游
> **隐式开一个会话且永不注销**：3 个槽很快占满，之后一律 TM.00001041，
> 而我们的退避重试等的是别人释放，上游只肯按超时回收。

`knownothing20/agent2api-fix` 的 Rust 版把规则写成了五条（每条都有测试）：

1. 周期 busy 续期失败**不释放槽位**（一次抖动 ≠ 对话结束）
2. 首次 busy 非 200 也要注销刚生成的那个 id
3. **只注销自己造的 id**（给别人的会话发 idle 等于踢掉别人的对话）
4. idle 恰好一次，且在最后一次 busy 落地之后
5. 本地准入满员回 **409**，不是 429（429 会被编排层当成额度耗尽去长冷却）

官方客户端的实现（反编译 bundle，`ChatSessionHeartbeat` 插件）：

```js
const q1n = "/snap-manager/v1/chat-session/heartbeat";
// session.status = busy → 立即 busy，并起 interval(30000) 续期
// session.status = idle → idle，成功后清 interval
```

### 我自己的实测（线上真实账号，不是照抄）

| 方法 | 形态 | 结果 |
|---|---|---|
| `PUT` | `?status=busy` + body `{}` | **200 `{"status":"ok"}`** ✅ |
| `PUT` | `?status=busy` + body `''` | **200 `{"status":"ok"}`** ✅ |
| `PUT` | status 放 body | 400 `TM.00001001 参数校验失败: wsf.validator.session.status` |
| `POST` | 同路径 | 404 `APIG.0101 The API does not exist: method POST not found` |
| `GET` | 同路径 | 404 `APIG.0101 ... method GET not found` |

另外两个坑：

- **必须带 `X-Security-Token`**（STS 临时凭据三件套里的 token）。只签 AK/SK
  会回 `APIG.0301 access key ... is not found` —— 这个报错看起来像 AK 过期，
  其实是没带临时 token。
- **`user-session-id` 必须参与签名**。心跳和聊天请求都要带同一个 id；
  聊天那边改了头不重签，上游按 SignedHeaders 校验会直接 401。

完整链路实测（同一个 session id）：

```
busy  → 200 {"status":"ok"}
POST /api/v2/chat/completions + user-session-id → 200，正常出 reasoning delta
idle  → 200 {"status":"ok"}
```

### 我们已经落地的

- `ca_codearts.heartbeat()` / `new_session_id()`
- `chat_headers(..., session_id=...)` → 带 `user-session-id` 并参签
- `_CodeartsLease` 持有会话：`lines()` 每 30s 续期 busy，`close()` 关连接 +
  还本地名额 + idle 注销（幂等）
- 聚合路径（非流式）同样 busy/idle
- 建连失败时立刻 idle 掉刚 busy 的 id（规则 2）

---

## 三、账号池：三种层次

### 1. 最简：轮转 + 失败计数（`2951461586/CodeArts2API`）

```go
// internal/store/store.go NextAccount
idx := (s.rotate + i) % n
if best == nil || a.Failures < best.Failures { best = a }
if a.Failures == 0 { s.rotate = (idx+1)%n; return a }   // 健康号直接给
```

配合 `withAccountRetry`：

- `ctx.Err()`（客户端断开）→ **不计账号失败**
- `IsTransientUpstream`（`TM.00001041` / 429 / 5xx）→ **不惩罚账号**，只退避重试
- 其它（4xx 鉴权等）→ `MarkAccountResult(false)` 累计失败

这套很轻，适合 2~3 个号。

### 2. 打分排序（`Coding2API/src/engine/scheduler.py`）

`Scheduler.select` 的排序键，从前往后：

```
免费优先(credit_rate==0) → pinned → 在途最少 → 主窗口(36h)内将过期额度多者
→ 次窗口(7d)内将过期额度多者 → 健康度 rank → 健康度值 → 剩余积分多 → id
```

注释里有一个很实在的教训：

> 到期/健康度是**静态**指标，按它们排出的次序是确定的 —— 所有并发请求会算出
> 同一个最优号并全部压上去（实测 2 小时里一个号吃了 180+ 次、其余基本闲置）。
> 在途数把「正在被占用的号」排到后面，并发自动摊到空闲号。

错误分类 → 冷却（`note_error`）：

| 类别 | 处理 |
|---|---|
| DEAD | 硬禁用 |
| PLAN | 12h 长冷却，清 err_count |
| CREDIT | 冷却到次日 04:00（等签到恢复） |
| SOFT | 短冷却，**不累计** err_count（防雪崩） |
| OTHER | 累计，达阈值 → 中冷却 |
| CONCURRENCY / MODEL / BLOCKED | 只写 **(凭证, 模型)** 条目，不动账号级 |
| REQUEST | **零动作**（不是账号的错） |

「模型级冷却」是我们没有的：同一个号上，模型 A 限流不该影响模型 B。

### 3. 本地准入闸（`hj01857655` / `agent2api-fix`）

按账号计在途会话数，上限 3，满员直接 409。key 是
`sha256(base_url + "\n" + account_id)`。

**不能用 AK 当 key**：AK 每次续期都换，拿它当 key 会让「同一账号」每刷一次期
就变成一个新闸门口，3 路上限被悄悄重置 —— 等于没限。我们的池子用的是
`account.id`，这点是对的。

### 补充：上游限制的口径可能不是「同时在途」

`Coding2API/src/tasks/pacer.py` 里有一段很具体的实测：

> 它限制的不是「同时在途」，而是「**每账号每约 60s 最多 3 个会话**」：
> 会话在 HTTP 流结束后仍滞留数十秒（3 并发打满后，单请求直到约 68s 才恢复）。
> 纯在途上限挡不住「3 个并发刚结束就立刻再发 3 个」这类突发。

它为此加了**滑动窗口**限流（最近 N 秒最多放行 K 次启动）。但这个结论是在
**没有心跳注销**的前提下测出来的。

我们有了 busy/idle 之后复测：连续 10 个请求（每个 2~5s）**全部 200，0 次 1041**。
说明 idle 让名额实时回收之后，那个「滞留数十秒」的窗口不再成立，**不需要**
再加滑动窗口限流 —— 加了反而会把吞吐压到每分钟 3 次。

### 我们自己现在的状态

`_CodeartsAccountPool`：每账号一个 `Semaphore(CODEARTS_CONCURRENCY=2)` +
一等冷却表（5s / 20s / 300s 三档）+ 在跑计数。比上面第 1 种强（有在途控制），
比第 2 种弱（没有打分、没有模型级冷却、没有会话粘性）。

**建议按优先级补**：

1. ✅ 会话心跳（已做，这才是 1041 的根因）
2. 会话粘性：同一对话固定同一账号（见下）
3. 模型级冷却：`(account, model)` 维度
4. 冷却分档细化：把 409/1041 与 TPM 429 分开（现在只有 5s vs 20s）

---

## 四、会话粘性（多账号时必须有）

`Coding2API/src/engine/affinity.py` 的三层识别，按可靠性排序：

1. **请求体显式会话标识**：`conversation_id` / `conversationId` / `prompt_cache_key`
2. **请求头**：`x-session-id` / `x-opencode-session` / `x-session-affinity`
3. **回落：消息数组增量前缀指纹** —— 下一轮的 messages 以上一轮完整 messages
   为前缀再追加，据此匹配

细节：

- 键里**掺 username**，否则两个用户的 `default` 会串到同一条粘性记录
- 头来源加前缀（`header:abc`），避免与 body 的 `conversation_id:abc` 撞键
- 前缀指纹只在请求体**没有** `user_id` 时才用（同一用户的并行对话前缀可能相同）
- TTL + 条目上限；纯内存即可，重启丢粘性只影响一轮

为什么重要：没有粘性时，同一对话的每轮可能落到不同账号，每个账号都开一条
新会话 —— 在「3 个名额」的账号上，这直接把名额打满。粘性既是体验问题，
也是并发问题。

我们目前**没有粘性**（单账号时无所谓，多账号必须补）。

---

## 五、三个协议的适配

### 分流结构

我们的：`_dispatch_chat_post` 按 path 分 `/v1/chat/completions`、`/v1/responses`、
`/v1/messages`，模型名再分 WorkBuddy / 码道两条上游。

`hj01857655` 的结构更细：`routes/{chat,responses,anthropic}.py` 只管 HTTP，
`adapters/{responses,anthropic}.py` 管纯数据转换（754 / 606 行），
`lanes/` 管上游通道（benefit / credit / oauth / session）。

`CodeArts2API-Go` 甚至把这条写进了 `internal/protocol/SPEC.md`：

> **不依赖任何内部包**，不碰网络、存储、日志、context。输入字节/结构体，
> 输出字节/结构体。**不做 HTTP 判断。**
>
> 理由：转换逻辑原本锁在一个依赖 `net/http`、`store`、`codearts` 的 712 行
> 处理器里，只能靠构造整个 Server 来测，而它当时**完全没有测试**。

这条对我们有直接参考价值：`ca_proxy.py` 两万行，协议转换埋在 Handler 里，
只能整机测。

### Responses（Codex CLI）

`Coding2API/src/compat/responses/request.py` 的字段表最完整，几个容易踩的点：

- `include=["reasoning.encrypted_content"]` → **接受并忽略**。Codex CLI 每轮都带，
  400 会直接打死主客户端
- `reasoning` / `compaction` 两类 input item → **丢弃**（chat 没有等价物），
  但要在注释里显式声明，不能装作支持
- `store=true` / `previous_response_id` / `background=true` → 400（无状态服务
  不假装支持）
- `prompt_cache_key` → 透传（会话粘性用它）
- `max_output_tokens` → `max_tokens`
- `tools: {type:function,name,description,parameters}` → chat 的
  `{type:function,function:{...}}`；非 function 工具 400

### Anthropic Messages（Claude Code）

- `tool_use` → `assistant.tool_calls`；`tool_result` → 独立的 `role:tool` 消息，
  **排在 assistant 之后**（顺序错了上游会拒）
- `thinking` / `redacted_thinking` → **不回流上游**（上游不需要，白烧上下文）
- 单个 text block 摊平成字符串，多块才用数组
- 错误信封必须是 Anthropic 的 `{"type":"error","error":{...}}`，否则 Claude Code
  认不出、当成不可重试的协议错误

### 错误语义映射（Go 版的表最完整）

`CodeArts2API-Go/internal/apierr/apierr.go` 把「内部错误 → 对外表述」做成了
一个纯函数，并且把映射表写进了注释：

| 情况 | 状态码 | OpenAI type | Anthropic type |
|---|---|---|---|
| 账号池为空 | 503 | server_error | overloaded_error |
| **凭据失效（无法续期）** | 502 | **credentials_error** | authentication_error |
| 上游并发上限 / 429 | 429 | rate_limit_error | rate_limit_error |
| 参数 / 模型名不合法 | 400 | invalid_request_error | invalid_request_error |
| 模型不存在 | 404 | invalid_request_error | invalid_request_error |
| 上游 5xx / 网络 | 502 | upstream_error | overloaded_error |

它着重强调的一点：

> 「凭据失效」必须与上游临时故障区分开：前者重试没有意义，只能重新登录；
> 把它报成 overloaded_error 会让客户端一直退避重试。

对照我们改之前的行为：**所有**非 200 都回 502 + `upstream_error`。后果是
`InferHub.001001005.400`（max_tokens 超限）这种纯参数错误也被客户端当成
网关抖动反复重试，日志里每次都是同一个 400。

已改：`_codearts_fail_spec()` + `_codearts_fail()`，429 走 `_rate_limited`
（带 `Retry-After`），其余按表映射；Anthropic 链路用自己那套 type 名。

补充一个容易踩的细节：`TM.00001041` 在 HTTP 上是 **400**，但语义是
「等会儿再来」，所以判断顺序必须**先于**参数错 —— 否则会被映射成 400
`invalid_request_error`，客户端直接放弃。

### 流中错误帧

`hj01857655/routes/chat.py` 的处理值得抄：

```python
# 上游错误帧（如 InferHub.001001005.400 param invalid）：原样透传会被
# Agent Runtime 当成空响应 → "no content and no tool calls" 无限重试。
# 转成 OpenAI error 帧并终止流，让客户端直接看到真实原因。
if chunk.get("error_code") or chunk.get("error_msg"):
    yield error_frame(...); yield b"data: [DONE]\n\n"; return
```

我们已经在做（`frame_err` → error 帧），一致。

它还有一条我们没有的：`_sanitize_tool_calls` —— 清洗「悬空 tool_calls /
孤儿 tool 消息」（客户端中断后上游会拒整条历史）。**待办**。

---

## 六、流式与断流

### 三个项目的共同选择：首帧之前不提交响应头

- Go：`started` 标志，第一个 chunk 到达才 `WriteHeader(200)`
- Python：`emitted` 标志，「出了就**绝不再换模型或换号**（半截输出不可回滚）」
- Rust/Flask 版：同

我们原来「一拿到上游句柄就先回 200」，首帧前失败就把自己逼到死角。
已改成**首帧才发头**：

- 首帧前失败 → 回干净的错误码（502/429），客户端按正常失败重试
- 首帧前断流 → 换号重开一次（客户端完全无感，它只收到过空的 role 帧）
- 已出内容 → **绝不重开**，发 error 帧 + `[DONE]`

### 断流时不要补 finish_reason=stop

`hj01857655/routes/chat.py` 的注释：

> 这里必须跳过下面的补尾逻辑，否则会给半截回答补一个 finish_reason=stop，
> 伪装成正常收尾。

我一开始是补 stop 的（想「别让客户端以为连接丢了」），现在改成 error 帧了 ——
用户看到「回答到一半停了」比看到「回答正常结束但内容不全」更容易判断该重试。

### SSE keepalive（我们还没做）

`Coding2API/src/api/streaming.py`：

> 上游思考/排队时可能长时间不吐字节；nginx `proxy_read_timeout` 默认 60s，
> 空闲超过它就会断开连接。SSE 注释帧被客户端忽略，只为保活。
> `KEEPALIVE_SECONDS = 15.0`

实现要点（它踩过的坑）：

> 取下一帧用**可复用的 Task** 而不是 `wait_for(anext(...))`。后者在超时时会
> cancel 掉 `anext` 协程，取消会穿透进上游生成器并把它关闭 —— **心跳反而变成了
> 断流**。

我们的架构是阻塞读（`resp.read1`），加心跳要另想办法：把 socket 超时设短，
超时就往客户端写 `: keepalive\n\n` 再继续读。

线上现状（2026-10-22 查）：nginx 已经是 `proxy_buffering off` +
`proxy_read_timeout 3600s`，这一层不会 60s 掐断。但日志里有 `POST /cdn-cgi/rum`，
说明中间可能还有 Cloudflare（免费版对无数据的 SSE 约 100s 超时）。
所以 keepalive 仍是**待办**，优先级从 P1 降到 P2 —— 上游首 token 通常 1~3s，
且 reasoning 一直在吐字节，触发概率低但不是零。

**2026-10-22 已实现**（口径与上面「阻塞读」的设想不同）：`iter_sse` 在开始读
之前把底层 socket 的读超时压到 15s，超时**不当作失败**，而是 yield 一个
`KEEPALIVE` 哨兵、接着读同一根连接；调用方把它翻成 SSE 注释行 `: keepalive`。
拿不到 socket（假对象、老版本 http.client）时退回原行为，绝不假装发过心跳。
连续 40 次空等（10 分钟）才判上游卡死，抛 `UpstreamBroken`。

这套做法的关键是**心跳不是往上游发，是往客户端发** —— 中间层掐的是我们到
客户端那一段，而上游那条连接有自己的 180s 读超时。

---

## 七、签名细节（容易静默错的地方）

`agent2api-fix/session.rs` 的注释：

> 心跳请求的签名 **带 Host**（`include_host=true`），与区域 API（不带）不同 ——
> 照参考实现逐字搬，别"统一"掉。

我们的 `aksk_sign` 无条件带 `Host`，两条路都能过（实测）。但要注意：
`canonical_uri` 必须**补尾斜杠**（我们已补，漏了会报
`verify ak sk signature fail`）。

---

## 八、结论：该抄什么

| 优先级 | 事项 | 状态 |
|---|---|---|
| P0 | 会话心跳 busy/idle + `user-session-id` 参签 | ✅ 已上线 |
| P0 | 断流不再冒到 socketserver；首帧前不发头；断流发 error 帧 | ✅ 已上线 |
| P1 | 零内容断流换号重开一次 | ✅ 已上线 |
| P1 | SSE keepalive（防 nginx 60s 空闲断流） | ✅ 已上线（`iter_sse` 空闲 15s yield 哨兵） |
| P1 | 会话粘性（多账号时） | ✅ 已上线（首条 user 消息指纹兜底） |
| P1 | **模型名大小写归一** | ✅ 已上线（线上实测：小写 glm-5.2 曾掉进空池回 503） |
| P1 | 未知模型回 404（而不是空池的 503） | ✅ 已上线 |
| P2 | 福利模型无权益（4004.200）→ 404 且从清单剔除 | ✅ 已上线 |
| P2 | `_sanitize_tool_calls`（悬空 tool_calls 清洗） | ⬜ 待做 |
| P1 | 错误语义映射（429+Retry-After / credentials_error / 400 / 404） | ✅ 已上线 |
| P2 | 模型级冷却 `(account, model)` | ⬜ 待做 |
| P2 | 协议转换抽成纯函数模块（可单测） | ⬜ 待评估 |
| P3 | 本地满员回 409 而不是 429 | 观望（客户端对 409 的处理差异大） |
| — | 滑动窗口限流（每 60s 3 次启动） | ❌ **不做**：心跳 idle 后实测 10 连发 0 次 1041，加了反而压吞吐 |

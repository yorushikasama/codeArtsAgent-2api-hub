# CodeArts Agent 2API Hub — 码道模型网关

把**华为云码道（CodeArts）**的推理能力封装成标准 OpenAI 兼容接口（Chat Completions / Responses），
自带账号管理、额度领取与 Web 看板。

- **开箱即用**：纯 Python 标准库，零第三方依赖；`start-codearts-hub.bat` / `.command` / `.sh` 双击即启；
- **单一上游**：只对接华为云码道（`snap-access.cn-north-4.myhuaweicloud.com`），账号、限额与用量都按这一个出口记账；
- **协议**：Chat Completions、Responses API（Codex）；Anthropic Messages 经协议转换且缓存兼容性未验证，默认禁用；
- **模型清单**：只列出**实测可推理**的模型，不拿服务端目录凑数；
- **账号接入**：看板点链接走华为云 PKCE + DPoP 授权，浏览器直接回跳本机网关，无需手动复制凭证；
- **每日额度**：码道账号每日可领 1000 万 Token 当日有效额度，接口幂等，可手动也可交给调度器；
- **STS 自动续期**：临时凭证约 2 小时到期，网关在快过期时自动续，不用人工干预；
- **并发护栏**：账号并发会话上限只有 3 个，网关串行化 + 退避重试，避免连发撞上限；
- **Web 看板**：指标卡片、模型性能与用量大表、请求流水、码道账号管理一屏可查。

> ⚡ **Vibe Coding 产物**：本项目为 100% Vibe Coding 协同产物——人类开发者提出架构与业务意图，AI 助手端到端完成逆向分析、链路调度与界面编写。

---

## 一、快速启动

### 1. 本机运行

**Windows** 双击 **`start-codearts-hub.bat`**，保持窗口运行；**macOS** 双击 **`start-codearts-hub.command`**
（首次被 Gatekeeper 拦截时右键 →「打开」确认一次），或在终端执行 `./start-codearts-hub.sh [端口]`（默认 8788）。

启动后：**API 地址** `http://127.0.0.1:8788/v1`，**Web 看板** `http://127.0.0.1:8788/`。
首次启动还没有账号，打开看板点「码道账号」完成授权即自动入库。

> 绿色包自带的精简 Python 运行时只覆盖 Windows；macOS / Linux 直接使用系统 Python，需要 **3.9+**。

### 2. 面板访问密码

看板需要**面板访问密码**，它与 API Key 相互独立：密码只用于打开看板，可在「设置」页修改
（或启动时 `--panel-password` 指定），以 PBKDF2-SHA256 摘要存于 `accounts/settings.json`（不存明文）。

本机 / 受信局域网自用可带 `?pwd=面板密码` 免手输直接进面板；**公网暴露时不要用** ——
密码会留在浏览器历史与反向代理日志里。**首次登录后请立即改掉默认密码。**

### 3. Docker 部署

```yaml
services:
  codearts-hub:
    image: ghcr.io/yorushikasama/codeartsagent-2api-hub:latest
    container_name: codearts-hub
    restart: unless-stopped
    ports:
      - "8788:8788"
    environment:
      - HOST=0.0.0.0
      - PORT=8788
      - TZ=Asia/Shanghai
    volumes:
      - ./accounts:/app/accounts
      - ./usage:/app/usage
```

镜像自带 `HEALTHCHECK`（每 30s 探一次 `/health`）。

### 4. 测试

```bash
python tests/run_all.py            # 全部套件
python tests/run_all.py realm      # 只跑名字里含 realm 的
```

- 95 个套件：72 个 Python + 23 个 JS；JS 需要 PATH 上有 `node`，缺失时会跳过并提示。
- `tests/_test_protocol_pure.py` 只 import `ca_protocol`，用来钉住「协议层不依赖 ca_proxy、不碰 I/O」。
- `tests/_test_protocol_golden.py` 对拍两种流式协议的**逐字节帧序列**（`tests/golden/*.json`）。
  只有确认行为变化是想要的才重录：`python tests/record_protocol_golden.py`，录完 review diff。
- 仓库不含 CI：`.github/workflows/` 已整体移除，测试只在本地/服务器手工跑（`--jobs 4` 可并行）。

---

## 二、核心特性

### 1. 码道账号（华为云 PKCE + DPoP）

账号区点「码道账号」→ 弹窗里生成授权链接 → 浏览器完成华为云登录 → 自动 307 回跳
`http://127.0.0.1:<网关端口>/oauth/callback?code=…`，网关当场换 token 落盘。

拿到的是 **STS 临时 AK/SK + securitytoken**（约 2 小时到期）外加一张 **30 天可续期**的 refresh_token。

几个必须知道的边界：

- **浏览器必须能访问到网关端口**。回跳地址写死成 `127.0.0.1:<端口>`（跟官方客户端一致），
  所以网关跑在 NAS / 容器 / 别的机器上时，要先把该端口映射到你自己这台机器。
- **DPoP 私钥与 refresh_token 绑定**（`cnf.jkt` 把 token 钉在登录时那把 P-256 私钥上），
  续期必须用同一把私钥签 proof。私钥随会话存在 `accounts/codearts/<账号ID>.json`，别把该目录同步出去。
- **refresh_token 是一次性轮换**的：每次续期成功都会换一张新的，旧的立即作废。
  若提示 `STS5.1806`，说明这张被别的客户端用掉了或已过 30 天，只能重新登录。
- **STS 到期不等于账号失效**：AK/SK 只是几小时的临时凭据，到期后续期即可，不需要重新走浏览器。

### 2. STS 自动续期

码道的 STS 只有约 **2 小时**寿命。网关在取会话时检查剩余时间，不足 `CODEARTS_REFRESH_MARGIN`
（默认 300 秒）就自动续期；已经过期的会话只要还能续期也会被救活。

三个必须注意的点：

1. **不能每次请求都续** —— refresh_token 一次性轮换，频繁续会疯狂换 token 且并发必然撞车；
2. **续期必须持锁**；
3. **锁内要重读存档** —— 别的线程可能刚续过，拿旧 refresh_token 再换会被判 1806 作废。

阈值可用环境变量 `CODEARTS_REFRESH_MARGIN` 调整。

### 3. 每日额度领取

`GET {权益网关}/api/v1/benefit/claim`，每个账号每天可领一份当日有效的推理额度
（实测每日上限 1000 万 Token，`expire_time = 0` 表示当日有效、0 点清零、不累计）。

- **接口是幂等的** —— 同一天重复调用都返回成功，不会叠加额度。所以「今天领没领」
  **不能靠本地时间戳判断**，唯一的判据是余额：满额（`total_balance == daily_token_limit`）
  且今日消耗为 0，就说明今天的已经在手上。
- 服务端返回的 `update_time` 在连续领取时**不刷新**，只作面板展示，不能当判据。
- 成功判据是 `error_code == "0000"` 而不是 HTTP 状态码：失败也回 200，判状态码会把失败当成功。

### 4. 并发护栏与退避重试

码道账号的**并发会话上限只有 3 个**（撞上就是 `400 TM.00001041 并发会话数已达上限`），
而且上游会把结束的会话再留约 20-30 秒。网关因此：

- **每个账号一个信号量**（默认 2，给 IDE 等其它使用者留 1 个名额），挑号时先看空闲、
  再看冷却，某个号满了自动换号，而不是所有请求排一条队；
- 对瞬时限流做**退避重试**（5/12/25/40 秒，最多 5 次），覆盖
  `429 ModelArts.811xx`（TPM 打满）与 `400 TM.00001041`（并发上限）。

并发、会话续期间隔与两种冷却都能在设置页调（「码道并发与冷却」），保存后**下一个请求
就生效**，不用重启；并发调小时已经在跑的请求不会被中断。

不这么做的话，用户侧看到的是「这个模型坏了」。

### 5. 模型清单

`/v1/models` 只列出**实测可推理**的模型，共 11 个：

```
deepseek-v4-flash-0731   glm-5.3-flash        deepseek-v4-pro-0813
deepseek-v4.1-flash      GLM-5.2              Qwen3-VL-235B
kimi-k2.6-vl             openpangu-2.0-flash  openpangu-2.0-pro
glm-5.3                  glm-5.2-sft-harmony
```

其中 `Qwen3-VL-235B` 与 `kimi-k2.6-vl` 支持读图。清单按「这个部署实际能服务谁」生成：
有码道账号就只列码道模型，不会拿内置快照凑一批调不通的名字。

**只有一条上游**：WorkBuddy 账号池已整体移除（2026-10-23），清单里的每一条都
`owned_by=codearts`，不在清单里的模型名一律回 404 `model_not_found`，不会再有
「清单说是 A、请求却去了 B」的分裂。

### 6. 推理超时

目录类接口 20 秒够用，推理不够 —— 实测 GLM-5.2 单次回答要 17 秒以上，从远端机房打过去更慢。
推理读超时默认 **180 秒**（`CODEARTS_CHAT_TIMEOUT` 可覆盖）。

### 7. 排障速查：三种「看着像网关坏了」的情况

| 症状 | 真实原因 | 怎么办 |
|---|---|---|
| 正文一个字没有，`finish_reason=stop` | `stop` 序列对**思考内容**同样生效：模型在 reasoning 阶段撞上停止串就结束，正文还没开始写。 | 放宽或去掉 `stop`（调试时先别带）；`usage` 里的 reasoning tokens 会明显偏高，可以据此确认。不是「流被吞了」。 |
| 400 `... response_format.type=... is not supported ...` | 上游把 `response_format` 当未知键**忽略**（实测连非法 type 都回 200），网关无法保证 JSON 输出，于是请求阶段直接拒绝，避免客户端拿到散文再解析失败。 | 去掉该字段、自己解析文本；要强制 schema 用 `tools` / function calling。 |
| 400 `messages must contain at least one user or assistant message` | 只发了 system 消息（或空列表）。上游会回 `ModelArts.81001.400 messages 参数非法`，报错点离真正原因很远，网关改成请求阶段就说清楚。 | 把真正的问题作为 user 消息发；Responses 的 `instructions` 不能单独用。 |

流式响应里偶尔出现的 `: keepalive` 是**注释行**（SSE 规范允许，标准客户端都会跳过）：
上游静默超过续期间隔时网关发它，防止中间代理把空闲连接掐掉。它不属于任何帧。

`stop_sequence` 为什么常常是 `null`：上游把命中的停止串从输出里**删掉了**，只回
`finish_reason=stop`，网关无从知道是哪条命中；只有上游真把串吐出来时才会填。
`stop_reason` 仍是准确的 `end_turn`。

---

## 三、账号管理

打开看板，在「账号」页操作。这里只管理码道账号：

- **添加 / 管理**：点「添加 / 管理码道账号」打开弹窗，可看已连接的账号、领当日额度、重新授权；
- **STS 续期**：弹窗里可手动续期；正常情况下网关会自动续，无需人工；
- **删除**：删除某个码道账号的本地会话。

---

## 四、客户端配置与接入

- **API 接口地址 (Base URL)**：`http://127.0.0.1:8788/v1`（局域网为 `http://<局域网IP>:8788/v1`）
- **API Key**：本机单机模式可留空或填任意字符；已配置 Key 请用看板「设置」页里绑好出口的 Key；
- **Key 优先级**：看板是唯一的凭据来源。只要看板配置过 Key（含已禁用、已删除的），`/v1` 就只认看板里启用中的 Key，`--api-key` / `.credentials` 里的 `API_KEY` 一律忽略；看板 Key 全部删除后接口继续要求 Key（返回 401），不会退回启动参数。仅当看板从未配置过 Key 时，`--api-key` 才作为无面板部署的入口生效。鉴权不会因为删光 Key 而自动关闭；确实需要关闭时，请显式设置 `auth_disabled`；
- **模型名称**：填 `/v1/models` 里列出的任意模型 ID（如 `glm-5.3`、`deepseek-v4.1-flash`）。

**Codex CLI / Claude Code（Responses API）**

```bash
export OPENAI_BASE_URL="http://127.0.0.1:8788/v1"
export OPENAI_API_KEY="你在看板设置中添加并绑定的API_Key"
```

---

## 五、看板与接口一览

访问 `http://127.0.0.1:8788/` 使用集成看板：顶部页签是「网关 / 账号 / 数据看板 / 设置 / 运行日志」，
每个主页面左侧有一条按页面区块现场生成的导航。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | / | Web 用量与任务监控看板 |
| POST | /v1/chat/completions | 标准 Chat Completions 接口 |
| POST | /v1/responses | Responses API 协议接口 |
| POST | /v1/messages | 实验性 Anthropic Messages 适配，默认禁用（HTTP 400） |
| POST | /v1/messages/count_tokens | 实验性计数估算接口，随 Messages 入口默认禁用 |
| GET | /v1/models | 实测可用的模型列表（含能力与规格宣告） |
| GET | /accounts/codearts | 码道账号列表：账号名 / STS 剩余时间 / 是否可续期 / 当日额度余额（需面板会话） |
| POST | /accounts/codearts/login/start | 生成码道授权链接（PKCE + DPoP），返回 `authUrl` 与 `state`（需面板会话） |
| GET | /accounts/codearts/login/poll?state= | 轮询码道登录结果：`pending` / `ok` / `error` / `expired`（需面板会话） |
| POST | /accounts/codearts/refresh | 用存档里的 DPoP 私钥 + refresh_token 续一次 STS（需面板会话） |
| POST | /accounts/codearts/claim | 领取当日推理额度。`accountId` 省略则逐个领全部（需面板会话） |
| POST | /accounts/codearts/delete | 删除某个码道账号的本地会话（需面板会话） |
| GET | /oauth/callback | 华为云授权回跳端点（**免面板鉴权**：浏览器 307 裸跳转带不上会话） |

---

## 六、版本更新记录 (Changelog)

<!-- 发版时：把下面的 Unreleased 段落整理成新版本号（## vX.Y.Z），整体移入 docs/CHANGELOG.md 顶部 -->

### Unreleased

**福利渠道下线：删掉 benefit 通道与「每日额度领取」**

- 触发：`deepseek-v4.1-flash` 一直回 `InferHub.4004.200 benefit not found`。归因不是「今天的额度没领」，而是**请求带错了分组开关**：`BENEFIT_MODELS` 里还把它算成福利模型，于是每个请求都带 `maas_type: benefit`，而上游的福利渠道已被官方收回。
- 实测（2026-10-23，同一账号、同一请求形状，只改一个头）：
  - `deepseek-v4.1-flash` 不带 `maas_type` → **200 正常出字**；带上 → `4004.200 benefit not found`。它已经内置化。
  - `deepseek-v4-flash-0731` / `glm-5.3-flash` / `deepseek-v4-pro-0813`：不带 → `002002009 model is not registered`；带上 → `4004.200`。**两条通道都不通**，已从 `CHAT_MODELS` 移除。
  - 权益网关 `opengw /api/v1/gateway/config` 直接回 `[4000] invalid channel, group not found` —— 不是「没领」，是这条账号没有这个渠道。
- 删除：
  - `ca_codearts`：`GATEWAY_HOST`、`gateway_config()`、`normalize_models()`、`BENEFIT_MODELS`、`model_group()`、`MAAS_BENEFIT`、`GROUP_BENEFIT`、`credit_headers()`、`claim_benefit()`、`enable_benefit_claim()`、`tokens_balance()`、`balance_summary()`、`_is_full()`、`record_claim()`、`claim_and_verify()` 全部退场。`model_catalog()` 只取内置目录；`chat_headers()` 不再接受 `maas_type`。
  - `ca_proxy`：`/accounts/codearts/claim`、账号面板的 `balance` 字段，以及 `mark_benefit_missing()` 那套「撞到 4004.200 就把它从清单里临时摘掉」的补丁 —— 福利模型都没了，没有可摘的对象，而且它治的是症状（真因是分组判错）。
  - `ca_scheduler.py` **整个删除**：它唯一的任务是每日 09:00 / 21:00 领额度，渠道没了就是空转。
  - 面板：调度器状态条与「立即巡检保活 / 暂停调度」两个按钮、`loadSchedulerStatus` / `triggerSchedulerNow` / `toggleScheduler`、token 额度行与「领取今日额度」按钮，以及为「渠道没了」准备的「重新授权」分支。
- 保留：**积分两条线不受影响** —— `credit_package()`（snap-manager 的「总已用积分」）与 `welfare_*`（snap-access 的每日签到）。加上已删的 opengw token 额度，原本是三个独立体系；现在账号面板只显示积分与签到状态。
- 测试口径：`_test_codearts.py` 删掉「每日领取」「调度领取前先续期」两段（-64 项），清单段改成「只有内置一组」；`_test_activity_history.py` 只留持久化与读取 API（领取记录三组用例退场）；`_test_codearts_stream_break.py` / `_test_panel_route_auth.py` / `_test_key_model_limits.py` / `_test_dashboard_scope.py` 去掉对已删符号的引用。


**中途错误帧不再被当成正常结束（半截回答不盖章）**

- 现象：上游先吐正文、再塞一个 `error_code` 帧时，客户端收到的是 `200` + `finish_reason=stop` + `[DONE]`，没有 error 帧；`usage.jsonl` 只有一条 `completed`。客户端把半截回答当完整结果，错误不进日志、账上算成功。
- 根因是 chat 流式的收尾只写了「一个字都没出就报错」这一条分支（`frame_err and not content_parts and not reasoning_parts`），**出过内容时没有分支接住 `frame_err`**，直接落到 `emit(frame({}, finish_reason or "stop", …))` + `record_usage(outcome="completed")` —— 正是那段注释里说要避免的「给半截回答盖章」。
- 另外两条入口漏得更彻底：`tap` 只把错误记进 sink 就照常喂给翻译器，翻译器不知道这件事，补了 `response.completed` / `message_stop`；收尾处还是 `if tap["error"] and not usage` —— 上游只要回过 usage，失败就被记成成功，而且失败/成功各落一行（同一请求账上算两次）。
- 聚合路径（非流式）同样有 `and not content and not reasoning`：拼出来的残句被当成完整答案回 200。
- 现在：错误帧一律压过完成。`ca_stream.tail_kind()` 把这条优先级写成显式规则（`error_frame > upstream_aborted > complete`），三个入口共用；`tap_lines` 遇到错误帧直接抛 `UpstreamErrorFrame` **打断翻译器**，由调用方按本协议发错误终态 —— chat 发 `{"error": …}` + `[DONE]`，Responses 发 `response.failed`，Messages 发 `event: error`。失败只落一行账，usage 跟着 `record_error` 走。
- 状态码不再写死 502：过 `frame_status` 那张表，被 TPM 限流就回 429 语义，客户端知道该等而不是该改请求。
- 顺带认两种以前漏掉的失败表达：`{"error": {"code": …, "message": …}}`（OpenAI 兼容层的错误帧）与 `finish_reason="error"`（以前只有 WorkBuddy 那条路认，#389）。
- **分层**：帧解析、收尾判定、上游错误码 → 状态码的映射整块搬进新模块 `ca_stream.py`（360 行，纯函数，只 import `json`），`ca_proxy.py` 20 647 → 19 740 行。以前这套判断散在三个 handler 里，同一种 bug 要修三遍，于是两遍没修。新增 `tests/_test_stream_tail.py`（57 项）钉住三态优先级、两种错误形状、三条入口各自的错误终态，以及「映射表只剩一份」的静态约束。

**移除 WorkBuddy 账号池：网关只服务码道**

- `POOL` 不再创建（恒为 `None`），启动不再读 `accounts/*.json` 的 WorkBuddy 凭据、不再扫桌面端会话、不再有 `--info` / `--import-desktop` / `--user-agent` 三个参数；`/health` 的 `accounts` 语义改成「码道会话数」。
- `/v1/models` 只从码道目录生成：不再合并 WorkBuddy 目录，也不再拿内置快照兜底（没有码道账号就回空清单，并在 `codearts.errors.sessions` 里说明原因）。每条都是 `owned_by=codearts`。
- 三个协议入口（`/v1/chat/completions`、`/v1/responses`、`/v1/messages`）非码道模型一律 **404 `model_not_found`**，不再有「转发到 WorkBuddy 上游」的分支。
- 面板删掉 WorkBuddy 那一整套接口：`/accounts`、`/accounts/export`、`/accounts/credits*`、`/accounts/login/*`、`/accounts/import*`、`/accounts/refresh`、`/accounts/sync-profile`、`/accounts/test`、`/accounts/set*`、`/accounts/delete`、`/accounts/product`、`/tasks*`、`/realm`、`/catalog/refresh`。
- 关键顺序：码道那组 `/accounts/codearts/*` 路由必须排在任何「账号池」判断**之前**。以前那段 `if POOL is None: 503` 会把「加一个码道账号」也一起打死，报错文案还写着 `account pool unavailable` —— 跟码道毫无关系，极难查。
- **代码层同步删干净**（第二步，同一个 2026-10-23）：`ca_accounts.py`（2 929 行）、`ca_identity.py`、`ca_atrest.py`、`ca_tasks.py`、`ca_fingerprint.py` 整体删除；`ca_proxy` 去掉 `open_upstream` 及其调用树（含 `fetch_models` / 产品目录拉取 / 账号探针 / 亲和分页），本地只留一支 `normalize_realm`（单出口下恒为 `cn`）；`ca_scheduler` 只保留码道每日领取。
- **顺带删掉两个「执行器在 WorkBuddy 那边」的功能**：本地网络工具（`ca_webtools` 的代跑循环只存在于已删的 Responses 转发里，留着开关只会注入没人执行的工具定义）与账号日限额三道护栏（`apply_daily_guard*` 全部作用在账号池上，池没了就是空操作）。
- **面板**：删掉积分获取历史、积分与套餐明细弹窗、账号限额、本地网络工具、成长任务、WorkBuddy 账号列表与登录/导入/刷新/导出/删除等一整套 `loadAccounts` / `fetchCredits` / `toggleAccount` / … 脚本与 `/realm` 启动调用；账号页只剩码道账号。
- 随功能一起退场的套件共 33 个（它们测的路径已经不存在），包括 `_test_account_proxy*.py`、`_test_affinity_pages.py`、`_test_balance_park.py`、`_test_catalog_refresh.py`、`_test_credit_grants.js`、`_test_daily_credit_limit.py`、`_test_daily_token_limit.py`、`_test_desktop_*.py`、`_test_error_persistence.py`、`_test_limit_realms.js`、`_test_local_web_tools.py`、`_test_pool_diagnostics.py`、`_test_product_persistence.py`、`_test_prompt_modes.py`、`_test_remaining_*.py`、`_test_restricted_403.py`、`_test_streak_report.py`、`_test_upstream_pool.py`、`_test_upstream_timeouts.py` 等。Anthropic 的协议面仍由 `_test_protocol_golden.py` + `_test_codearts.py` 覆盖，出口退避保留 `_test_egress_backoff.py` 的纯退避那一半。
- **保留但已无调用方**：`ca_settings` 里的三组日限额键与 `limits_data` 迁移（老 `settings.json` 里的历史值仍能读、不被当成坏数据；写入入口只剩设置文件本身）。


**模型清单补上上游新出现的 `kimi-k3`**

- 逐条对过：上游 `/v1/model/builtin` 返回 **9** 个内置模型，网关只广告 **8** 个，缺 `kimi-k3`（上游 `display_enabled=true`，官方 IDE 的模型选择器里看得到）。原因不是取数失败，而是它不在 `CHAT_MODELS` 这张「实测可路由」白名单里 —— 后果很隐蔽：`is_codearts_model("kimi-k3")` 为假，请求掉进 WorkBuddy 池，只配码道账号的部署回 `503 no usable account`，报错和模型名毫无关系。
- 输出上限是**实测**的，不是抄兄弟模型：`65536` → 200 正常出字；`81920` / `100000` / `131072` / `262144` → 全部 `InferHub.001001005.400 The request param is invalid`。所以 `BUILTIN_MODEL_LIMITS["kimi-k3"] = (0, 65536)`：输出 65536，输入窗口留 0（上游不返回，本项目自己不编数字）。
- 这件事顺带证明「实测表必须压过模型知识库」：`ca_modelsdev.CONTEXT_FALLBACK` 里 `kimi-k3` 是 `(1048576, 131072)`，而 **131072 上游必拒**。`lookup()` 的优先级是 `remote > table > cache > default`，我们这条 65536 作为 remote 值生效，清单上的 `max_output_tokens` 才是对的；没这条就会给客户端报一个上游不认的数。上下文 1M 仍由 knowledge table 提供，`context_source` 标成 `table`（面板据此区分「上游说了」和「按 1M 兜底」）。
- 顺带核对了其余 8 条的字段：`count` 与清单一致（8 条码道模型 + 2 条别名 `gpt-5-codex → glm-5.2`、`claude-sonnet-4-5-20250929 → glm-5.3`，目标都在清单里）；`codearts.errors.benefit = [4000] invalid channel` 是这条账号没有福利渠道，属预期（福利组那 3 个模型因此不广告）；`GLM-5.2` 这类大写 id 与小写请求之间由 `resolve_model` 做大小写无关归一，分流不受影响。
- 未修的一条：`kimi-k2.6-vl` 不在 `BUILTIN_MODEL_LIMITS` 里，清单上 `max_output_tokens` 是 null，客户端发大 `max_tokens` 不会被夹。它是上游 `display_enabled=false` 的视觉模型，实测上限还没测到干净值，等有需要再补。

**「静默 60 秒被切」是上游的空闲超时，不是网络抖动**

- 15:15–15:20 同一条请求（`msgs=33 chars=32568 tchars=92258 tools=55`）连撞四次，每次先吐 5.4 / 6.4 / 7.1 / 9.1 KB，然后**一个字节都没有** 59.8 / 59.8 / 60.0 / 60.0 秒，被掐。心跳三条全发出去（`pings=3`）、socket 也在（`sock=True`）—— 与续期无关；同一账号上有 **616 秒成功**的请求，所以也不是「总时长超 60 秒」的限制。结论：上游（APIG 的「后端超时」，默认 60 s）只按**有没有输出**计时。
- 这类失败有个很坑的性质：**同一个请求会一直在同一处被切**。客户端自动重试，表现就是「反复回复同一句话」（用户看到的正是这个）。所以错误帧不再只给 `IncompleteRead(0 bytes read)`，静默 ≥50 s 时补一句 `upstream sent no bytes for 60s and was cut by its ~60s idle limit; … split this turn into smaller steps or lower the thinking budget`，让上层改策略而不是原样重试。
- 三个入口都带上这句（`chat` 用 `stream_stats`；`messages` / `responses` 原来根本不传 stats，现在也传了，于是它们的断流错误里同样看得到 `silent_s`）。
- 诊断口径：`silent_s` 按**任何字节**（含 SSE 注释）更新（见 `ca_codearts.iter_sse`），所以 `silent=60.0` 是真的零字节，不是「没解析出 data 帧」。我们自己的静默上限（`STREAM_IDLE_TIMEOUT` 15 s × `STREAM_MAX_IDLE` 40 = 600 s）比上游宽 10 倍，永远轮不到它先触发。

**重启不再把会话名额丢在上游**

- `idle` 注销写在 `finally` 里，只挡得住异常，挡不住 `systemctl restart` / OOM / 断电。进程一死，那几条 `busy` 就挂在上游直到它自己超时；账号只有 3 个名额，**一次部署就能全占掉**，之后一律 `TM.00001041`，而我们的退避等的是「别人释放」（2026-10-23 15:00–15:03 连着重启五次，那一小时的 1041 全出自这里）。
- 现在把自造过的 `user-session-id` 落盘（`accounts/codearts_sessions.json`，与 `codearts_affinity.json` 同目录、已被 `accounts/*.json` 忽略），`busy` 成功才记、`idle` 成功就销账；启动后由后台线程逐条补发 `idle`，best-effort，不拖启动。
- 三条保守设定：没凭据的条目留到超龄（1 小时）为止，别静默丢账；`idle` 失败的留一会还能再试；清理收尾是**合并写**而不是覆盖 —— 清理期间新登记的会话不会被抹掉（那正好是下一次重启要泄漏的那批）。

**`APIG.0203` 的请求形状可归因，建连预算按「预估下一轮」判断**

- 建连预算的判断时机是错的：原来只看「已经花了多久」，第 1 轮 60 秒 `<` 75 秒预算 → 放行第 2 轮 → 再跑 60 秒，客户端要等 **130 秒**才拿到 504（线上 15:02 实测 129 975 ms）。改成用「再来一轮至少需要一个首字节窗口」预估（`elapsed + min(header_timeout, 60) > CODEARTS_OPEN_BUDGET`），第 1 轮失败后就停；预算日志同时打出 `another attempt needs ~60s, budget 75s`，不用再倒推。
- 成功请求也开始留一行 `chat stream open: … shape=…`。以前只在失败时打形状，而 0203 的典型现象正是**同一形状时好时坏**（15:04 同 `msgs=27 chars=32077 tchars=92258 tools=55` 的请求 33 秒成功，15:02 那条 130 秒失败），没有成功样本就没法对比。一次请求一行，与 `chat done` 同量级。
- 请求形状补充 `think=` 与 `keys=`：前者带 `thinking.type` / `budget_tokens` / `reasoning_effort`，后者是顶层出现的所有额外键。以前只有 `thinking=yes`，分不出是「client 给了个巨大的 budget」还是「多带了个 `stream_options`」把上游顶住的。
- 新增 `dump_failed_request()`：失败时把 **tools / tool_choice / thinking / max_tokens** 落盘到 `usage/failed-req-<ts>.json`，供离线复现（**不含任何消息正文**）。开关 `WB_DUMP_FAILED_TOOLS`，默认关闭，5 分钟内最多一份。实测价值明确：合成的 46KB 工具集永远能过，只有拿到真实的 92 258 字节那套（`CronCreate` 6 239B、`AskUserQuestion` 5 060B…）才确认「形状本身不是根因」。
- 锁住限流映射：`ModelArts.81111`（按 TPM）与 `81114`（按请求数）是同一种瞬时限流，上游有时把它塞在 HTTP 400 的 body 里，以前缺断言。现在两条都钉死为 **429**，避免客户端把「等几秒就好」当成坏请求丢掉。

**失败记账与响应同源，一次失败只落一行**

- `_codearts_open_lease`（流式建连）以前 `record_error(model, 502, …)` 写死 502，而对外走 `_codearts_fail()` 把 `APIG.0203` 映射成 504：同一个失败，`gw.log` / `usage.jsonl` 记 502、客户端收 504。现在记账用 `_codearts_fail_spec()` 算出的同一个状态码（网络异常仍记 502）。
- 流式断流分支以前先 `record_error` 再 `record_usage(..., outcome="upstream_aborted")`，一次失败在 `usage.jsonl` 里落**两行**（同 `iso`、同 `elapsed_ms`，一行 `failed`、一行 `upstream_aborted`）。这违背了 `record_error` 自己的约定（docstring 写明「usage 随行带上，不再单独记一条」，`usage=` 参数此前零调用）。现在 usage 跟着 `record_error` 一起落，只写一行；token 不丢。
- 影响：总量不再被放大一倍；成功率口径不再分裂（矩阵口径把 aborted 算 err 得 34/31≈52%，而按 `outcome=="failed"` 数错误会得 45/20≈69%，同一份数据两个答案）。

**断流归因与续期改造（`IncompleteRead(0 bytes read)`）**

- 2026-10-23 09:11–09:29 出现 11 次 `upstream closed early: IncompleteRead(0 bytes read)`，同一时段还有 APIG 的 `APIG.0203 Backend timeout`（实测约 60 秒一刀）。两者指向同一件事：**上游后端长时间没有输出**——0203 发生在建连阶段（响应头都没来），`IncompleteRead` 发生在流中途的 chunk 边界。
- **会话续期改成独立线程**：原来挂在读循环上（每收一行试一次、按 30 秒节流），模型思考期间上游不吐字节时只能靠 `KEEPALIVE` 哨兵带动；哨兵拿不到 socket 就完全没续期。另外带签名的 HTTP PUT 塞在收帧路径上，一次慢心跳会让读停住，反过来顶满上游写缓冲。现在线程每 5 秒醒一次、到点续 busy，`close()` 先等可能在途的 busy 落地再发 idle。
- 断流日志带归因：`bytes`（收了多少）、`silent`（断前静默多久）、`pings`（心跳发了几次）、`sock`（socket 拿没拿到）、`shape`（消息数 / 字符数 / 工具数 / max_tokens）。
- `APIG.0203` 映射为 **504**（不再含糊地报 502）；流式请求的建连重试增加 **75 秒总预算**——一次 0203 就花掉 60 秒，再重试时客户端早已离开（线上实测 `open retry 1/3 → 2/3 → client gone`），继续试只是替没人要的回答占着会话。非流式不受这条限制。

**价格系统的设置面收干净（面板 + `/settings` + `ca_settings`）**

- 价格估算 2026-10-22 下线时，设置页的控件删了，但配套 JS（约 230 行）、`/settings/save` 的三个分支、`ca_settings` 的四个读写函数都还留着：面板每次加载都在操作不存在的 DOM，服务端每次保存都在写一个没人读的键。
- 现在这条链只留「只读答复」：面板不再读写 `pricing_*`；`/settings/save` 收到这三个键按未知键忽略（老页面不报错，只是不再有效果）；`ca_settings` 里的键常量、小时→分钟迁移函数与 getter/setter 一并删除。老 `settings.json` 里的残留键不读不写，保存时原样保留，回滚旧版本仍能读到。
- `/pricing`、`/pricing/refresh`、`/pricing/mapping` 三个接口**保留**：仍在运行的老页面加载时还会去拉一次，返回 404 会让它弹网络错误。它们本来就只有「已移除」这一种答复。
- 成本列与 `PRICING_ON` 开关已随本轮看板重构整体删除；旧分支不再残留。

**重构后遗留的死代码清理**

- `ca_proxy`：删掉 `exclusive_realm` + `CN_EXCLUSIVE` 清单（国际版移除后没有任何调用点，模型到出口的映射已恒等于 `CURRENT_REALM`；改那份清单不会影响行为）、namespace「直接拒绝」分支的 `REJECT_NAMESPACE_TOOLS` / `NAMESPACE_TOOL_MESSAGE` / `find_namespace_tool`（正解是展开 + 还原），以及价格体系下线时留下的 `_EMPTY_POLICIES` / `_EMPTY_TIMELINE` / `_cost_from_memo`。
- `ca_accounts`：`DEFAULT_UA_VERSION`、`REALM_MARKERS`、`desktop_auth_dir`（注释写着「kept for older callers」，但已经没有任何调用方）。
- `ca_codearts`：`GATEWAY_SERVICE_NAME`——真正发出去的只有 `User-Agent`，留着容易被当成出站头在用。
- 口径：每个名字都先在 `.py` / `.js` / `.html` / `.md` / `.sh` 全仓搜过「零引用」，再删；`ca_proxy` 现在没有零引用的模块级定义。**保留**了 `poll_ticket` + `TICKET_*` 这一簇（旧的 ticket 登录通道是成组的历史资料，拆一半比留着更糟），也保留了 claim 家族里暂时没接线的 `enable_benefit_claim`。
- 顺带把这个文件里 5 处「三空行 / 只含空白的行」统一成两个空行。

**协议层 golden：帧序列逐字节钉死**

- 新增 `tests/_test_protocol_golden.py`（套件 133）：把 Anthropic Messages 与 Responses 各 6~7 个场景的**完整帧序列**存成 `tests/golden/*.json`，改完代码一 diff 就知道哪一帧变了。录制时把 `new_id` 与 `time` 打桩，所以能逐字节比。
- 覆盖：正文 + 缓存用量、思考 + 正文、单/多工具调用（参数分片）、`max_tokens`、空流、上游错误帧、`stop_sequence` 命中、只有工具没有正文。
- 反向验证过：把 `message_start` 改成 `message_startX`，6 个场景当场变红。
- 顺带补三条纯度断言：`ca_protocol` 里不许出现 `log(` / `logging`、不许读 `ca_settings` / `ACCOUNTS_DIR`、只依赖 `json` / `re` / `time` / `uuid` 四个标准库模块。

**Messages 的 `stop_sequence` 回填（尽力而为）与面板并发可见**

- Anthropic 的 `stop_sequence` 以前恒为 `null`。现在非流式回包与流式 `message_delta` 都会拿请求里的 `stop_sequences` 去匹配输出**结尾**，命中就填上（多串命中取最长）。**但码道上游实测会把命中的串丢掉**：2026-10-23 直连 `stop=["六"]`，正文/思考里都没有「六」，只有 `finish_reason=stop` —— 没有信号能反推是哪条命中，所以这种情况仍保持 `null`，绝不猜。
- 面板账号卡片新增运行期一行：`并发 在跑/容量 · 冷却 Ns`。容量取自信号量的**实时值**，面板改并发后立刻反映，不用重启。
- `/accounts/codearts` 与 `/codearts/pool` 的 `runtime` 增加 `capacity` 字段。

**请求形状校验与 Responses 帧格式收口**

- **只有 system 消息 / 空 messages**：以前原样转给上游，回 `ModelArts.81001.400 messages 参数非法`，报错点离真正原因很远（Responses 只发 `instructions` 时最容易撞上）。现在三条协议（Chat / Responses / Messages）都在请求阶段回 400，文案说明「至少要有一条 user 或 assistant 消息」。
- **`clean_responses_frame` 少一个换行**：以前对每个被清洗的帧固定追加 `\n\n`，输入本来以空行结尾时会多出一个换行（SSE 能容忍，但按行对拍帧时会看到漂移）。现在补回**恰好一个**空行。
- **排障速查**：README 新增一节，写清「正文空但 finish=stop（stop 命中思考内容）」「`response_format` 为什么 400」和 `: keepalive` 注释行的含义。

**码道每账号并发改完即生效（不用重启）**

- 信号量改成容量可调的实现：面板把并发从 2 调到 4，**下一个取号就按 4**；调小时只收紧新名额，已经在跑的请求不受影响。
- 以前的「已有账号要重启才生效」不再成立；顺带把 429 文案与 `/codearts/pool` 里的 `concurrency_per_account` 也改成读实时值。

**码道并发与冷却可在面板调**

- 设置页新增「码道并发与冷却」四项：每账号并发（1~8，默认 2；上游给 3 个会话名额，留一个余量）、流式会话续期间隔、并发满（1041）冷却、TPM 限流冷却。
- 四项保存后**下一个请求即生效**（5 秒缓存）；每账号并发由容量可调的信号量承载，改完不用重启，调小也不打断在跑的请求。
- 后端按区间校验，越界回 400；`settings.json` 被手改坏的值退回默认，不会把网关配成不可用。

**码道协议补齐：采样参数、多模态错误、`n` / `response_format`**

- **采样参数以前被白名单挡掉**：码道路径只转发 `model/messages/max_tokens/stream/thinking/tools/tool_choice`，`temperature` / `top_p` / `stop` / `seed` / `presence_penalty` / `frequency_penalty` 全部丢弃。上游实测（用非法值验证）是真解析这些字段的，现在原样转发；`stop` 字符串会包成数组（上游只收数组），超过 4 条按 OpenAI 语义裁掉。Anthropic 的 `stop_sequences` 因此也真正生效了。
- **图片发给纯文本模型**（`InferHub.001001020.406` "not multimodal"）从 502 改成 400，并直接提示改用 `Qwen3-VL-235B` / `kimi-k2.6-vl`——以前客户端会当成网关抖动，反复重试同一张图。
- **`n>1`** 与 **`response_format=json_object/json_schema`** 现在在请求阶段就回 400 说明原因（上游分别只给一条 choice、以及直接忽略该字段），不再静默降级：客户端拿到形状不符的结果比拿到明确错误更难查。
- **TPM 限流按模型冷却**：`glm-5.3` 撞限流只晾这个模型，不再连带停掉同一账号上的其它模型（1041 并发满与凭据失效仍是账号级）。

**移除全部 GitHub Actions 工作流**

- 删掉 `.github/workflows/`（`tests` / `release` / `release-checksums` / `docker-publish` / `revert-guard`），
  以及只为它们服务的 `release/` 打包工具（`matrix_legs.py` / `release_tools.py` / `portable_runtime.py` / `portable.txt`）
  与 `tests/_test_release_assets.py`；
- 测试不再自动跑：`python tests/run_all.py` 由本地/服务器手工执行；
- 发布改为手工：打 `v*` tag 前先本地跑全量，`.ipk` / `.apk` 用 `wrt/openwrt/*.sh` 本地构建后上传；
- 代价要说清：没有三平台（Ubuntu 3.9 / 3.12、Windows 3.12）矩阵，也没有合并前的自动回滚检查（revert guard）——
  合并前请自己核对合并结果里 base 的新增代码是否还在。

**项目身份从 WorkBuddy 改为 CodeArts（码道）**

- 运行模块 `wb_*.py` → `ca_*.py`（21 个），启动脚本 `start-/restart-wb-proxy*` → `*-codearts-hub*`；
- 服务名、部署目录、`server_version`：`wb-proxy` / `wbhub` → `codearts-hub`；
- OpenWrt 包名 `workbuddy2api` → `codearts2api`；Docker 镜像与 quick-deploy 改为指向本仓库自己的产物；
- **保留不动**（属于上游协议标识，改名会打断线上部署）：桌面缓存目录 `~/.workbuddy`、`WB_*` 环境变量（含 `WB_PROXY_KEY`）、上游账号域名 `www.workbuddy.cn`、`owned_by=workbuddy`、微信成长任务 id `wb_wechat_oa_subscribe_task`，以及上游仓库链接与 `docs/CHANGELOG.md` 历史记录。

已发布版本的完整记录见 **[docs/CHANGELOG.md](docs/CHANGELOG.md)**。

---

## 七、致谢与引用声明 (Credits & References)

本项目的网关骨架、看板与调度器来自上游 **[ardeyouxipianyi/workbuddy2api-hub](https://github.com/ardeyouxipianyi/workbuddy2api-hub)**
（MIT）。码道（华为云）链路为本项目新增：PKCE + DPoP 授权、STS 续期、每日额度领取、
`maas_type` 分组分流与并发护栏均为独立实现，不依赖上游的账号体系。

---

## 八、免责声明 (Disclaimer)

1. 本项目为非官方自托管网关，仅供技术研究、协议学习与个人合法授权账号在私有环境测试使用。
2. 本项目不提供任何账号及额度。请严格遵守官方服务条款，禁止用于任何商业转售、恶意并发或违规滥用。

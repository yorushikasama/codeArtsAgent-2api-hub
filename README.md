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

- 133 个套件：107 个 Python + 26 个 JS；JS 需要 PATH 上有 `node`，缺失时会跳过并提示。
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

**重名模型归谁**：`deepseek-v4.1-flash` / `glm-5.3` / `glm-5.3-flash` 两边都有，
按**码道优先**分流 —— 但前提是**这个部署真的配了码道账号**：没配时这些名字仍走
WorkBuddy 账号池，不会因为「模型名在码道清单里」就拐去一个不存在的出口。
清单里的 `owned_by` 永远跟实际分流一致，不会出现「清单说是 WorkBuddy、请求却去了码道」。

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

**价格系统的设置面收干净（面板 + `/settings` + `ca_settings`）**

- 价格估算 2026-10-22 下线时，设置页的控件删了，但配套 JS（约 230 行）、`/settings/save` 的三个分支、`ca_settings` 的四个读写函数都还留着：面板每次加载都在操作不存在的 DOM，服务端每次保存都在写一个没人读的键。
- 现在这条链只留「只读答复」：面板不再读写 `pricing_*`；`/settings/save` 收到这三个键按未知键忽略（老页面不报错，只是不再有效果）；`ca_settings` 里的键常量、小时→分钟迁移函数与 getter/setter 一并删除。老 `settings.json` 里的残留键不读不写，保存时原样保留，回滚旧版本仍能读到。
- `/pricing`、`/pricing/refresh`、`/pricing/mapping` 三个接口**保留**：仍在运行的老页面加载时还会去拉一次，返回 404 会让它弹网络错误。它们本来就只有「已移除」这一种答复。
- 成本列继续按 `PRICING_ON = false` 恒隐藏；该常量现在没有赋值点，只为让历史渲染分支短路。

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

# 码道 CodeArts Agent 上游调研报告

> 目的：评估把 `codearts2api-hub`（原项目）改造为「华为云码道 CodeArts 代码智能体 → OpenAI 兼容 API」的可行性。
> 方法：静态分析本机已安装的码道 Agent（Electron 应用 + 扩展 bundle）+ 日志实测取证。
> 日期：2026-10-16

---

## 0. 一句话结论

**可行，而且形态比原项目更规整。** 码道 Agent 的登录是**标准 OAuth2 授权码 + PKCE + 本地 loopback 回调**，并且额外提供了一条 **`ticket_id` 轮询**通道——这条通道在结构上与原项目的 `state` + `/v2/plugin/auth/token` 轮询**一一对应**，正是"服务端代理 + 前端轮询"型网关所需要的。

代价是：**这不是"改登录"，而是"换上游"**。原项目下游的 chat / billing / checkin / 出站身份头全是 WorkBuddy 专有协议，换上游必须整体替换。

---

## 1. 调研对象与取证方式

本机已经装了码道 Agent，所有结论都来自实测，不依赖猜测：

| 对象 | 路径 |
|---|---|
| Electron 主程序 | `C:\Program Files\CodeArts Agent\codearts-agent.exe`（210 MB） |
| 渲染层/主进程 JS | `...\resources\app\out\main.js`（2.5 MB）、`out\cli.js` |
| **认证扩展（核心）** | `...\resources\app\extensions\huaweicloud.authentication\dist\plugin.js`（3.78 MB） |
| 支持扩展 | `...\extensions\huaweicloud.codearts-agent-support\` |
| 运行时日志 | `%APPDATA%\codearts-agent\User\logs\CodeArts Agent-*.log` |
| 用户数据 | `C:\Users\Administrator\.codeartsdoer\` |
| 凭证库 | `%APPDATA%\codearts-agent\User\globalStorage\state.vscdb` |

分析方法：对 `plugin.js` 做关键字定位 + 上下文窗口提取，还原出完整的鉴权逻辑；对日志做域名/路径聚合，得到真实调用面。

---

## 2. 架构解剖

```
CodeArts Agent (Electron / VSCode fork)
├── out/main.js, out/cli.js           # 主进程 + CLI
├── extensions/
│   ├── huaweicloud.authentication    # ★ 登录 / 令牌 / STS 凭证
│   ├── huaweicloud.codearts-snap     # 码道核心（模型 / 会话 / 网关配置）
│   ├── huaweicloud.codearts-agent-support
│   └── remotedev-codearts-agent
├── 本地 WebServer（"CodeMate WebServer"）
│   └── 随机端口，实测 pid=178812, port=41040, version=1.0.0-1157190986607552
└── AgentKernel（opencode 内核）
    └── ~/.codeartsdoer/CodeArts_Agent/AgentKernel_Vscode_26_9_902_1_0_0-*.exe (173 MB)
```

**关键判断：这是一个 opencode 系的产品。** 证据：

- `~/.codeartsdoer/package.json` → `{"dependencies":{"@opencode-ai/plugin":"1.0.0-1157190986607552"}}`
- `~/.codeartsdoer/codearts-data/codearts.json` → `{"$schema":"https://opencode.ai/config.json"}`
- `~/.codeartsdoer/codearts-data/opencode.db`（SQLite，6.5 MB）

**这对我们很有利**：opencode 本身是开源 TypeScript 项目，有成熟的 provider 抽象（`baseURL` + `apiKey` + model 列表）。模型接入这一层几乎不用逆向——照 opencode 的 provider 配置格式填就行。

另外：码道 Agent 自己就跑着一个**本地 HTTP 服务**（CodeMate WebServer，随机端口）。也就是说"Agent 内核 ↔ IDE 前端"之间本来就是 HTTP 通信，hub 的架构思路（本地起 HTTP 服务暴露 API）在这里是被官方认证过的形态。

---

## 3. 上游端点清单（日志实测）

### 3.1 主域名

| 域名 | 命中次数 | 作用 |
|---|---|---|
| `snap-access.cn-north-4.myhuaweicloud.com` | 1110 | **主上游**（国内区域 cn-north-4） |
| `snap-access.cn-north-4.myhuaweicloud.cn` | 126 | 国内镜像备用域 |
| `snap-access.ap-southeast-1.myhuaweicloud.com` | — | 国际版上游 |
| `sts.cn-north-4.myhuaweicloud.com` | — | **IAM/STS：换 token、查身份** |
| `auth.huaweicloud.com` | — | 华为云统一登录页（浏览器授权入口） |
| `opengw.developer.huaweicloud.com` | 19 | `/v2` —— 推理网关候选 |
| `codearts.huaweicloud.com` | 28 | portal（授权页 + 设置页） |

### 3.2 业务接口（`snap-access`）

| 路径 | 命中 | 用途推测 |
|---|---|---|
| `/v1/chat/record-request` | 324 | 对话请求上报（非推理本体） |
| `/v1/sessions` | 174/176 | 会话管理 |
| `/v1/agent-center/agents/useragents` | 138 | 用户自定义智能体 |
| **`/api/v1/queue/status`** | 131 | **排队状态**（网关有队列，必须处理） |
| `/snap-manager/v1/statistics/plugin` | 65 | 统计上报 |
| `/v1/agent-center/agents/detail` | 60 | 智能体详情 |
| `/v1/benefit-gateway-config` | 30 | 权益网关配置 |
| `/v1/ops/credit/usage` | 16 | **积分/用量**（对应原项目的 billing） |
| `/v1/model/builtin` | 12 | **内置模型清单** |
| `/v1/gateway-config` | 2 | **网关配置** |
| `/v1/llm/vendors` | 2 | 模型厂商 |
| `/v1/model/thinking-variants` | 8 | 思考模式变体 |
| `/v1/policy/bundle` | 3 | 策略包 |
| `/v1/current/user` | — | 当前用户（AK/SK 签名调用） |
| `/v1/login/ticket` | — | **ticket 换凭证（轮询通道）** |

### 3.3 推理入口（关键）

从日志里的模型配置回包直接抠出：

```json
"inferhubBaseUrl": "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/,https://snap-access.cn-north-4.myhuaweicloud.cn/api/v2/"
"knowledgeBaseUrl": "https://snap-acc..."
"provider": "inferhub-provider"
```

- 推理基址：**`https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/`**（逗号分隔的 `.cn` 备用域）
- provider 名：`inferhub-provider`
- 另有 `https://api.modelarts-maas.com/v2/chat/completions` 出现在配置样本里 → 说明基址 + `chat/completions` 是 OpenAI 兼容风格

### 3.4 可用模型（从 `model/builtin` 回包实测）

```
glm-5.1 / glm-5.2 / glm-5.3 / glm-5.3-flash / glm-5.2-sft-harmony
deepseek-v4-flash / deepseek-v4-flash-0731 / deepseek-v4-pro / deepseek-v4-pro-0813 / deepseek-v4.1-flash
MiniMax-M2.7 / MiniMax-M3
Qwen3-VL-235B / Qwen3-30B_QC2
gemini-2.5-pro / gemini-3-pro-preview
gpt-5 / gpt-5.4
kimi-k2.6 / kimi-k2.6-vl
openpangu-2.0-flash
```

模型元数据带 `reasoning`、`model_type`、`limit{input,output,context}` —— 例如 `GLM-5.2` 的 `limit = {input:196608, output:131072, context:202752}`。

---

## 4. 登录链路（完整还原）

### 4.1 环境常量（`plugin.js` 内嵌的 JSON）

```json
{
  "snapEngineApiHost":    "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager",
  "intlSnapEngineApiHost":"https://snap-access.ap-southeast-1.myhuaweicloud.com/snap-manager",
  "portalHost":           "https://codearts.huaweicloud.com/portal",
  "intlPortalHost":       "https://codearts.ap-southeast-1.huaweicloud.com/portal",
  "iamStsHost":           "https://sts.cn-north-4.myhuaweicloud.com",
  "iamLogin":             "https://auth.huaweicloud.com/authui/login.html",
  "env":                  "prod"
}
```

### 4.2 其它关键常量

| 常量 | 值 | 含义 |
|---|---|---|
| `EXTENSION_ID` | `huaweicloud.authentication` | |
| `IAM_TOKEN_API` | `/v1/oauth2/tokens` | 拼在 **`iamStsHost`** 后面 |
| `AUTH_REDIRECT_URL` | `/oauth/callback` | 本地回调路径 |
| `LOGIN_PLUGIN_NAME` | `snap_AIIDE` | 插件标识，随请求头上报 |
| `CLIENT_ID` | `vscode.env.uriScheme` | **OAuth client_id = IDE 的 URI scheme** |
| `GrantType` | `authorization_code` / `refresh_token` | |
| `LoginWay` | `old_login` / `new_iam_login` | 两种登录实现 |
| `EXPIRATION_TIME_THIRTY_DAYS_MIILISECONDS` | `2592000000` | **refresh_token 有效期 30 天** |
| `MAX_TIMES_OF_TRYING_TO_GET_LOGIN_STATE` | `10` | 轮询 10 次 |
| `RETRY_MILLISECONDS` | `2000` | → 轮询窗口 20s |
| `MAX_TIMES_OF_TRYING_FOR_CALLBACK` | `300` | 回调等待 300 次 |
| `RETRY_MILLISECONDS__FOR_CALLBACK` | `1000` | → 5 分钟 |
| `RENEW_TOKEN_INTERVAL_WHEN_LAST_TIME_FAILED` | `600000` | 刷新失败退避 10 分钟 |
| `WAIT_TIME_FOR_MULTI_WINDOW_RENEWAL` | `5000` | 多窗口刷新互斥 5s |

错误类型也直说了 refresh 语义：`InvalidSystemTime` / `ExpiredRefreshToken` / `AlreadyRefreshed` / `AlreadyUsedRefreshToken`（**refresh_token 单次有效**，与原项目一模一样）。

### 4.3 授权 URL 的构造（`buildLoginUrl`）

```js
ticketId = random(32 bytes).hex          // 客户端自己生成的随机票据
portalUrl = `${getPortalHost()}/authorize`
  + `?theme=${activeColorTheme}&locale=${language}`
  + `&uri_scheme=${CLIENT_ID}&client_id=${CLIENT_ID}`
  + `&port=${callbackServerPort}`
  + `&code_challenge=${pkce.codeChallenge}&code_challenge_method=${pkce.method}`
  + `&ticket_id=${ticketId}&plugin-name=snap_AIIDE&plugin-version=${version}`
```

**联邦登录（企业 IdP / SSO）变体**：

```js
`https://auth.huaweicloud.com/authui/login.html?loginType=idp&service=${encodeURIComponent(portalUrl)}`
```

> ⚠️ 这就是你给我的那个 URL 的同族形态。你给的 `?service=.../portal/settings/personal-usage` 是"从 portal 某页面被踢去登录"的普通入口；而插件走的是 `?loginType=idp&service=<portal/authorize?...>`。**两者都只是"把人送去华为云登录页"的跳板，真正的授权上下文在 `service=` 里那个 `/portal/authorize` 上。**

### 4.4 通道 A：`old_login` —— ticket 轮询（★ 与原项目结构对应）

```http
GET {snapEngineApiHost}/v1/login/ticket?ticket_id={hex32}&secret={secret}
Headers:
  Content-Type: application/json;charset=UTF-8
  plugin-name: snap_AIIDE
  plugin-version: {extension version}
```

- 客户端每 **2 s** 轮询一次，最多 **10 次**（20 s 窗口）
- 成功判据：响应体含 `user_name`
- 可取消：`onDidCanceledLogin` 会 `clearInterval` 并 reject

**这就是原项目 `/v2/plugin/auth/token?state=` 的对位物**：客户端自造票号 → 塞进授权 URL → 浏览器里完成登录 → 客户端拿票号轮询换凭证。**不需要回调能打到服务端。**

### 4.5 通道 B：`new_iam_login` —— OAuth2 授权码 + PKCE + DPoP

**① 浏览器回调**：本地起 HTTP 服务监听 `http://127.0.0.1:{callbackServerPort}/oauth/callback`，从中拿到 `code`。

**② 换 token**：

```http
POST https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens
Headers:
  DPoP: {JWE}                              # generateDpopJWE(dpopKeyPair, generateDpopPayload(method, url))
  Content-Type: application/x-www-form-urlencoded
Body (URLSearchParams):
  client_id={CLIENT_ID}
  code={授权码}
  code_verifier={PKCE verifier}
  grant_type=authorization_code
  redirect_uri=http://127.0.0.1:{port}/oauth/callback
timeout: 60s
```

**③ 刷新**：同 URL，body 换成

```
client_id, code_verifier, grant_type=refresh_token, refresh_token
```

**④ 连通性探测**：`POST {iamStsHost}/v1/oauth2/tokens`（空 body）

### 4.6 返回的凭证结构

```ts
class Authentication {
  account; scopes;
  accessToken;                    // OAuth 访问令牌
  accessKey; secretKey;           // ★ STS 临时 AK/SK
  securitytoken;                  // ★ STS 安全令牌
  expires_at;
  domainId;
  safelyRenewTokenInterval;
  loginContext;
  refresh_token;                  // 30 天
}
```

后续业务调用的两种鉴权方式：

- **AK/SK 签名**（`SDK-HMAC-SHA256`，带 `X-Sdk-Date`）
  ```http
  GET https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity
  Headers: X-Security-Token: {securitytoken}, Content-Type: application/json
  （请求被 accessKey/secretKey 签名）
  ```
- **`X-Auth-Token`**（日志中 256 次命中，是最主要的业务鉴权头）

### 4.7 凭证存哪

```
%APPDATA%\codearts-agent\User\globalStorage\state.vscdb   (SQLite)
  └── ItemTable
      key   = secret://{"extensionId":"huaweicloud.authentication","key":"HuaweiCloudSession"}
      value = 10297 bytes，Electron safeStorage 加密（Windows 下即 DPAPI）
```

对照原项目：`accounts/<uid>.json` **明文**存 token。新项目可以沿用明文（保持简单），也可以顺手把 `ca_atrest.py` 那套 AES-GCM 用上。

---

## 5. 与原项目逐条对照

| 维度 | 原项目（WorkBuddy） | 码道 CodeArts |
|---|---|---|
| 登录协议 | 私有三段式：`auth/state` → 浏览器 → `auth/token?state=` | **标准 OAuth2 授权码 + PKCE + DPoP**（另有 ticket 轮询） |
| 谁生成票据 | **上游**返回 `state` | **客户端**自造 32 字节 tickets |
| 轮询窗口 | TTL 600 s | 20 s（10 × 2 s） |
| 回调 | 无（上游绑状态，网关只轮询） | 本地 loopback `127.0.0.1:{port}/oauth/callback` 或 ticket 轮询 |
| 换 token | `GET /v2/plugin/auth/token?state=` | `POST https://sts.cn-north-4.myhuaweicloud.com/v1/oauth2/tokens` |
| 刷新 | `X-Refresh-Token` → `/v2/plugin/auth/token/refresh` | 同 URL，`grant_type=refresh_token`，**30 天** |
| 凭证形态 | accessToken + refreshToken（**非** JWT 之外无他） | OAuth accessToken **+ STS 临时 AK/SK + securitytoken** |
| uid 来源 | `jwt_uid()` 解 JWT 的 `sub` | `GET /v5/caller-identity` 或 `GET /v1/current/user`（响应含 `user_name`、`domainId`） |
| 出站鉴权 | `X-IDE-Type` / `X-Agent-Intent` 等专有头族 | **`X-Auth-Token`** 或 **AK/SK 签名 + `X-Security-Token`** |
| 长久凭证 | 无 | **有**：`CODEARTS_CLI_AK` / `CODEARTS_CLI_SK`（CLI 官方路径） |
| 推理入口 | `https://www.workbuddy.ai`（私有多路） | `https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/` |
| 模型清单 | 网关自维护 `/v1/models` | `GET /v1/model/builtin` |
| 用量 | `/v2/billing/meter/*` | `GET /v1/ops/credit/usage` |
| 排队 | 无 | **有**：`GET /api/v1/queue/status` |
| 凭证落盘 | `accounts/<uid>.json` 明文 | `state.vscdb` + DPAPI 加密 |

**结论**：两边是"同构不同协议"。原项目的控制器/调度器/看板/账号池抽象**大部分能复用**；要换的是 **auth 层 + 出站身份层 + 业务端点层**这三层。

---

## 6. 新项目怎么搞

### 6.1 先认清三条硬约束

1. **换登录 = 换上游。** `Account.accessToken` 会被下游一堆 WorkBuddy 专有端点消费，换个非 WorkBuddy 的凭证进来，账号一入池就 401。要么全换，要么别动。
2. **loopback 回调要求 hub 与浏览器同机。** `redirect_uri` 写死 `http://127.0.0.1:{port}/oauth/callback`，服务端大概率会校验。Hub 跑在用户自己电脑上（别人经局域网访问）时没问题——这也正是原项目的部署形态。若要 hub 与浏览器分机，就得走 ticket 轮询通道，或让用户把回调 URL 手工粘回面板。
3. **`client_id = IDE 的 uriScheme`。** 这个值是华为云侧登记的 OAuth 客户端标识，**不能随便编**。要么照抄 `codearts-agent` 对应的 scheme，要么注册自己的。这是**唯一一个可能卡死的点**，必须实测确认服务端是否校验 client_id 白名单。

### 6.2 三条落地路线

| 路线 | 做法 | 工作量 | 风险 |
|---|---|---|---|
| **① 复刻 ticket 轮询**（最贴近原项目） | hub 自造 `ticket_id`，拼 `/portal/authorize?...&ticket_id=` 给用户浏览器打开；hub 每 2s 打 `/v1/login/ticket?ticket_id=&secret=` | 中 | `secret` 的取值来源未确认（见 §7） |
| **② 复刻 loopback 授权码** | hub 监听 `127.0.0.1:{port}/oauth/callback`，拿到 code → `POST /v1/oauth2/tokens`（要 DPoP/JWE + PKCE） | 高 | DPoP 实现复杂；loopback 非同机不可用 |
| **③ AK/SK 直连**（最快出效果） | 面板填 AK/SK，出站用 `SDK-HMAC-SHA256` 签名 | **低** | 需要用户去控制台建密钥；不是"浏览器登录"体验 |

**推荐组合**：先做 ③ 把整条链路（模型清单 → 推理 → 用量）跑通并验证，再把 ① 接上作为"人性化登录"。② 只在 ① 走不通时作为兜底。

### 6.3 改造映射清单（逐文件）

| 原项目位置 | 改什么 |
|---|---|
| `ca_accounts.py:177 REALM_CONFIGS` | 加 `hw` realm：`chat_upstream`/`billing_upstream` → `snap-access...`，`origin` → `codearts.huaweicloud.com` |
| `ca_accounts.py:204-214` 端点常量 | 换成 `/v1/model/builtin`、`/v1/ops/credit/usage`、`/api/v2/`、`/v1/login/ticket`、`/v1/oauth2/tokens` |
| `ca_accounts.py:3276 start_login` | 改成自造 ticket/生成 PKCE + 拼 `/portal/authorize` |
| `ca_accounts.py:3298 poll_login` | 改成轮询 `/v1/login/ticket?ticket_id=&secret=`（判据：响应含 `user_name`） |
| `ca_accounts.py:1259 refresh` | 改成 `POST {iamStsHost}/v1/oauth2/tokens` + `grant_type=refresh_token`；保留"按账号加锁"（refresh_token 单次有效） |
| `ca_accounts.py:238 jwt_uid` | **失效**（码道凭证不是 JWT）→ 改用 `caller-identity` / `current/user` 的 `domainId`/`user_name` |
| `ca_accounts.py:148 http_json` | 只能拿 body，**拿不到响应头**（STS 凭证可能在头里）→ 需加 header-aware 版本 |
| `ca_accounts.py:1603 checkin` | 码道无签到概念 → 删除或改成"拉一次用量" |
| `ca_identity.py:137 build_identity_headers` | 换成 `X-Auth-Token` / AK-SK 签名 + `X-Security-Token`，去掉 `X-IDE-Type` 族 |
| `ca_fingerprint.py` | 可保留（设备指纹对 STS 无意义，但也不算错） |
| `ca_atrest.py` | 可保留（若决定加密落盘） |
| `dashboard.html:4940-5007` 登录弹窗 | `old_login`：给链接 + 轮询（**几乎不用改**）；`AK/SK`：加表单 |
| `ca_proxy.py:18512/18524` 路由 | 基本不动（只是转发） |
| **新增** | `ca_codearts_auth.py`（OAuth2/PKCE/DPoP/ticket 轮询）、`ca_huawei_sign.py`（AK/SK 签名）、`ca_queue.py`（排队状态轮询） |
| **必处理** | `/api/v1/queue/status` —— 网关有队列，前端要显示排队位置 |

---

## 7. 风险与待确认

| # | 事项 | 影响 | 怎么确认 |
|---|---|---|---|
| 1 | **`client_id` 是否被服务端白名单校验** | 卡死级。若校验，必须用合法 scheme | 用真实 `codearts-agent` scheme 发一次 authorize，看是否报错 |
| 2 | **`secret` 从哪来** | 决定 ticket 通道能否"不依赖同机回调" | 抓一次真实登录的完整流量（浏览器 → portal → 回调） |
| 3 | DPoP（JWE）是否**强制** | 强制则必须实现 DPoP，工作量翻倍 | 不带 DPoP 头打 `/v1/oauth2/tokens`，看返回码 |
| 4 | 推理的确切路径 | 决定 OpenAI 兼容层怎么映射 | 日志未直接抓到；推测 `/api/v2/chat/completions`，需抓包确认 |
| 5 | 是否有 SSE 流式 | 决定 hub 能否做 stream 透传 | 抓一次对话 |
| 6 | 排队机制的返回结构 | 影响可用性 | 打一次 `/api/v1/queue/status` |
| 7 | 是否需要**已开通套餐**才能换到凭证 | 无套餐时登录能成功但拿不到模型 | `codearts models` 试一下 |
| 8 | 合规 | 这是把商业服务的客户端协议用于自建网关，属灰色地带 | 需你自行判断 |

---

## 8. 建议的下一步

1. **先抓一次真实授权流量**（成本最低、信息量最大）：装/跑本机 `codearts` CLI 或 IDE，用 mitmproxy/Fiddler 或 CDP 抓 `auth.huaweicloud.com` → `codearts.huaweicloud.com/portal/authorize` → `127.0.0.1:xxx/oauth/callback` → `sts.../v1/oauth2/tokens` 的完整链路，即可一次性确认 §7 的 #1/#2/#3。
2. **同时抓一次对话**，确认推理路径与流式行为（#4/#5/#6）。
3. 拿到这两组样本后，auth 层与上游层可以**确定性实现**，不再有猜测。
4. 实现顺序：AK/SK 通道 → 模型清单/推理透传 → ticket 轮询登录 → 看板改造。

---

## 附：关键事实速查

```
主上游        https://snap-access.cn-north-4.myhuaweicloud.com
推理基址      https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/
网关配置      {snapEngineApiHost}  = .../snap-manager
IAM/STS       https://sts.cn-north-4.myhuaweicloud.com
  换token     POST /v1/oauth2/tokens   (grant_type=authorization_code, PKCE, DPoP)
  刷新        POST /v1/oauth2/tokens   (grant_type=refresh_token, 30 天)
  身份        GET  /v5/caller-identity (AK/SK 签名 + X-Security-Token)
ticket 轮询   GET  {snapEngineApiHost}/v1/login/ticket?ticket_id=&secret=   (10 × 2s)
授权页        https://codearts.huaweicloud.com/portal/authorize?...
联邦变体      https://auth.huaweicloud.com/authui/login.html?loginType=idp&service=<encoded authorize>
插件标识      plugin-name: snap_AIIDE
模型清单      GET /v1/model/builtin
用量          GET /v1/ops/credit/usage
排队          GET /api/v1/queue/status
凭证存储      state.vscdb → secret://{"extensionId":"huaweicloud.authentication","key":"HuaweiCloudSession"}
```

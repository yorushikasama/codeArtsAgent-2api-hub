# CodeArts Agent 接口全景与项目接入判断

> 2026-10-21 逆向 + 线上实测。
> 逆向对象：本机 `C:\Program Files\CodeArts Agent\resources\app\extensions\vscode-codebot\out\extension.js`（10.5 MB）。
> 实测环境：线上 `155.248.163.15:~/codearts-hub`，用真实账号的 AK/SK + X-Security-Token 签名。
>
> **本文只记实测过的结论**。没探通的写明「未验证」，不猜。

---

## 一、整体结构：真正跟网关有关的只有四层

客户端里能抽出 **266 个**路径字面量，但按归属分完，跟本项目相关的只有一小撮：

| 层 | 数量 | 是什么 | 对本项目 |
|---|---|---|---|
| `/cag/*` | 137 | **本机** Agent Core 的 HTTP 服务（`127.0.0.1:<port>`），管会话、文件、终端、代码索引、MCP、定时任务 | **无关**。这是 IDE 进程内的本地服务 |
| `/session/*` `/tui/*` `/experimental/*` `/pty` `/permission` `/provider` 等 | 106 | 同上，另一批本地服务（opencode 风格的 REST） | **无关** |
| 云端 PromptCenter | 20 | `snap-access.cn-north-4.myhuaweicloud.com` 下的 `/v1/*`：模型目录、技能、规则、配置、二维码登录 | **部分相关** |
| 云端 inferhub / snap-manager | 十余个 | `/api/v2/chat/completions`（推理）、`/snap-manager/*`（账号、积分、项目） | **核心** |

一句话：**266 个里有 243 个是本地 IDE 的，跟网关没有任何关系。** 剩二十来个才需要逐个判断。

---

## 二、项目已接入的接口：实测现状

用线上真实账号逐个打，结果分三类。

### ✅ 活着且正常（5 个）

| 接口 | 用途 | 实测 |
|---|---|---|
| `POST /api/v2/chat/completions` | 推理入口 | 200，能出字、能出 `tool_calls` |
| `GET /v1/model/builtin` | 内置模型目录 | 200，`count: 8` |
| `POST /v1/model/thinking-variants` | 思考档位 | 400 `HDN.1000`（我探的时候没带 body，项目里是带 body 的，行为见既有实现） |
| `GET /snap-manager/v1/statistics/plugin` | 体验版积分 | 200，`11500 总额 / 4824.90 已用 / 6675.10 剩余` |
| `GET /v1/ops/delivery?channel=IDE` | 运营活动清单 | 200，含「每日签到」「邀请」「学生认证」等活动与各自 `status` |
| `POST /v1/ops/claim` | **每日签到领 1000 积分** | **200，实测领到**：总额 `11500 → 12500`，`ELIGIBLE → CLAIMED` |

#### 签到接口的正确姿势（2026-10-21 实测，此前我判错过，这里记死）

```
GET  /v1/ops/delivery?channel=IDE
     → data.items[] 里 campaignId=1、type=USER_LOGIN、
       title="每日签到领1000积分"、benefitAmount=1000、status=ELIGIBLE

POST /v1/ops/claim
     {"campaignId": 1, "channel": "IDE", "idempotentKey": "..."}
     → {"code":0,"data":{"campaignId":1,"status":"CLAIMED",
                         "totalAmount":1000.00,...}}

POST /v1/ops/confirm
     {"campaignId": 1}          ← 客户端 claim 成功后立刻 confirm，才算真正到账
```

三个必须记住的点：

1. **`channel` 必须是大写 `IDE`。** 小写 `ide` 在 `/v1/ops/delivery` 上照样 200（服务端把它转成 `IDE`），
   但在 `/v1/ops/claim` 上回 `{"code":40001,"message":"当前渠道不支持领取该运营权益"}` ——
   同一个词大小写不一致，一个能读一个不能领，很容易被误判成「接口没了」。
2. **GET 探不到不代表接口不存在。** claim 只有 POST；用 GET 打会回
   `The API does not exist: method GET not found`。这跟「路径真的不存在」的
   `The API does not exist or has not been published in the environment` 是**两种不同的错误**，
   看后半句就能区分。我第一版就是混了这两句，误判签到接口已下线。
3. **项目里早就实现对了**：`ca_codearts.WELFARE_CHANNEL = "IDE"`，
   `welfare_claim()` 走 claim + confirm 两步，`welfare_claim_daily()` 还带幂等短路。
   实测 `welfare_claim_daily()` → `already: True, status: CLAIMED`。

内置模型 8 个，与项目 `/v1/models` 完全一致：

```
GLM-5.2          Qwen3-VL-235B     kimi-k2.6-vl      openpangu-2.0-flash
openpangu-2.0-pro  glm-5.3         glm-5.2-sft-harmony  deepseek-v4.1-flash
```

> 注意 `Qwen3-VL-235B` / `kimi-k2.6-vl` 的 `display_enabled=false` 且 `credit=[]` ——
> 客户端 UI 里**不显示**这两个，但推理入口能跑通。我们照样列出来，是对的选择。

### ⚠️ 两套账必须分开看：token 额度 ≠ 积分

这是本项目最容易搞混的地方，也是我第一版报告出错的地方：

| | 每日 **token** 额度 | 每日 **积分** 签到 |
|---|---|---|
| 入口 | `/api/v1/benefit/claim` + `/api/v1/user/tokens/balance` | `/v1/ops/claim` + `/v1/ops/delivery` |
| 给什么 | 1000 万 token / 天，当日清零 | 1000 积分 / 天，进积分包 |
| 现状 | **404，接口已从网关上撤掉** | **正常，实测能领** |
| 项目函数 | `claim_benefit()` / `balance_summary()` | `welfare_claim_daily()` |

**「领不到额度」和「领不到积分」是两件事。** 前者确实黄了，后者一直好好的。

### 💀 已经下线（3 个，都属于「每日 token 额度」那条链）

| 接口 | 项目里还在用 | 实测 |
|---|---|---|
| `GET /api/v1/gateway/config` | `ca_codearts.gateway_config()` | **404 APIG.0101**（接口不存在） |
| `GET /api/v1/user/tokens/balance` | `balance_summary()` | **404 APIG.0101** |
| `POST /api/v1/benefit/claim` | `claim_benefit()` | **404 APIG.0101**（注意：是「路径不存在」，不是「方法不对」） |

之前看到的 `[4000] invalid channel, group not found` 已经升级成彻底 404。
上游把整个 benefit 渠道的 API 从网关上下架了，不是「临时没额度」。
项目里这三个函数现在只会返回错误。

### ⚠️ 接口在，但参数要换

| 接口 | 实测 | 说明 |
|---|---|---|
| `GET /api/v1/queue/status` | 400 缺 `task_id` | 是**会话级**排队查询，不是全局状态 |
| `GET /v1/ops/credit/usage` | 400 `type: Parameter is invalid` | `day` / `token` 都不对，参数枚举未探明 |

---

## 三、值得接的（按价值排序）

### ★★★ `/v1/benefit-gateway-config` —— 一句话解释「为什么领不到额度」

```
GET https://snap-access.cn-north-4.myhuaweicloud.com/v1/benefit-gateway-config
Agent-Type: PromptCenter
→ 200 {"enabled": false, "is_examination_domain": false, "examination_model_enable": false}
```

这是 `enabled: false` —— **上游明确告诉我们福利渠道被关了**。
现在面板只能显示「额度读取失败」加一串 404/4000，用户根本不知道是自己账号的问题还是上游收摊了。
接上它之后可以直说：「上游已关闭福利渠道（`enabled=false`），与账号无关」。

顺带还有 `/v1/education-gateway-config`（`enabled:false, is_student_certified:false`），同一批。

**改动量**：约 20 行 + 面板一行文案。

### ★★☆ `/snap-manager/v1/current/user` —— 面板显示真实账号名

```
GET https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/current/user
→ 200 {"domain_id":"01a1…","domain_name":"hid_bgatv9rp4x32nge",
        "user_id":"01a1…","user_name":"hid_bgatv9rp4x32nge"}
```

现在面板上账号显示的是内部 ID（`hid_bgat…`）。有了它至少能确认「这份凭证对应哪个华为云账号」，
排查多账号时有用。`user_name` 当前和 `domain_name` 一样（子用户），不保证一定有真名。

**改动量**：约 15 行，账号列表多一列。

### ★☆☆ `/v1/llm/vendors` —— 第三方厂商模型清单

```
GET …/v1/llm/vendors  → 200
vendors[]: {vendor_id:"deepseek", base_url:"https://api.deepseek.com",
            chat_completions_path:"/chat/completions", api_url, api_key_url,
            models:[{model_id:"deepseek-v4-pro", …}, …]}
```

有 `api_url` 和 `api_key_url` —— 这是客户端「自带 key 接第三方模型」的配置源。
但**当前账号下 `third-party-model/model/list` 返回 `total: 0`**，说明这个能力没开通。
真要用得先有第三方 provider 配置，暂时只是「知道有这么回事」。

### ★☆☆ `/snap-manager/v1/member/roles` —— 判断套餐/角色

```
→ 200 {"team_roles":[], "enterprise_roles":["enterprise_admin"]}
```

配合 `/v1/llm/tenant/settings`（我们打出来是 `403 TM.00001035 当前套餐不支持该功能`），
可以判断「这个账号是什么套餐、哪些能力不可用」。面板做个能力矩阵才有意义，单看没价值。

---

## 四、判断为「不要接」的

| 接口 | 理由 |
|---|---|
| `/cag/*`（137 条） | 本机 Agent Core，绑 `127.0.0.1`，网关拿不到也没用 |
| `/session/*` `/tui/*` `/pty` `/permission` `/provider` 等（106 条） | 同上，IDE 进程内服务 |
| `/v1/skill-center/*` `/v1/skills-rules/*` `/v1/prompts/*` | 技能与提示词广场，IDE 侧功能 |
| `/v1/agent-center/agents/useragents` | 实测 404 / `TM.00001001 未找到合法可路由api`。这是客户端拿 `model_parameters` 的路，网关走 `/v1/model/builtin` + 实测表已经够用 |
| `/v1/builtin-tools` `/v1/mcp-tools` | 在 snap-access 与 chatDomain 上都是 404，实际挂在本地 Core 侧 |
| `/api/v1/queue/status` | 要 `task_id` 才有意义，网关侧拿不到稳定的 task 标识 |
| `/v1/im-linker/*` `/v3/auth/domains` `/v3/projects` `/v3/regions` | 二维码登录 / IAM 项目域，与推理网关无关 |
| `/snap-manager/v1/token/renew` | **不要探**：refresh_token 一次性轮换，探一次就把线上账号踢下线。项目现有续期路径已验证可用，不动 |

---

## 五、结论

1. **积分体系是健康的，不用动**：`/v1/ops/delivery` + `/v1/ops/claim`（`channel="IDE"`）+
   `/snap-manager/v1/statistics/plugin` 实测全 200，签到实领 1000 积分（11500 → 12500）。
   项目里 `welfare_claim_daily()` 早就实现对了。
2. **黄的只有「每日 token 额度」那半边**：`benefit/claim`、`tokens/balance`、`gateway/config` 三个全 404，
   面板还在按老协议请求，用户看到的是无法自救的报错。接 `/v1/benefit-gateway-config`
   就能把话说明白（`enabled:false`）。
3. **推理主线健康**：`chat/completions`、`model/builtin` 实测都 200。
4. **客户端那 243 个本地接口没有参考价值** —— 它们解决的是 IDE 自己的会话、终端、索引问题，
   跟「给外部客户端提供 OpenAI 兼容接口」是两件事。之前想从客户端抄 tools 处理抄不到，原因也在这里：
   客户端用 `mcp_servers` 把工具交给服务端驱动，压根不走 `tools`。

### 方法论教训（写下来免得再犯）

- **探接口必须把方法试全**。POST-only 的接口用 GET 打会伪装成「不存在」，
  差别只在错误串后半句：`method GET not found` vs `has not been published`。
  我第一版就是只发 GET，把签到接口误判成已下线。
- **参数大小写要照着客户端抄，不要自己想**。`channel` 读的时候不区分大小写，
  领取时必须大写 `IDE`，这种不对称只能靠实测发现。
- **别把两套账合并成一句结论**。token 额度和积分是两条独立链路、两套接口、两种失效方式。

---

## 附：复现方式

探针脚本见 `.workbuddy/tmp/probe_*.py`（本地，未入库，跑完已清理）。核心四件事：

1. 用 `ca_proxy.pick_codearts_session()` 拿 AK/SK/securitytoken；
2. 头里带 `X-Security-Token` + `Agent-Type: PromptCenter`；
3. **query 参数必须走 `aksk_sign(..., query=params)`**，不能只拼进 URL ——
   否则 canonical query 对不上，回 `APIG.0301 verify ak sk signature fail`；
4. POST 的 body 要参与 `payload_hash`，漏掉同样回 0301。

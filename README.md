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

- 132 个套件：106 个 Python + 26 个 JS；JS 需要 PATH 上有 `node`，缺失时会跳过并提示。
- CI（`.github/workflows/tests.yml`）跑同一条命令：Ubuntu 上 python 3.9 与 3.12，Windows 上 python 3.12。

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

- 用信号量**串行化**码道请求（默认 1 个，`CODEARTS_CONCURRENCY` 可调）；
- 对瞬时限流做**退避重试**（5/12/25/40 秒，最多 5 次），覆盖
  `429 ModelArts.811xx`（TPM 打满）与 `400 TM.00001041`（并发上限）。

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

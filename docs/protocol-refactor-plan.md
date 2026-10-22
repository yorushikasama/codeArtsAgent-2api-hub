# 协议层抽取长计划（ca_proxy → ca_protocol）

> 目标：把 `ca_proxy.py` 里「协议转换」的部分搬进 `ca_protocol.py`，让它成为**不碰
> socket、不读全局、不写日志**的纯函数层，从而能直接单测，而不是每次起服务器打 socket。
>
> 原则只有一条：**只移动，不改逻辑**。任何顺手发现的 bug 单独记、单独提交，不混进
> 移动提交——否则回归时无法判断是「搬坏了」还是「修错了」。

---

## 0. 现状（2026-10-23 凌晨，全部十刀收工）

| 项 | 数字 |
|---|---|
| `ca_proxy.py` | 20 729 行（起点 22 119） |
| `ca_protocol.py` | 1 620 行，38 个函数 |
| 测试套件 | 133 个（107 Python + 26 JS） |
| `_test_codearts_stream_break.py` | 214 项 |
| `_test_protocol_pure.py` | 41 项（只 import ca_protocol） |
| `_test_protocol_golden.py` | 19 项（逐字节帧序列） |
| 线上 | `codearts-hub` active，跑的是 `d6da9d9` |
| 远端 | `origin/main` = `d6da9d9` |

已完成十刀：

| 刀 | 搬走的东西 | 测试增量 |
|---|---|---|
| 1 | `anthropic_sse_frame`、`anthropic_stop_reason` | +10 |
| 2 | `strip_empty_function_calls`、`clean_responses_frame` | +4 |
| 3 | `normalize_roles` | +3 |
| 4 | `anthropic_text`、`anthropic_usage`、`best_cached_tokens` | +4 |
| 5 | `iter_sse_lines`、`strip_data_prefix`、`SSE_READ_BLOCK`、`stream_messages_events`、`new_id`、`anthropic_message_id`、`anthropic_error_type` | +19 |
| 6 | `messages_to_chat` 一族 11 个函数 | +18 |
| 7 | `stream_responses_events` + 依赖闭包 18 个顶层定义（696 行） | +14 |
| 8 | `chat_to_messages`、`anthropic_parse_tool_input` | +7 |
| 9 | 传输原语（在第 5 刀顺手完成） | — |
| 10 | 拆掉 44 条别名桥，57 处调用点改成 `ca_protocol.x` | — |

`ca_proxy` 里只剩两个包装函数（它们要注入本地状态）：
`messages_to_chat`（注入模型表）、`stream_responses_events`（注入 `ca_webtools`）。

**三个反复出现的坑，守卫都在 `_test_codearts_stream_break.py` 里**：

1. 搬走的函数少写别名（第五刀 `_new_id`，20 处悬空）；
2. 搬进 `ca_protocol` 的函数内部还在叫旧下划线名（第六刀 `_anthropic_text` 23 处、
   第七刀 `time` 漏 import）；
3. 前两种 import 都不报错，只在真跑时报 `NameError`，而且可能被调用方的
   `try/except` 吞成「少一帧」。

对应三道静态检查（都反向验证过会报红）：
- `ca_proxy` 不许调用「ca_protocol 有、自己没有」的旧名；
- `ca_protocol` 内部不许残留旧下划线名；
- `symtable` 检查两个文件都没有「用了但没定义/没 import」的全局名。

**完成标志全部达成**：`ca_proxy` ≤ 21 000 行、别名桥已拆、纯层可脱离服务器测试。

---

## 1. 目标物清单（全部搬完）

| 目标 | 计划行数 | 结果 |
|---|---:|---|
| `stream_messages_events` | 200 | ✅ 第 5 刀 |
| `messages_to_chat` 一族 | 296 | ✅ 第 6 刀（实际 11 个函数） |
| `stream_responses_events` | 496 | ✅ 第 7 刀（实际依赖闭包 696 行） |
| `chat_to_messages` | 47 | ✅ 第 8 刀（+ 参数解析 15 行） |
| `iter_sse_lines` / `strip_data_prefix` | 56 | ✅ 第 5 刀顺手 |
| 别名桥 | 44 条 | ✅ 第 10 刀拆掉 |

最终：`ca_proxy.py` 20 729 行（-1 390），`ca_protocol.py` 1 620 行。

**依赖顺序（必须按这个顺序，否则会拖出循环导入）**

```
帧层/映射（已完成）
      ↓
第 5 刀  stream_messages_events        ← 已完成（0ecc9e7）
      ↓
第 6 刀  Anthropic 请求层（6 个小函数 + messages_to_chat）  ← 已完成（5c10396）
      ↓
第 7 刀  stream_responses_events + _responses_usage
      ↓
第 8 刀  chat_to_messages（非流式回包）
      ↓
第 9 刀  传输原语 iter_sse_lines / strip_data_prefix  ← 已在第 5 刀顺手搬完
      ↓
第 10 刀 拆别名桥（删 ca_proxy 里的 `x = ca_protocol.x`，调用点改用 ca_protocol.x）
```

---

## 2. 每一刀的固定动作（照抄执行）

假设要搬 `foo`：

1. **量边界**：`grep -n "^def foo" ca_proxy.py`，确认到下一个顶层 `def` 的行数；
2. **查依赖**：`sed -n 'A,Bp' ca_proxy.py | grep -oE '\b[a-z_][a-z0-9_]*\(' | sort -u`
   —— 逐个确认依赖已在本模块或 `ca_protocol` 里；
3. **脚本化搬运**（不要手工复制，避免漏行）：

   ```python
   import re
   s = open('ca_proxy.py', encoding='utf-8').read()
   m = re.search(r"^def foo\(.*?(?=^def |\Z)", s, re.S | re.M)
   block = m.group(0).rstrip() + "\n"
   s = s[:m.start()] + s[m.end():]
   s = s.replace('X = ca_protocol.X\n', 'X = ca_protocol.X\nfoo_alias = ca_protocol.foo\n', 1)
   open('ca_proxy.py','w',encoding='utf-8',newline='\n').write(s)
   ```

4. **在 `ca_protocol` 里改名**（去掉前导下划线，如 `_foo` → `foo`），并**全文替换函数体
   内对同族函数的调用**——第 4 刀就是漏了这一步才 `NameError`：别名只解决调用方，
   不解决被搬函数内部的互相引用；
5. **桥接**：`ca_proxy` 顶部别名区加一行，所有原调用点保持不动；
6. **实跑一次**：`python -c "import ca_proxy, ca_protocol; print(...)"`，
   import 通过不等于函数能跑，必须真调一次；
7. **回归**：`python tests/_test_codearts_stream_break.py` + 相关套件；
8. **线上**：`scp ca_protocol.py ca_proxy.py` → 重启 → 一条真请求；
9. **提交**：标题写明「第 N 刀」、移动了什么、测试增量、验证方式。

---

## 3. 分刀细节

### 第 5 刀：`stream_messages_events`（200 行，最高优先）✅ 已完成（`0ecc9e7`）

- **内容**：Anthropic 流式状态机——`state` 字典 + `ensure_start` / `ensure_thinking` /
  `ensure_text` 三个闭包 + delta 分支 + 收尾帧。
- **依赖**：`anthropic_sse_frame`、`anthropic_stop_reason`、`anthropic_usage`、
  `anthropic_text`（全部已在 `ca_protocol`）+ `anthropic_error_type`（需一并搬，约 10 行）。
- **风险点**：`content_block` 的 index 分配顺序（thinking 在前、text 在后）、
  `content_block_stop` 的时机、`message_delta` 里的 stop_reason 与 usage 合并。
  这些**一律不要动**，整块搬。
- **验收**：现有 `_test_anthropic_messages`（50）与 `_test_codearts_stream_break`
  必须全绿；再抓一次真实 `/v1/messages` 流（需在面板开启）对比帧序列。
- **实际结果**：HTTP 读取层（`iter_sse_lines` / `strip_data_prefix` / `SSE_READ_BLOCK`）
  与三个小函数（`new_id` / `anthropic_message_id` / `anthropic_error_type`）一并搬完。
  线上验了两条真请求（流式正文、流式工具调用），帧序列与用量行都对。
  **踩坑见 §0 末尾**——漏别名不会立刻炸，会被 `try/except` 吞成「少一帧」。

### 第 6 刀：Anthropic 请求层（约 250 行）✅ 已完成（`5c10396`）

- 搬 `_anthropic_system_text`、`_anthropic_tool_choice`、`anthropic_tools_to_chat`、
  `anthropic_effort_from_messages`、`_anthropic_content_to_text`、
  `_anthropic_blocks_to_messages`、`messages_to_chat`。
  （`_anthropic_message_id` 已在第 5 刀搬走，别重复搬。）
- **顺序**：先搬 5 个叶子（无依赖），再搬 `_anthropic_blocks_to_messages`，最后
  `messages_to_chat`；每搬一个跑一次 `import` + 实调。
- **风险点**：`messages_to_chat` 里 `max_tokens` 的默认值来自
  `model_default_max_output_tokens`（查模型表），这是唯一的外部依赖——**不要搬它**，
  通过参数注入（`default_max_tokens=None`）或保留在 `ca_proxy` 里调用后传值。
- **验收**：`_test_anthropic_messages` 50 项 + 新增对拍测试（见 §4）。
- **实际结果**：真正的依赖簇是 **11 个**函数，比计划多出 4 个——
  `_anthropic_content_to_text` 不是叶子，它拉着 `_anthropic_block_text` /
  `_anthropic_image_part` / `_anthropic_document_text` / `_anthropic_json_text`。
  所以「先搬叶子」这句要按**实际调用图**判断，别信函数清单。
  `model_default_max_output_tokens` 按计划注入；`ca_proxy` 留同名包装函数。
  对拍用「`git archive HEAD` 到临时目录 + 同一份 25 条 payload 脚本跑两遍」，
  逐字节零差异（比只跑单测硬）。

### 第 7 刀：`stream_responses_events`（496 行，最大）✅ 已完成（`d026512`）

- 依赖 `_responses_usage`、`anthropic_error_type` 等；`clean_responses_frame` 已在
  纯函数层，但**调用点在 ca_proxy**，这刀一起看。
- **风险点**：Responses 事件种类多（`response.output_item.added` /
  `content_part.added` / `output_text.delta` / reasoning summary / `.done` 系列），
  任何顺序变化都会让 Codex CLI 解析失败。整块搬、不改顺序。
- **前置**：先给现状录一份「事件序列 golden」（见 §4），搬完逐帧对比。
- **验收**：golden 对拍 + `_test_codearts_stream_break` 里 responses 相关用例。
- **实际**：用 AST 算依赖闭包得到 18 个顶层定义（不只是 7 个函数，还有 7 个正则
  常量与 4 个工具函数），共 696 行。`ca_webtools` 是唯一外部依赖，用
  `webtools=None` 参数注入。golden 覆盖 14 个场景（含 DSML、namespace、
  截断参数、网路工具代跑），HEAD 与搬家后逐字节一致。
  **新坑**：漏 `import time`，被 golden 脚本的 `time` patch 盖住了，最后靠
  symtable 静态检查抓到。

### 第 8 刀：`chat_to_messages`（47 行，非流式回包）✅ 已完成（`4c4e306`）

- 依赖 `anthropic_usage`、`anthropic_stop_reason`（已就位）。
- 顺带处理 `stop_sequence` 字段：当前恒 `None`，如果接了 `stop` 参数，这里可以回填
  **命中的那一条**（属于改逻辑，单独提交）。
- **实际**：连带 `anthropic_parse_tool_input`（15 行，唯一依赖）一起搬。

### 第 9 刀：传输原语（可选，45 + 11 行）✅ 已在第 5 刀顺手搬完

- `iter_sse_lines` 是**读取效率**优化，不是协议语义；放 `ca_protocol` 会让「纯函数层」
  混入 I/O 概念。原计划**不搬**，但第 5 刀搬状态机时把它一起带走了（状态机是它的
  唯一使用者之一，且搬完 `SSE_READ_BLOCK` 不会两处漂移）。
- 现状：`ca_protocol.iter_sse_lines` / `strip_data_prefix` / `SSE_READ_BLOCK`，
  `ca_proxy` 保留同名别名。若以后要恢复「纯函数层不含 I/O」的洁癖，再单开一刀
  拆到 `ca_stream.py`，不要混进协议刀。

### 第 10 刀：拆桥（收尾）✅ 已完成（`d6da9d9`）

- 删掉 `ca_proxy` 顶部所有 `x = ca_protocol.x` 别名，调用点改成
  `ca_protocol.x(...)`（一次性机械替换 + 全量回归）。
- 目的：避免以后有人改 `ca_protocol` 却不知道 `ca_proxy` 还有一份名字指向它，
  也避免「到底用的是哪个」的困惑。
- **实际**：44 条别名里 25 条早已无人调用（函数搬走后只剩别名），一并清掉；
  实际只改 57 处调用点。7 个测试套件的引用同步改到 `ca_protocol`，
  「别名指向同一对象」的断言改成「旧名字在 ca_proxy 里已消失」。
  保留两个包装函数（`messages_to_chat` / `stream_responses_events`），
  因为它们要注入 ca_proxy 的本地状态。

---

## 4. 测试策略：从「起服务器」到「构造输入」 ✅ 已落地

现在协议层的测试靠 `_test_anthropic_*` 起真服务打 socket；搬完之后每层都能直接喂数据。
三条都已实现：

1. **纯层套件** `tests/_test_protocol_pure.py`（41 项）：只 import `ca_protocol`，
   覆盖帧层、角色归一、用量映射、请求翻译、SSE 读取、DSML、引用标注、namespace，
   外加纯度断言（不许 `socket` / `open(` / `self.wfile` / `log(` / `ca_settings`，
   只依赖 `json` / `re` / `time` / `uuid`）。
2. **golden 套件** `tests/_test_protocol_golden.py`（19 项，套件数 133）：
   - `tests/golden/anthropic_stream.json`：7 个场景 / 43 帧；
   - `tests/golden/responses_stream.json`：6 个场景 / 50 帧；
   - 场景清单与打桩逻辑放在 `tests/_golden_cases.py`，录制与对拍共用，避免两边漂移；
   - 重录入口 `python tests/record_protocol_golden.py`，且只在「确认行为变化是想要的」时跑。
   - 录制时把 `new_id` 与 `time` 钉死，所以能**逐字节**比较；套件里还有一条
     「连跑两次结果完全相同」，防止以后有人引入未打桩的随机源把 golden 变成装饰。
   - 反向验证过：把 `message_start` 改成 `message_startX`，6 个场景当场变红。
3. **请求层对拍**：第 6 刀用 25 条 payload 在 HEAD 与工作区之间逐字节对拍
   （文本 / 图片 / 文档 / 工具 / 工具结果 / 思考块 / system / effort / 非法输入），零差异。

原始计划里提过的「golden 存 `tests/golden/anthropic_stream.json`」已经照做，
只是帧覆盖从「一串 delta」扩到了 13 个场景（含 Responses）。

## 5. 与协议抽取无关、但待处理的事项

七项都已处理完（2026-10-23 凌晨，`ca_protocol.empty_conversation_error` 与
`_ResizableSemaphore` 是这轮的两个新东西）：

| # | 事项 | 结果 |
|---|---|---|
| 1 | 只有 system 消息时上游 400（`ModelArts.81001`） | ✅ 三条协议入口统一在请求阶段回 400，文案点名 `81001` 并说明缺 user/assistant 回合（`ca_protocol.empty_conversation_error`） |
| 2 | `clean_responses_frame` 每帧多一个换行 | ✅ 改成 `rstrip("\n") + "\n\n"`，只留一个空行；纯层套件加了「不能以 `\n\n\n` 结尾」的断言 |
| 3 | `stop` 对 reasoning 也生效 | ✅ README「排障速查」写清症状（正文空 + finish=stop）与确认方式 |
| 4 | `response_format` 已明确 400 | ✅ 同一节写明原因与替代方案（tools / function calling） |
| 5 | 面板「码道并发与冷却」英文/繁中词典 | ✅ en / zh-Hant 各补 9 条；顺带修掉面板里漏出来的 markdown `**` |
| 6 | 每账号并发的动态生效 | ✅ 信号量换成容量可调的 `_ResizableSemaphore`：按「在跑数不变」换算空闲数，改完下一个取号就生效；429 文案与 pool 快照也读实时值 |
| 7 | `messages` 里 `developer` 角色在 Responses 侧 | ✅ 第 3 刀已归一，这里只留记录 |

---

## 6. 验收与回滚

**每刀的验收门槛（缺一不可）**

1. `python tests/run_all.py --jobs 4` 全绿（不是只跑相关套件）；
2. `python scripts/check_clean_checkout.py` clean；
3. 线上重启后一条真实请求 200，`usage` 正常记账；
4. 该刀涉及的协议路径真跑一次（`/v1/chat/completions`、`/v1/messages` 或
   `/v1/responses`，取决于搬的是哪一层）。

**回滚**

- 单刀回滚：`git revert <sha>`，因为每刀是独立提交、只移动不改逻辑，revert 安全；
- 别名桥让回滚更容易：即使 `ca_protocol` 里的函数有问题，只要把 `ca_proxy` 的
  别名指回本地实现（或恢复被删的 def）就能立刻回到旧路径；
- 线上有 `ca_proxy.py.bak.*` / `ca_codearts.py.bak.*`，重启前可秒回。

**完成标志（全部达成）**

- ✅ `ca_proxy.py` 20 729 行（≤ 21 000），`ca_protocol.py` 覆盖全部协议转换；
- ✅ `_test_protocol_pure.py`（41 项）全绿，只 import `ca_protocol`；
- ✅ `ca_proxy` 顶部不再有别名桥（只剩两个注入包装）；
- ✅ golden 套件钉住两种流式协议的逐字节帧序列（19 项）；
- ✅ 套件数 133（README 已同步）。

---

## 7. 建议排期（按半天计）

| 时段 | 内容 |
|---|---|
| 1 | ~~第 5 刀 + golden 录制 + 全量回归~~ ✅ 2026-10-22 夜（golden 用「第 14 节真调」代替） |
| 2 | ~~第 6 刀（5 个叶子 + blocks + messages_to_chat）~~ ✅ 2026-10-22 深夜（实际 11 个函数） |
| 3 | ~~第 7 刀~~ ✅ 2026-10-23 凌晨（golden 14 场景逐字节对拍） |
| 4 | ~~第 8 刀 + 第 10 刀拆桥~~ ✅ 2026-10-23 凌晨（第 9 刀已在第 5 刀完成） |
| 5 | ~~`_test_protocol_pure.py` + 文档收尾~~ ✅ 2026-10-23 凌晨（遗留项 1-6 同批处理完，见 §5） |

**不要在同一时段混做两刀**：每刀都要一次完整回归，混做会让失败定位成本翻倍。

# 协议层抽取长计划（ca_proxy → ca_protocol）

> 目标：把 `ca_proxy.py` 里「协议转换」的部分搬进 `ca_protocol.py`，让它成为**不碰
> socket、不读全局、不写日志**的纯函数层，从而能直接单测，而不是每次起服务器打 socket。
>
> 原则只有一条：**只移动，不改逻辑**。任何顺手发现的 bug 单独记、单独提交，不混进
> 移动提交——否则回归时无法判断是「搬坏了」还是「修错了」。

---

## 0. 现状（2026-10-22 深夜，第六刀收工后）

| 项 | 数字 |
|---|---|
| `ca_proxy.py` | 21 536 行 |
| `ca_protocol.py` | 807 行，25 个函数 |
| 测试套件 | 131 个（105 Python + 26 JS） |
| `_test_codearts_stream_break.py` | 193 项 |
| 线上 | `codearts-hub` active，跑的是 `5c10396` |
| 远端 | `origin/main` = `5c10396` |

已完成六刀（都遵循「别名桥接、调用点零改动」）：

| 刀 | 搬走的东西 | 测试增量 |
|---|---|---|
| 1 | `anthropic_sse_frame`、`anthropic_stop_reason` | +10 |
| 2 | `strip_empty_function_calls`、`clean_responses_frame` | +4 |
| 3 | `normalize_roles` | +3 |
| 4 | `anthropic_text`、`anthropic_usage`、`best_cached_tokens` | +4 |
| 5 | `iter_sse_lines`、`strip_data_prefix`、`SSE_READ_BLOCK`、`stream_messages_events`、`new_id`、`anthropic_message_id`、`anthropic_error_type` | +19 |
| 6 | `messages_to_chat` 一族 11 个函数（含 `anthropic_json_text`、`anthropic_blocks_to_messages`） | +18 |

`ca_protocol.py` 现有函数：`anthropic_text`、`best_cached_tokens`、
`anthropic_usage`、`anthropic_sse_frame`、`normalize_roles`、
`strip_empty_function_calls`、`clean_responses_frame`、`anthropic_stop_reason`、
`new_id`、`anthropic_message_id`、`anthropic_error_type`、`strip_data_prefix`、
`iter_sse_lines`、`stream_messages_events`、`anthropic_json_text`、
`anthropic_block_text`、`anthropic_image_part`、`anthropic_document_text`、
`anthropic_content_to_text`、`anthropic_system_text`、`anthropic_tool_choice`、
`anthropic_tools_to_chat`、`anthropic_effort_from_messages`、
`anthropic_blocks_to_messages`、`messages_to_chat`。

**第五、第六两刀踩的是同一个坑**：搬走的函数在 `ca_proxy` 少写别名（第五刀的
`_new_id`），或搬进 `ca_protocol` 后内部还叫旧下划线名（第六刀的 `_anthropic_text`）。
两者都不会在 import 时暴露：前者被 `_responses_codearts` 的 `try/except` 吞成
「少一帧」，后者只在真调 `messages_to_chat` 时才 `NameError`。
测试现在做**双向静态普查**：`ca_proxy` 不许悬空旧名、`ca_protocol` 内部不许残留
旧名，两处都用「临时去掉别名 / 加回旧名」反向验证过会报红。



**关键结论：第 5 刀要用的依赖已经全部就位**，不需要再拖旁支。

---

## 1. 剩余目标物清单（行号取自 `dea939c`）

| 函数 | 行数 | 位置 | 依赖 |
|---|---:|---|---|
| ~~`stream_messages_events`~~ | ~~200~~ | 第 5 刀已搬 | — |
| `stream_responses_events` | 496 | `ca_proxy.py:16402` | 同上 + `_responses_usage` 等 |
| ~~`messages_to_chat` 一族（11 个）~~ | ~~296~~ | 第 6 刀已搬 | — |
| `chat_to_messages` | 47 | `ca_proxy.py:16032` | `anthropic_usage`、`anthropic_stop_reason` |
| ~~`iter_sse_lines`~~ | ~~45~~ | 第 5 刀已搬 | — |
| ~~`strip_data_prefix`~~ | ~~11~~ | 第 5 刀已搬 | — |

剩余约 543 行（Responses 状态机 496 + 非流式回包 47）；搬完 `ca_proxy.py`
约降到 21 000 行、`ca_protocol.py` 约 1 300 行。
（第六刀后实测：21 536 / 807 行。）

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

### 第 7 刀：`stream_responses_events`（496 行，最大）

- 依赖 `_responses_usage`、`anthropic_error_type` 等；`clean_responses_frame` 已在
  纯函数层，但**调用点在 ca_proxy**，这刀一起看。
- **风险点**：Responses 事件种类多（`response.output_item.added` /
  `content_part.added` / `output_text.delta` / reasoning summary / `.done` 系列），
  任何顺序变化都会让 Codex CLI 解析失败。整块搬、不改顺序。
- **前置**：先给现状录一份「事件序列 golden」（见 §4），搬完逐帧对比。
- **验收**：golden 对拍 + `_test_codearts_stream_break` 里 responses 相关用例。

### 第 8 刀：`chat_to_messages`（47 行，非流式回包）

- 依赖 `anthropic_usage`、`anthropic_stop_reason`（已就位）。
- 顺带处理 `stop_sequence` 字段：当前恒 `None`，如果接了 `stop` 参数，这里可以回填
  **命中的那一条**（属于改逻辑，单独提交）。

### 第 9 刀：传输原语（可选，45 + 11 行）✅ 已在第 5 刀顺手搬完

- `iter_sse_lines` 是**读取效率**优化，不是协议语义；放 `ca_protocol` 会让「纯函数层」
  混入 I/O 概念。原计划**不搬**，但第 5 刀搬状态机时把它一起带走了（状态机是它的
  唯一使用者之一，且搬完 `SSE_READ_BLOCK` 不会两处漂移）。
- 现状：`ca_protocol.iter_sse_lines` / `strip_data_prefix` / `SSE_READ_BLOCK`，
  `ca_proxy` 保留同名别名。若以后要恢复「纯函数层不含 I/O」的洁癖，再单开一刀
  拆到 `ca_stream.py`，不要混进协议刀。

### 第 10 刀：拆桥（收尾）

- 删掉 `ca_proxy` 顶部所有 `x = ca_protocol.x` 别名，调用点改成
  `ca_protocol.x(...)`（一次性机械替换 + 全量回归）。
- 目的：避免以后有人改 `ca_protocol` 却不知道 `ca_proxy` 还有一份名字指向它，
  也避免「到底用的是哪个」的困惑。

---

## 4. 测试策略：从「起服务器」到「构造输入」

现在协议层的测试靠 `_test_anthropic_*` 起真服务打 socket。搬完之后每层都能直接喂数据。

**建议新增独立套件 `tests/_test_protocol_pure.py`**（套件数 131 → 132，需同步 README）：

1. **帧序列 golden**：给定一串 chat delta（文本 / reasoning / tool_calls / finish），
   断言产出的 Anthropic 帧序列**逐字节相等**。golden 从现有实现录一次，搬完用它对比，
   这是「搬而不改」最硬的证明。
2. **边界**：空 delta、只有 reasoning、只有 tool_calls、finish 缺失、usage 缺失、
   非法 JSON 行、`[DONE]` 前后多余空行。
3. **请求层**：Anthropic 请求 → chat 请求的对拍（图片、tool_result、thinking、
   `stop_sequences`、`metadata.user_id`）。
4. **不纯检查**：`ca_protocol` 源码里不许出现 `socket` / `self.` / `log(` / `open(`
   —— 一条静态断言，防止以后有人往里塞 I/O。

录制 golden 的方式：搬之前跑一次 `stream_messages_events(list_of_chunks, ...)`，
把输出 `json.dumps` 存成 `tests/golden/anthropic_stream.json`；搬之后同输入同输出。

---

## 5. 与协议抽取无关、但待处理的事项

| # | 事项 | 现状 | 建议 |
|---|---|---|---|
| 1 | 只有 system 消息时上游 400（`ModelArts.81001`） | 既有行为，未处理 | 产品决定：补一条 user 消息 or 原样透出错误。单独提交 |
| 2 | `clean_responses_frame` 每帧多一个换行 | 既有行为，SSE 容忍 | 与第 7 刀一起归一（改逻辑，单独提交） |
| 3 | `stop` 对 reasoning 也生效 | 上游行为 | 写进 README 排障段，避免被当成「流被吞」 |
| 4 | `response_format` 已明确 400 | 已上线 | 文档补一句「要 schema 用 tools」 |
| 5 | 面板「码道并发与冷却」英文/繁中词典 | 未补 | 若开英文界面，键缺失会回落中文；补 i18n |
| 6 | 每账号并发的动态生效 | 需重启（已写明） | 可选：实现「空闲时重建信号量」 |

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

**完成标志**

- `ca_proxy.py` ≤ 21 000 行，`ca_protocol.py` 覆盖全部协议转换；
- 新增 `_test_protocol_pure.py` 全绿，且能脱离服务器运行；
- `ca_proxy` 顶部不再有别名桥；
- 三份协议文档（README / docs/codearts-projects-study.md / 本文件）状态一致。

---

## 7. 建议排期（按半天计）

| 时段 | 内容 |
|---|---|
| 1 | ~~第 5 刀 + golden 录制 + 全量回归~~ ✅ 2026-10-22 夜（golden 用「第 14 节真调」代替） |
| 2 | ~~第 6 刀（5 个叶子 + blocks + messages_to_chat）~~ ✅ 2026-10-22 深夜（实际 11 个函数） |
| 3 | 第 7 刀（最大，留足时间看事件顺序） |
| 4 | 第 8 刀 + 第 10 刀拆桥（第 9 刀已在第 5 刀完成） |
| 5 | `_test_protocol_pure.py` 补全、文档收尾、遗留项 1-4 |

**不要在同一时段混做两刀**：每刀都要一次完整回归，混做会让失败定位成本翻倍。

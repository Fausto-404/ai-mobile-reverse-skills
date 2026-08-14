# AI Mobile Reverse Skills

AI Mobile Reverse Skills 是一套面向移动安全场景的阶段化分析产品规范，用于将 APK 静态侦察、抓包联动、SO/JNI 深挖、加密与漏洞综合分析、验证设计以及报告交付组织成一条可连续推进的执行链。

如果你只是想快速上手，建议先看：

- [USER-README.md](USER-README.md)

它面向的输入材料包括：

- Android APK
- 脱壳后、反编译后的目录
- Jadx 反编译结果
- Burp / Yakit  抓包结果
- so / JNI 相关材料
- IDA / Ghidra 工程
- 前序阶段生成的结构化 JSON 和报告

它的设计重点不是提供零散 Prompt，而是提供：

- 可供上层 AI / Skill 复用的总控入口规范
- 固定的 6 阶段执行规程
- 分阶段 MCP 使用规范
- 本地索引脚本与 Native 自动化辅助脚本
- 可直接沉淀的结构化交付产物

## 产品能力

它能帮助你按顺序完成以下 6 件事：

1. [agent-01-sample-recon.md](agents/agent-01-sample-recon.md)
2. [agent-02-protocol-mapper.md](agents/agent-02-protocol-mapper.md)
3. [agent-03-crypto-native-analyzer.md](agents/agent-03-crypto-native-analyzer.md)
4. [agent-04-crypto-vuln-analyzer.md](agents/agent-04-crypto-vuln-analyzer.md)
5. [agent-05-validation-designer.md](agents/agent-05-validation-designer.md)
6. [agent-06-reporter.md](agents/agent-06-reporter.md)

整体结构如下：

- 根 [SKILL.md](SKILL.md) 负责总控与路由
- `agents/agent-01` 到 `agent-06` 负责阶段执行
- [MCP-INTEGRATION.md](docs/MCP-INTEGRATION.md) 负责阶段接入规范
- `tools/scripts/*.py` 负责结构化索引增强与 Native 自动化辅助

## 运行模式

这套 Skills 支持两大类运行方式，并允许在开始时提前选择模式，而不是临场由系统猜测。无论选择哪种模式，流程都从第一阶段开始，区别只在于后续哪一段开始自动接管。

### 1. 逐阶段步进模式

适合希望人工控制节奏的场景。

选择方式：

```text
run_mode: step_by_step
```

特点：

- 由测试人员逐阶段下发指令
- 每一阶段完成后默认挂起
- 人工先复核当前阶段的 JSON / Markdown 产物，再决定是否继续

适用方式：

- `开始第一步`
- `开始第二步`
- `开始第三步`

### 2. 自动链

选择方式：

```text
run_mode: auto_chain
auto_chain_mode: A/B/C
```

自动链再细分为 3 条链路。

#### 链路 A：分析闭环

适合以下场景：

- 从第一阶段开始执行
- 第一阶段完成后，需要人工完成检测绕过、代理配置、抓包准备等前置工作
- `burp-mcp` / `yakit-mcp` 与 `ghidra-mcp` / `ida-mcp` 已接通

运行范围：

- Phase 1 人工确认
- Phase 2 -> Phase 3 -> Phase 4 -> Phase 5 -> Phase 6 自动推进

说明：

- 第一阶段仍然正常执行
- 第一阶段结束后，等待人工完成抓包与其他前置准备
- 即使人工已经做好前置准备，系统仍会先做前置检查，而不是直接跳过检测结论、抓包材料和 Native 线索判断
- 若关键条件成立，则从第二阶段自动推进到第六阶段

#### 链路 B：验证闭环

适合以下场景：

- 从第一阶段开始执行
- 前 1-3 阶段由人工逐步确认
- 人工已经确认需要在第四阶段后自动进入漏洞验证与报告交付阶段

运行范围：

- Phase 1 -> Phase 2 -> Phase 3 人工确认
- Phase 4 -> Phase 5 -> Phase 6 自动推进

说明：

- 前三阶段仍然正常执行并允许人工逐步确认
- 从第四阶段开始，系统会自动衔接到第五和第六阶段
- 适合“前面先人工分析，后面自动收口”的场景

#### 链路 C：直通车

适合以下场景：

- 一开始就已完成全部人工前置准备
- `jadx-mcp`、`burp-mcp` / `yakit-mcp`、`ghidra-mcp` / `ida-mcp` 全部已接通
- 抓包结果已经准备完毕

运行范围：

- Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5 -> Phase 6

说明：

- 直通车模式不是跳过第一阶段，而是第一阶段完成后，继续自动推进后续阶段
- 即使用户已经人工确认“当前 App 可抓包、可调试”，系统仍然会先执行第一阶段的样本侦察和检测分析，再决定是否自动进入后续链路

### 模式选择原则

- 如果你希望人工一阶段一阶段确认结果，就显式选择：
  - `run_mode: step_by_step`
- 如果你希望系统在条件满足后自动继续，就显式选择：
  - `run_mode: auto_chain`
- 若希望第一阶段后、从第二阶段起自动化，通常选择：
  - `auto_chain_mode: A`
- 若希望前 1-3 阶段人工确认、从第四阶段起自动化，通常选择：
  - `auto_chain_mode: B`
- 若从第一阶段起全流程自动推进，通常选择：
  - `auto_chain_mode: C`

## 标准启动模板

为了避免每次临场组织输入，推荐按“两段式交互”启动。

### 第一步：先声明模式

#### 模板 1：逐阶段步进模式

```text
run_mode: step_by_step
```

#### 模板 2：自动链 A（分析闭环）

```text
run_mode: auto_chain
auto_chain_mode: A
```

#### 模板 3：自动链 B（验证闭环）

```text
run_mode: auto_chain
auto_chain_mode: B
```

#### 模板 4：自动链 C（直通车）

```text
run_mode: auto_chain
auto_chain_mode: C
```

### 第二步：再进入第一阶段

无论选择哪种模式，后续都先进入第一阶段模板：

```text
step: 1
analysis_mode: local_source/jadx_mcp_session
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: yes/no
```

补充说明：

- `step_by_step`：从第一步开始，每个阶段结束后默认挂起
- `auto_chain + A`：从第一步开始，第一阶段后人工完成前置准备，第二阶段起自动化
- `auto_chain + B`：从第一步开始，前 1-3 阶段人工确认，第四阶段起自动化
- `auto_chain + C`：从第一步开始，按高自动化链路连续推进，但第一阶段仍必须先执行

## 设计原则

### 1. 严格只走 6 个阶段

这套 Skill 不会擅自增加新的主阶段，也不会改写你的阶段顺序。

### 2. AI 主导分析

大多数情况下，优先直接通过：

- MCP
- 阶段文档
- 当前上下文材料

让 AI 直接完成分析。

### 3. 阶段脚本默认规则

当前版本采用“AI 主导分析 + 阶段脚本组合”的方式：

- 当第一阶段使用 `local_source` 分析本地代码目录时，默认执行以下 4 个索引脚本：
  - `endpoint_extractor.py`
  - `secret_scanner.py`
  - `native_bridge_indexer.py`
  - `env_guard_indexer.py`
- 当第一阶段使用 `jadx_mcp_session` 时，不默认执行上述 4 个脚本，优先直接消费 `jadx-mcp` 上下文
- `resolve_native_target.py`、`ghidra_target_loader.py` 与 `ida_target_loader.py` 继续保持原有自动化逻辑，不受第一阶段输入方式影响

换句话说，前 4 个脚本的默认执行条件是“走本地代码分析路径”，不是“所有场景无条件执行”。

### 4. Phase 1 不负责脱壳

Phase 1 只分析**已经得到的脱壳后、反编译后的材料**。  
这套 Skill 不把“脱壳”作为它自己的职责。

## 当前形态

当前仓库的形态是：

- Skill 总控规范
- 6 个阶段 Agent 文档
- 本地索引脚本与 Native 自动化辅助脚本

它目前不是一个已经封装好的独立 CLI、TUI 或 Web 控制台。

文档里提到的“你说开始第一步，总控返回模板并路由”，指的是上层 AI / Skill 按 [SKILL.md](SKILL.md) 的规则执行，不代表仓库内已经包含自动对话路由程序。

## 标准使用方式

推荐交互方式如下：

1. 你先说：`开始第一步` / `开始第二步` / `开始第三步`……
2. 总控先返回该阶段的标准输入模板
3. 你按模板补齐材料
4. AI 再正式执行该阶段

标准原则如下：

- 模板只保留当前阶段最基本输入项
- 不要求手动填写 `focus`
- 每个 Agent 默认完成对应阶段的完整分析范围
- 如果提供 `output_dir`，阶段结果应尽量落盘形成标准产物
- 如果 `output_dir` 不存在，应先创建后再写入结果

默认产物原则如下：

- 只要当前阶段已经拿到了足够输入材料，并且用户提供了 `output_dir`，就应尽量把阶段结果写入该目录
- 尤其是第一阶段，在提供 `jadx_mcp=yes + output_dir` 或 `target_dir + output_dir` 后，默认应生成：
  - `file_inventory.json`
  - `tech_stack.json`
  - `entrypoints.json`
  - `env_guard_report.json`
- 除非用户明确说明“只要口头分析，不需要写文件”，否则第一阶段不应只给对话摘要

关于 `env_guard_report.json`，默认要求如下：

- 即使没有发现明确的 Root / Frida / 代理 / SSL Pinning 阻断逻辑，也必须输出该文件
- 文件中必须明确区分：
  - `confirmed`
  - `suspected`
  - `sdk_signal_only`
  - `not_confirmed_yet`
  - `not_observed`
- 不允许因为“暂时没看到”就省略环境校验结果
- 不允许把“未确认”写成“没有问题”

## 统一输出根目录

路径约定：

- 对用户自己的样本目录、抓包目录、输出目录，可以填写真实路径
- 本仓库内部的技术文件、规则文件、模板文件，统一以 `ai-mobile-reverse-skills/` 为根目录使用相对路径引用
- README 与各阶段规则中不应固化任何个人电脑的绝对目录

从第一步开始，一旦你确认了 `output_dir`，它就应被视为整个流程的统一输出根目录。

推荐目录结构如下：

```text
analysis_runs/current_run/
├── step1/
├── step2/
├── step3/
├── step4/
├── step5/
└── step6/
```

默认约定如下：

- 第一步结果写入 `step1/`
- 第二步结果写入 `step2/`
- 第三步结果写入 `step3/`
- 第四步结果写入 `step4/`
- 第五步结果写入 `step5/`
- 第六步结果写入 `step6/`

也就是说，当你第一次提供：

```text
output_dir: analysis_runs/current_run
```

后续默认应按以下路径落盘：

- `analysis_runs/current_run/step1/`
- `analysis_runs/current_run/step2/`
- `analysis_runs/current_run/step3/`
- `analysis_runs/current_run/step4/`
- `analysis_runs/current_run/step5/`
- `analysis_runs/current_run/step6/`

这样做的好处是：

- 每一步产物边界更清楚
- 后续阶段知道该去哪个阶段目录读前序结果
- 输出目录更适合自动衔接和交付
- 避免所有 JSON / Markdown 平铺在同一个目录

建议同时在输出根目录保留两个伴生状态文件：

- `analysis_state.json` — 流程状态（哪个 Phase 在跑）
- `session_blackboard.json` — 知识积累（各 Phase 发现了什么）

### `analysis_state.json` 是什么

`analysis_state.json` 是当前任务的流程状态文件。  
它不负责保存漏洞结论或协议还原结果，而是负责记录：

- 当前任务是谁；
- 当前运行模式是什么；
- 当前执行到第几阶段；
- 哪些阶段已完成、挂起、阻塞或失败；
- 各阶段产物写到了哪里。

它的主要用途是：

- 让系统知道当前流程该停在哪一步、该从哪一步继续；
- 为自动链 A / B / C 提供切换依据；
- 在中断、失败或人工介入后，帮助流程从正确阶段恢复；
- 避免后续阶段重复询问前序阶段产物位置。

### `session_blackboard.json` 是什么

`session_blackboard.json` 是当前任务的**跨 Phase 知识积累文件**，与 `analysis_state.json` 并列存放。

它负责记录各 Phase 发现的关键事实，让下游 Phase 直接读取已知结论，而不是重新推导：

- **Fact**：各 Phase 写入的关键发现，带可信度级别（PATTERN / TRIAGE / CONFIRMED）
- **Intent**：上游 Phase 对下游 Phase 的定向信号（如 Phase 2 指定 Phase 3 的 native 分析目标）
- **Hint**：总控在 auto_chain 模式下写入的质量警告（主要针对 Phase 1-3 的覆盖不足，例如 `stall_warning`）

正常使用时，测试人员不需要手工维护这两个文件。  
`analysis_state.json` 由总控或 `tools/scripts/phase_guard.py` 更新；`session_blackboard.json` 由各 Phase Agent 写入，所有下游 Phase 可读。

如需查看完整字段定义、阶段状态值与自动链切换条件，可参考：

- [docs/STATE-MODEL.md](docs/STATE-MODEL.md)

### 首次使用前建议先配置的参数

如果后续需要自动收敛 so，并从 APK 解包源码中自动拉取目标 so 后导入 Ghidra，建议在任务一开始就先确认：

- `ghidra_root`

同时需要确保当前任务具备 APK 解包源码目录，且目录下可以访问 `lib/<abi>/*.so`。  
反编译代码用于判断“为什么分析这个 so”，APK 解包源码目录用于真正从 `lib/` 中自动拉取目标 so。缺少任意一侧时，只能降级分析，不能宣称完整 SO 自动化链路已完成。若用户显式提供 `.so`，可以作为 native 分析材料使用，但不能称为“自动化拉取 so”。

其中，`ghidra_root` 是本机 Ghidra 安装根目录，需要用户提前填写，后续统一继承。建议在首次使用前通过 `--ghidra-root` 或 `GHIDRA_INSTALL_DIR` 确认一次。

其余与 Ghidra 自动导入相关的内容，例如：

- `ghidra_project_dir`
- `ghidra_project_name`
- `so_search_roots`
- `preferred_abis`

默认应由系统结合 `{output_dir}`、样本目录结构和 so 实际分布自动推导，不要求用户手工填写。

## 路径只需说明一次

为了减少重复输入，这套 Skill 现在默认采用“会话级路径继承”规则。

也就是说，只要你在当前任务里已经明确提供过：

- `target_dir`
- `output_dir`
- `traffic_source`
- `native_analysis_source`
- `target_name`

后续阶段默认自动沿用，不需要你每一步再重复写一遍。

例如：

### 第一次声明

```text
step: 1
analysis_mode: local_source
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: no
```

### 后续继续

你后面可以直接说：

```text
开始第二步
```

如果没有明确更换路径，总控应默认继续使用：

- `target_dir: sample_target/decompiled`
- `output_dir: analysis_runs/current_run`

同理：

- 开始第三步时默认继承 `target_dir`、`output_dir`
- 进入第四步时，默认继承 `output_dir`
- 第六步默认继承 `target_name`、`report_type`、`include_appendix`（若之前已给出）
- 统一输出根目录下的 `step1` 到 `step6` 子目录也默认持续沿用，不需要每一步重新指定

## 每一步的标准输入模板

这些模板用于**进入具体阶段**。  
如果你已经在前面声明过模式，那么后续阶段只需要补当前阶段缺失的材料；路径和前序上下文默认自动继承。

### 第一步输入模板

```text
step: 1
analysis_mode: jadx_mcp_session/local_source
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: yes/no
```

### 第二步输入模板

```text
step: 2
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
mcp: burp/yakit/none
traffic_source: analysis_runs/current_run/traffic/traffic.json
```

### 第三步输入模板

```text
step: 3
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
mcp: ida-mcp/ghidra-mcp/none
native_analysis_source: sample_target/native/sample.i64_or_sample.gpr_or_libsample.so
```

补充说明：

- 若 `mcp = ghidra-mcp` 且希望自动导入目标 so，则应在任务开始前已确认 `ghidra_root`
- 推荐将这类本机相关参数统一写入 `analysis_state.json`，而不是在第三阶段临时补充

### 第四步输入模板

```text
step: 4
output_dir: analysis_runs/current_run
allow_reanalyze_code: yes/no
```

### 第五步输入模板

```text
step: 5
output_dir: analysis_runs/current_run
authorized_only: yes/no
```

### 第六步输入模板

```text
step: 6
output_dir: analysis_runs/current_run
target_name: 项目名称
report_type: brief/full
include_appendix: yes/no
```

## 示例对话

### 用法一：先选模式，再进入第一步

例如你先选择：

```text
run_mode: auto_chain
auto_chain_mode: B
```

然后下一条再提供：

```text
step: 1
analysis_mode: local_source
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: no
```

此时系统应理解为：

- 整个流程仍从第一步开始
- 前 1-3 阶段允许人工确认
- 从第四阶段开始自动推进到第六阶段

### 用法二：逐阶段步进模式

如果你希望每一步都人工确认，可以先提供：

```text
run_mode: step_by_step
```

然后进入第一步模板。后续只需继续说：

- `继续第二步`
- `继续第三步`
- `继续第四步`

系统应在每一阶段结束后默认挂起，等待人工复核。

### 用法三：自动链 A

如果你希望第一阶段后、从第二阶段起自动化，可以先提供：

```text
run_mode: auto_chain
auto_chain_mode: A
```

然后进入第一步模板。此时系统应：

- 先完成第一阶段
- 等人工完成抓包准备、MCP 接通和其他前置动作
- 从第二阶段开始自动推进到第六阶段

### 用法四：自动链 C

如果你一开始就已完成全部人工前置准备，可以先提供：

```text
run_mode: auto_chain
auto_chain_mode: C
```

然后进入第一步模板。此时系统应：

- 从第一阶段开始执行
- 不跳过检测分析
- 在条件满足时继续自动推进后续阶段

## 完整流程示例

下面给出一条从 Phase 1 到 Phase 6 的完整示例，目的是让使用者清楚看到：

- 每一步怎么开始
- 每一步需要补什么材料
- 每一步会沉淀什么结果
- 下一步如何消费上一步产物

### 示例背景

假设当前已有以下材料：

- 反编译目录：`sample_target/decompiled`
- 输出目录：`analysis_runs/demo_app_run`
- 抓包导出文件：`analysis_runs/demo_app_run/traffic/traffic.json`
- IDA 工程：`sample_target/native/demo_app.i64`

### Step 1：开始 APK 静态侦察

用户先说：

```text
开始第一步
```

总控先返回模板：

```text
step: 1
analysis_mode: jadx_mcp_session/local_source
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: yes/no
```

用户补齐后发送：

```text
step: 1
analysis_mode: local_source
target_dir: sample_target/decompiled
output_dir: analysis_runs/demo_app_run
jadx_mcp: no
```

本阶段默认应路由到：

- [agent-01-sample-recon.md](agents/agent-01-sample-recon.md)

本阶段结束后，至少应沉淀：

- `file_inventory.json`
- `tech_stack.json`
- `entrypoints.json`
- `env_guard_report.json`

若识别到环境对抗逻辑，还应尽量补齐：

- `frida_bypass_plan.json`
- `frida/android_phase1_bypass.js`

### Step 2：开始流量与代码对齐

用户先说：

```text
开始第二步
```

总控先返回模板：

```text
step: 2
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
mcp: burp/yakit/none
traffic_source: analysis_runs/current_run/traffic/traffic.json
```

用户补齐后发送：

```text
step: 2
target_dir: sample_target/decompiled
output_dir: analysis_runs/demo_app_run
mcp: none
traffic_source: analysis_runs/demo_app_run/traffic/traffic.json
```

本阶段默认应路由到：

- [agent-02-protocol-mapper.md](agents/agent-02-protocol-mapper.md)

本阶段结束后，至少应沉淀：

- `api_endpoints.json`
- `protocol_map.json`
- `traffic_alignment.json`

同时应尽量补齐供后续阶段直接消费的字段级结果，例如：

- `field_role`
- `builder_path`
- `crypto_entry_candidate`
- `related_endpoint_group`
- `matched_field_flows`

### Step 3：开始 SO / JNI 深度分析

用户先说：

```text
开始第三步
```

总控先返回模板：

```text
step: 3
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
mcp: ida-mcp/ghidra-mcp/none
native_analysis_source: sample_target/native/sample.i64_or_sample.gpr_or_libsample.so
```

用户补齐后发送：

```text
step: 3
target_dir: sample_target/decompiled
output_dir: analysis_runs/demo_app_run
mcp: none
native_analysis_source: sample_target/native/demo_app.i64
```

本阶段默认应路由到：

- [agent-03-crypto-native-analyzer.md](agents/agent-03-crypto-native-analyzer.md)

本阶段结束后，至少应沉淀：

- `crypto_native_analysis.json`
- `jni_analysis.json`

同时应尽量补齐：

- `java_entry`
- `native_entry`
- `crypto_algorithm_candidate`
- `key_derivation`
- `iv_derivation`
- `salt_derivation`
- `input_order`
- `output_encoding`
- `restoration_confidence`

### Step 4：开始弱加密与高风险漏洞筛查

用户先说：

```text
开始第四步
```

总控先返回模板：

```text
step: 4
output_dir: analysis_runs/current_run
allow_reanalyze_code: yes/no
```

用户补齐后发送：

```text
step: 4
output_dir: analysis_runs/demo_app_run
allow_reanalyze_code: yes
```

本阶段默认应路由到：

- [agent-04-crypto-vuln-analyzer.md](agents/agent-04-crypto-vuln-analyzer.md)

本阶段结束后，至少应沉淀：

- `vuln_analysis.json`
- `risk_matrix.json`

若材料充分，还应尽量补齐：

- `secrets_report.json`
- `jsbridge_analysis.json`

这一阶段会优先消费 Phase 2 和 Phase 3 的字段结果，而不是从零重新猜测。

### Step 5：开始最小验证 POC 设计

用户先说：

```text
开始第五步
```

总控先返回模板：

```text
step: 5
output_dir: analysis_runs/current_run
authorized_only: yes/no
```

用户补齐后发送：

```text
step: 5
output_dir: analysis_runs/demo_app_run
authorized_only: yes
```

本阶段默认应路由到：

- [agent-05-validation-designer.md](agents/agent-05-validation-designer.md)

本阶段结束后，至少应沉淀：

- `validation_cases.json`
- `test_plan.md`
- `repro_steps.md`
- `poc_scripts_index.json`

如材料充分，还应尽量补齐：

- `pocs/{vuln_id}/validate_request.py`
- `pocs/{vuln_id}/runtime_observe.js`
- `pocs/{vuln_id}/README.md`

### Step 6：开始渗透报告汇总

用户先说：

```text
开始第六步
```

总控先返回模板：

```text
step: 6
output_dir: analysis_runs/current_run
target_name: 项目名称
report_type: brief/full
include_appendix: yes/no
```

用户补齐后发送：

```text
step: 6
output_dir: analysis_runs/demo_app_run
target_name: Demo App
report_type: full
include_appendix: yes
```

本阶段默认应路由到：

- [agent-06-reporter.md](agents/agent-06-reporter.md)

本阶段结束后，至少应沉淀：

- `security_report.md`
- `findings.json`

并按材料情况尽量补齐全量附件：

- `api_endpoints_full.md`
- `secrets_full.md`
- `native_findings_full.md`

### 这条完整链路说明了什么

这套 Skills 的推进方式不是“用户一句话让 AI 自由发挥”，而是：

1. 总控先返回阶段模板
2. 用户补齐该阶段最小输入
3. 当前阶段 Agent 生成结构化产物
4. 下一阶段继续消费这些产物

因此，这个仓库更适合：

- 人驱动阶段推进
- AI 按规程执行分析
- 每一步落盘标准结果
- 最终形成完整交付链

## 标准工作流

### 第一步：先做 APK 静态侦察

输入：

- `{target_dir}`
- 或已连接 `jadx-mcp` 且目标样本已在 Jadx 中打开
- 可选：`jadx-mcp`

目标：

- 拿到 `file_inventory.json`
- 拿到 `tech_stack.json`
- 拿到 `entrypoints.json`
- 拿到 `env_guard_report.json`

### 第二步：做流量与代码对齐

输入：

- `{target_dir}`
- `{traffic_source}` 或 Burp / Yakit MCP

目标：

- 拿到 `api_endpoints.json`
- 拿到 `protocol_map.json`
- 拿到 `traffic_alignment.json`

本阶段现在会尽量补齐一组供第 4 步直接消费的字段级证据，包括：

- `field_role`
- `location`
- `builder_path`
- `crypto_entry_candidate`
- `related_endpoint_group`
- `value_shape`
- `related_native_candidate`
- `replay_relevant`
- `matched_field_flows`

### 第三步：做 SO 与 JNI 深挖

输入：

- `{native_analysis_source}` 或 so 材料
- 可选：`ida-mcp` / `ghidra-mcp`

目标：

- 拿到 `crypto_native_analysis.json`
- 拿到 `jni_analysis.json`

说明：

- Phase 3 的主路径是 `ida-mcp` / `ghidra-mcp` 直接分析 so 与 JNI
- 本地脚本只补入口和桥接线索，不承担 so 逆向主流程

本阶段现在会尽量补齐一组供第 4 步直接消费的 native 还原字段，包括：

- `java_entry`
- `native_entry`
- `related_fields`
- `related_endpoints`
- `crypto_algorithm_candidate`
- `key_derivation`
- `iv_derivation`
- `salt_derivation`
- `input_order`
- `output_encoding`
- `restoration_confidence`

### 第四步：做弱加密与高风险漏洞筛查

输入：

- 前 1-3 步结果
- `session_blackboard.json`（优先读取 CONFIRMED 级别 Fact 作为分析基线）

目标：

- 拿到 `vuln_analysis.json`
- 拿到 `risk_matrix.json`
- 尽量补齐 `secrets_report.json`
- 尽量补齐 `jsbridge_analysis.json`

第 4 步不是简单总结，而是优先消费 blackboard 中的 CONFIRMED Fact 和第 2、3 步已沉淀的字段，再完成：

- `sign/data/encryptData` 的综合还原判断
- 弱加密和签名安全评估
- 源码侧 Top10 风险审计
- 数据包侧风险联动分析

每条漏洞会被 **Guardian 验证层**评定 L1-L5 证据深度：

- L4 EXPLOITABLE：静态链路完整，Phase 5 可直接写 PoC
- L3 CONTROLLABLE：source→sink 可追踪，Phase 5 先 Frida 确认
- L2 REACHABLE：有调用链但参数来源未完全明确
- L1 PATTERN：仅代码模式匹配，暂不出 PoC

因此在 `vuln_analysis.json` 里，除了漏洞条目，还会尽量补齐：

- `crypto_findings`
- `signature_findings`
- `crypto_restoration`
- `packet_risks`
- `source_phase_2_fields`
- `source_phase_3_fields`
- `gap_filled_by_phase4`
- 每条漏洞的 `guardian_level` + `guardian_evidence`

`risk_matrix.json` 中还会新增：

- `by_guardian_level`：按证据深度分组的漏洞 ID 列表
- `phase5_priority_queue`：Phase 5 的工作队列（immediate / needs_frida_first / needs_callchain_first / defer）

### 第五步：做最小验证 POC 设计

输入：

- Phase 4 的漏洞条目和风险矩阵
- `risk_matrix.json` 中的 `phase5_priority_queue`（若存在，直接作为工作队列）

目标：

- 拿到 `validation_cases.json`
- 拿到 `test_plan.md`
- 拿到 `repro_steps.md`
- 拿到 `poc_scripts_index.json`

Phase 5 优先按 `guardian_level` 排序工作：L4 直接写 PoC，L3 先 Frida 确认参数可控性，L2 先补调用链，L1 暂缓。

如材料充足，还会尽量拿到：

- `pocs/{vuln_id}/validate_request.py`
- `pocs/{vuln_id}/runtime_observe.js`
- `pocs/{vuln_id}/README.md`

### 第六步：做渗透报告汇总

输入：

- 前 1-5 步结果

目标：

- 拿到 `security_report.md`
- 拿到 `findings.json`
- 拿到配套的全量附件

## MCP 使用方式

建议按下列方式使用：

- Phase 1：`jadx-mcp` 或本地目录分析
- Phase 2：Burp MCP / Yakit MCP
- Phase 3：`ida-mcp` / `ghidra-mcp`
- Phase 4-6：以前序结果为主，必要时回调前序 MCP

详细说明见：

- [MCP-INTEGRATION.md](docs/MCP-INTEGRATION.md)

## 脚本使用方式

脚本作为可选增强层使用。

当前可用脚本：

- [endpoint_extractor.py](tools/scripts/endpoint_extractor.py)
- [secret_scanner.py](tools/scripts/secret_scanner.py)
- [native_bridge_indexer.py](tools/scripts/native_bridge_indexer.py)
- [env_guard_indexer.py](tools/scripts/env_guard_indexer.py)
- [ai_summarizer.py](tools/scripts/ai_summarizer.py)
- [sign_rebuilder.py](tools/scripts/sign_rebuilder.py)
- [resolve_native_target.py](tools/scripts/resolve_native_target.py)
- [ghidra_target_loader.py](tools/scripts/ghidra_target_loader.py)
- [ida_target_loader.py](tools/scripts/ida_target_loader.py)

用途：

- `endpoint_extractor.py`：补接口、URL、deeplink、provider 等线索
- `secret_scanner.py`：补硬编码密钥、Token、证书、云凭证等线索
- `native_bridge_indexer.py`：补 JNI、WebView、JSBridge、Native 加载线索，不替代 `ida-mcp` / `ghidra-mcp` 的 so 分析
- `env_guard_indexer.py`：补 Root、模拟器、代理、SSL Pinning、Frida、签名校验线索
- `ai_summarizer.py`：4 个索引脚本跑完后生成压缩摘要，供 AI 优先消费
- `sign_rebuilder.py`：Phase 5 签名重算，支持 17 种算法 + pipeline 链式
- `resolve_native_target.py`：Phase 2 后收敛最值得分析的 so 目标
- `ghidra_target_loader.py`：自动导入目标 so 到 Ghidra 项目（支持 macOS / Windows）
- `ida_target_loader.py`：自动导入目标 so 到 IDA，headless 建 `.i64` 库 + 跑完 auto-analysis + 拉起 GUI 交给 `ida_pro_mcp`（与 ghidra loader 输入通用，兼容 IDA 9.x/8.x，macOS/Windows 自动定位）
- `tools/frida/android_phase1_bypass.js`：补 Phase 1 运行时绕过模板资产

详细说明见：

- [tools/scripts/README.md](tools/scripts/README.md)

## 目录结构

```text
ai-mobile-reverse-skills/
├── SKILL.md                          ← 总控：6 Phase 编排、auto_chain、质量门
├── README.md
├── USER-README.md
├── docs/
│   ├── STATE-MODEL.md               ← 状态模型文档（analysis_state + session_blackboard）
│   └── MCP-INTEGRATION.md
├── templates/
│   ├── analysis_state.template.json      ← Phase 流程状态初始化模板
│   ├── session_blackboard.template.json  ← 跨 Phase 知识积累初始化模板
│   ├── mobile-reverse-report-template.md
│   └── repro-steps-template.md
├── agents/
│   ├── agent-01-sample-recon.md
│   ├── agent-02-protocol-mapper.md
│   ├── agent-03-crypto-native-analyzer.md
│   ├── agent-04-crypto-vuln-analyzer.md  ← 含 Guardian L1-L5 验证层
│   ├── agent-05-validation-designer.md
│   └── agent-06-reporter.md
└── tools/
    ├── scripts/
    │   ├── README.md
    │   ├── endpoint_extractor.py
    │   ├── secret_scanner.py
    │   ├── native_bridge_indexer.py
    │   ├── env_guard_indexer.py
    │   ├── ai_summarizer.py
    │   ├── sign_rebuilder.py
    │   ├── resolve_native_target.py
    │   ├── ghidra_target_loader.py
    │   └── ida_target_loader.py
    ├── poc_templates/
    │   ├── frida_runtime_observe.js.tmpl
    │   └── python_http_validation.py.tmpl
    └── frida/
        ├── README.md
        ├── android_phase1_bypass.js
        └── dex_dumper_art.js
```

## Phase 2 / 3 / 4 的衔接关系

各 Phase 通过两条通道传递信息：

**通道一：结构化 JSON 文件**（原有机制）
- Phase 2 负责把抓包字段和代码构造逻辑对齐，重点吐出 `field_role`、`builder_path`、`crypto_entry_candidate`、`matched_field_flows`
- Phase 3 负责把 Java → JNI → so 的链路打通，重点吐出 `java_entry`、`native_entry`、`crypto_algorithm_candidate`、`key_derivation`、`input_order`
- Phase 4 优先消费这些字段，再综合成 `crypto_restoration`、`packet_risks`、`vulnerabilities`

**通道二：session_blackboard.json**（新增机制）
- Phase 1 发现的硬编码密钥、JNI 入口 → 写入 blackboard 作为 PATTERN Fact
- Phase 2 确认 sign 字段下沉到 native → 写 CONFIRMED Fact + 向 Phase 3 发 Intent（指定目标 so 和字段名）
- Phase 3 启动时先读 Intent → 直接从指定目标开始，不重新推导；完成后写 CONFIRMED crypto_finding Fact
- Phase 4 读 CONFIRMED Fact → 以此为基线，不退化为 unknown 重新猜测

auto_chain 模式下，总控仅对 Phase 1-3 检查新增 Fact 数；Phase 4-6 以必要产物和 `phase_gate.json` 为质量门，避免汇总阶段因不新增 Fact 被误报停滞。

因此，第 4 步承担的是综合收口职责，而不是单纯的风险列表生成职责。

## 交付产物

按照标准流程推进时，这套 Skills 会逐步沉淀以下可交付产物：

- Phase 1：`file_inventory.json`、`tech_stack.json`、`entrypoints.json`、`env_guard_report.json`、`ai_summary.json`、`phase_gate.json`、`analysis_state.json`
- Phase 2：`api_endpoints.json`、`protocol_map.json`、`traffic_alignment.json`
- Phase 3：`crypto_native_analysis.json`、`jni_analysis.json`
- Phase 4：`vuln_analysis.json`、`risk_matrix.json`
- Phase 5：`validation_cases.json`、`test_plan.md`、`repro_steps.md`、`poc_scripts_index.json` 及按漏洞拆分的 `pocs/`
- Phase 6：`security_report.md`、`findings.json` 及配套附件

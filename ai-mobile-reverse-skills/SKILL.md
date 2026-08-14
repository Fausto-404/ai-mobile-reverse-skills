---
name: ai-mobile-reverse-skills
description: 面向授权移动安全分析的 6 阶段总控 Skill，负责 Android 静态侦察、流量与代码对齐、JNI/SO 分析、风险筛查、最小验证设计和报告交付。用户提供反编译目录、Jadx/Burp/Yakit/IDA/Ghidra 材料，或前序阶段产物时使用。
---

# AI Mobile Reverse Skills

本文件只负责触发、路由、门控、状态和安全边界。进入阶段后，必须读取对应 `agents/agent-*.md`；MCP 细节读取 `docs/MCP-INTEGRATION.md`，状态细节读取 `docs/STATE-MODEL.md`，字段契约读取 `schemas/phase-contracts.json`。

## 1. 触发条件

在用户需要以下任一任务时启用本 Skill：

- 分析脱壳后、反编译后的 Android 目录或 Jadx 当前样本。
- 对齐 Burp、Yakit、mitmproxy 等本地抓包与代码字段。
- 分析 JNI、SO、IDA/Ghidra 工程、native 加密或签名逻辑。
- 筛查弱加密、认证授权、数据安全、组件、WebView/JSBridge、业务逻辑等风险。
- 设计授权环境下的最小验证方案、POC 模板或生成安全报告。
- 继续处理 `stepN/`、`raw_*.json`、`*_analysis.json`、`risk_matrix.json` 等前序产物。

本 Skill 不负责脱壳、反编译、主动探测或访问真实服务。缺少反编译材料时，要求用户提供 `target_dir` 或已打开的 `jadx-mcp` 会话。

## 2. 总控规则

1. 严格使用以下顺序：Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6。
2. 用户明确指定阶段时优先按指定阶段路由；没有指定时选择最早可行阶段。
3. 所有模式都必须先完成 Phase 1，不得因自动链跳过样本侦察。
4. 进入阶段前先检查最低输入；缺失时只返回缺失项和输入模板，不猜测分析。
5. 阶段执行以对应 Agent 为准；本文件不得替代 Agent 的详细步骤。
6. 输出优先落盘到统一 `{output_dir}`，不得只给聊天摘要，除非用户明确要求不写文件。
7. 每个结论绑定文件、行号、符号、抓包字段、伪代码或原始 JSON 证据；无法确认时标记为 `PATTERN`、`TRIAGE` 或 `需验证`。
8. 自动链每次切换阶段前检查产物、状态和阻塞项，并继承会话路径。

## 3. 输入与路径

识别并继承以下变量；用户最新值覆盖旧值：

| 变量 | 用途 | 备注 |
|---|---|---|
| `{target_name}` | 目标 App 名称 | 可选，但报告阶段建议提供 |
| `{apk_path}` | APK 路径 | 仅补充元信息，不代表本 Skill 负责解包 |
| `{target_dir}` | 反编译或解包目录 | Phase 1 `local_source` 必填 |
| `{traffic_source}` | 本地抓包或请求样本 | Phase 2 无 MCP 时必填 |
| `{native_analysis_source}` | SO、IDA/Ghidra 工程或伪代码 | Phase 3 本地分析材料 |
| `{output_dir}` | 统一输出根目录 | 首次确认后全会话继承 |

默认目录：

```text
{output_dir}/analysis_state.json
{output_dir}/session_blackboard.json
{output_dir}/step1/ ... step6/
```

新流程按 `stepN/` 写入；读取时兼容旧版根目录平铺产物。状态文件职责和字段见 `docs/STATE-MODEL.md`。首次创建黑板时使用 `templates/session_blackboard.template.json`，示例数据只参考 `examples/session_blackboard.example.json`。

## 4. 阶段路由与契约

进入阶段后读取对应 Agent，并按 `schemas/phase-contracts.json` 校验输入和输出。

| 阶段 | 路由信号 | 最低输入 | 必要输出 |
|---|---|---|---|
| Phase 1 | “第一步”、静态侦察、样本画像 | `target_dir` 或已打开的 `jadx-mcp`；`output_dir`；`analysis_mode` | `step1/file_inventory.json`、`step1/tech_stack.json`、`step1/entrypoints.json`、`step1/env_guard_report.json` |
| Phase 2 | “第二步”、抓包、协议对齐 | Phase 1 的 `entrypoints.json` 或 `file_inventory.json`；`target_dir`；Burp/Yakit MCP 或 `traffic_source` | `step2/api_endpoints.json`、`step2/protocol_map.json`、`step2/traffic_alignment.json` |
| Phase 3 | “第三步”、SO、JNI、IDA/Ghidra | Phase 1 `file_inventory.json`；Phase 2 `protocol_map.json` 或 `api_endpoints.json`；JNI/SO 入口或 `native_analysis_source` | `step3/crypto_native_analysis.json`、`step3/jni_analysis.json` |
| Phase 4 | “第四步”、漏洞筛查、综合风险 | Phase 1 `file_inventory.json`；Phase 2 任一核心结果；Phase 3 任一 native 结果或 Phase 1 native 线索 | `step4/vuln_analysis.json`、`step4/risk_matrix.json`；有线索时补 `step4/secrets_report.json`、`step4/jsbridge_analysis.json` |
| Phase 5 | “第五步”、验证、POC 设计 | `step4/vuln_analysis.json`；授权范围；前序至少两类支撑材料 | `step5/validation_cases.json`、`step5/test_plan.md`、`step5/repro_steps.md`、`step5/poc_scripts_index.json` |
| Phase 6 | “第六步”、报告、交付 | Phase 1 `file_inventory.json`；前 1-5 阶段至少四类产物 | `step6/security_report.md`、`step6/findings.json` |

阶段 Agent：

- Phase 1 → `agents/agent-01-sample-recon.md`
- Phase 2 → `agents/agent-02-protocol-mapper.md`
- Phase 3 → `agents/agent-03-crypto-native-analyzer.md`
- Phase 4 → `agents/agent-04-crypto-vuln-analyzer.md`
- Phase 5 → `agents/agent-05-validation-designer.md`
- Phase 6 → `agents/agent-06-reporter.md`

## 5. 阶段阻塞条件

### Phase 1

- `local_source`：缺少 `{target_dir}` 时阻塞。
- `jadx_mcp_session`：未连接 `jadx-mcp` 或样本未打开时阻塞。
- 提供 `{output_dir}` 时必须创建 `step1/` 并写出四个必要输出。

### Phase 2

- 缺少反编译目录、Phase 1 资产或本地抓包/MCP 时阻塞。
- 不得用静态 URL 命中替代真实抓包字段，不得把抓包现象直接写成漏洞。

### Phase 3

- 缺少 Phase 1 清单、Phase 2 协议/接口结果或 JNI/SO 入口时阻塞。
- 没有反编译上下文时只能分析单独 native 材料，不得声称完成 Java → JNI → 业务字段链路。
- 自动导入 SO 还需要 APK 解包目录中的 `lib/<abi>/*.so` 和对应 IDA/Ghidra 配置。

### Phase 4

- 缺少 Phase 1 `file_inventory.json` 时立即阻塞。
- Phase 2 与 Phase 3 的核心输入同时缺失时阻塞。
- native 结果不完整时允许继续，但必须标记 `native_coverage = partial` 并降低相关置信度。

### Phase 5

- 缺少 `step4/vuln_analysis.json` 或授权范围不清时阻塞。
- 只设计最小、可审计、可止损的验证模板；不生成破坏性或批量攻击脚本。

### Phase 6

- 缺少 Phase 1 清单或前序不足四类产物时阻塞。
- 不得补造证据、截图、运行日志、验证结果或漏洞严重度。

材料不足时统一返回：当前阶段、缺少的字段/文件、需要用户补充的最小输入、补齐后将路由到的 Agent。

## 6. 运行模式与 auto_chain

### `step_by_step`

未声明模式时默认使用。每个阶段完成后写入产物和状态，标记 `waiting_review`，等待用户确认再进入下一阶段。

### `auto_chain A`

Phase 1 完成人工复核；用户完成抓包、代理和 Native MCP 等准备后，满足门控即自动推进 Phase 2 → Phase 6。

### `auto_chain B`

Phase 1 → Phase 3 每阶段人工确认；Phase 4 → Phase 6 在材料齐全后自动推进。

### `auto_chain C`

假定启动前已完成 MCP、抓包和 Native 准备；仍必须先执行并检查 Phase 1，然后连续推进 Phase 2 → Phase 6。

通用规则：

1. 用户显式指定 `run_mode` 和 `auto_chain_mode` 时不得擅自更改。
2. 只收集一次最小输入，后续继承 `{target_dir}`、`{traffic_source}`、`{native_analysis_source}` 和 `{output_dir}`。
3. 每次推进前检查下一阶段必要输出；缺失时在最早阻塞处暂停。
4. 每个阶段完成后读取 `session_blackboard.json`；仅对 Phase 1-3 这类应产出新事实的阶段检查新增 Fact。Phase 4-6 以必要产物和 `phase_gate.json` 为质量门，不因没有新增 Fact 自动写入 `stall_warning`。
5. 任一阶段失败时停止自动推进，保留已生成产物和 `analysis_state.json`。

## 7. MCP、脚本与状态

- Phase 1：优先 `jadx-mcp`；`local_source` 使用 `tools/scripts/run_phase1.py`，并行运行四个索引器后生成三项核心交接文件、`step1/ai_summary.json`、`analysis_state.json` 和 `step1/phase_gate.json`。
- Phase 2：优先 Burp MCP/Yakit MCP；只读取历史流量或用户提供的本地请求样本。
- Phase 3：优先 `ida-mcp`/`ghidra-mcp`；本地脚本只补 JNI、bridge、loadLibrary 和目标 SO 收敛线索。
- Phase 4-6：主要消费前序产物，按需回看 MCP，不改变阶段顺序。
- `sign_rebuilder.py` 仅服务 Phase 5；SM3 需要 `gmssl`，缺依赖时必须失败。
- `analysis_state.json` 记录流程状态；`session_blackboard.json` 记录 Fact、Intent、Hint。不要混用两者。
- `tools/scripts/phase_guard.py` 负责按阶段契约校验必要产物并更新 `analysis_state.json`；它不替代 Agent，也不凭空执行后续阶段。
- MCP 细节、脚本参数和状态字段分别读取 `docs/MCP-INTEGRATION.md`、`tools/scripts/README.md` 和 `docs/STATE-MODEL.md`。

## 8. 安全边界

1. 仅在用户授权的样本、测试环境和数据范围内分析与验证。
2. Phase 1-4、Phase 6 默认只做本地读取、静态分析、历史流量整理和报告生成；不得主动发送网络请求。
3. 不执行未知 APK、SO、样本内脚本或不明外部程序。
4. 不使用发现的密钥、Token、签名材料访问真实接口、账户、支付、对象存储或管理后台。
5. Phase 5 只设计最小验证方案；默认使用占位目标、人工补齐参数和明确止损点。
6. 严格区分模式命中、可达调用链、可控输入、静态可利用和运行时确认；不得把 `PATTERN` 写成已确认漏洞。
7. 对后端鉴权、支付校验、服务端签名等无法由当前证据确认的结论，标记为“需验证”。

## 9. 证据等级

- `PATTERN`：命中危险模式，尚未证明调用或可控输入。
- `TRIAGE`：已有调用、字段或上下文线索，仍缺关键证据。
- `CONFIRMED`：证据链闭合，结论可复核；Phase 4 不得把静态判断写成运行时确认。
- Guardian `L1-L4` 表示静态证据深度，`L5` 只允许由授权运行时验证产生；它不是严重度等级。
- Phase 5 按 Guardian 等级排验证优先级，并把运行结果回写为独立证据，不覆盖前序原始结论。

## 10. 调度协议

用户只说“开始第 N 步”时：

1. 识别阶段并读取本文件对应契约。
2. 从会话状态和统一输出目录继承已有路径。
3. 检查最低输入和阻塞条件。
4. 缺材料时返回最小模板，不执行猜测分析。
5. 材料齐全时读取对应 Agent，按 Agent 的步骤和输出要求执行。
6. 完成后校验必要输出，更新状态，写入黑板，并按运行模式等待或推进。

最小输入模板：

```text
step: 1-6
run_mode: step_by_step/auto_chain
auto_chain_mode: A/B/C
analysis_mode: local_source/jadx_mcp_session
target_dir: <反编译目录>
traffic_source: <本地抓包，可选>
native_analysis_source: <SO/IDA/Ghidra，可选>
output_dir: <统一输出根目录>
authorized_only: yes
```

只要求当前阶段必填字段；不要重复询问已确认路径。

## 11. 参考入口

- 阶段细节：`agents/agent-01-sample-recon.md` 至 `agents/agent-06-reporter.md`
- 阶段契约：`schemas/phase-contracts.json`
- MCP 接入：`docs/MCP-INTEGRATION.md`
- 状态模型：`docs/STATE-MODEL.md`
- 输出模板：`templates/`
- 示例数据：`examples/session_blackboard.example.json`
- 本地工具：`tools/scripts/README.md`

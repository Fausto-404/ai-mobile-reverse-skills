# MCP 阶段接入规范

本文件不是泛泛而谈的“说明”，而是当前 6 阶段主流程的 MCP 接入规范。  
它只回答 4 个问题：

1. 每个阶段优先接什么 MCP
2. 每个阶段最低需要哪些输入
3. 每个阶段希望从 MCP 得到什么
4. MCP 与本地脚本、阶段文档如何配合

本规范面向已经具备 MCP 接入条件的使用者，重点说明“在当前阶段应如何使用 MCP”，而不是讲解 MCP 服务本身的安装步骤。

## 总体原则

### 原则 1：MCP 提供工具能力，不替代阶段结论

MCP 的作用是把工具上下文带给 AI，例如：

- Jadx 类 / 方法 / 字符串检索
- Burp / Yakit 历史流量
- IDA / Ghidra 伪代码与交叉引用

但每个阶段的分析结论仍然由当前阶段文档负责约束。

### 原则 2：默认 AI 主导分析

如果：

- MCP 已连接
- 当前阶段材料足够
- 目录规模可控

则优先直接让 AI 基于 MCP 完成阶段分析。  
不强制先跑本地脚本。

### 原则 3：脚本属于 on-demand 增强

只有在以下情况才建议跑脚本：

- 目录很大
- 需要批量穷举命中
- 需要先生成 `raw_*.json`
- 需要给后续阶段一个稳定的结构化输入

### 原则 4：不引入新的主阶段

本规范严格服从当前 6 个阶段，不新增 `Phase 0 / 1.5 / 2.5` 等额外主流程概念。

### 原则 5：`output_dir` 由阶段侧负责创建

若用户已提供 `{output_dir}` 但目录尚不存在，当前阶段应先创建该目录，再写入标准产物。

## 阶段接入矩阵

| 阶段 | 主任务 | 推荐 MCP | 是否必需 | 最低输入 | 推荐输出 |
|---|---|---|---|---|---|
| Phase 1 | APK 静态侦察 | `jadx-mcp` 或无 MCP | 否 | `jadx_mcp=yes` 或 `{target_dir}` | `file_inventory.json` `tech_stack.json` `entrypoints.json` `env_guard_report.json` `ai_summary.json`（local_source 时） |
| Phase 2 | 流量与代码对齐 | Burp MCP / Yakit MCP | 建议使用 | `{target_dir}` + Phase 1 资产 + 抓包 MCP 或 `{traffic_source}` | `api_endpoints.json` `protocol_map.json` `traffic_alignment.json` |
| Phase 3 | SO 与 JNI 深度分析 | `ida-mcp` / `ghidra-mcp` | 建议使用 | Phase 1/2 交接产物 + JNI/SO 入口材料 + native 后端 | `crypto_native_analysis.json` `jni_analysis.json` |
| Phase 4 | 风险与漏洞筛查 | 无强制 MCP | 否 | Phase 1 清单 + Phase 2 核心结果 + Phase 3 native 结果或 native 线索 | `vuln_analysis.json` `risk_matrix.json` `secrets_report.json` `jsbridge_analysis.json` |
| Phase 5 | 最小验证 POC 设计 | Burp MCP / Yakit MCP 可选 | 否 | Phase 4 结果 | `validation_cases.json` `test_plan.md` `repro_steps.md` |
| Phase 6 | 渗透报告汇总 | 无强制 MCP | 否 | 前 1-5 阶段结果 | `security_report.md` `findings.json` |

## Phase 1：APK 静态侦察接入规范

### 目标

围绕以下任务完成第一轮静态画像：

- Manifest、权限、组件
- 三方 SDK
- 硬编码信息
- 环境对抗逻辑
- sign / token / encrypt / JNI / WebView 入口

### 路径 A：使用 `jadx-mcp` 分析 Jadx 当前已打开样本

适用场景：

- 目标样本已经在 Jadx 中打开
- 希望直接通过 Jadx 视图分析 Manifest、类、方法和资源
- 需要快速做类 / 方法 / 关键词定位
- 需要快速定位 URL、加密、请求封装器、native 调用

建议最小输入：

- `{output_dir}`
- `jadx_mcp = yes`

补充说明：

- 此模式下，AI 通过 `jadx-mcp` 获取 Jadx 当前已打开样本的 Manifest、类、方法、字符串、资源和调用线索
- 若 `{output_dir}` 不存在，应先创建后再写入结果

希望从 MCP 拿到的内容：

- 类名 / 方法名 / 包名
- 关键词命中
- 调用链片段
- 可疑字符串和协议路径

推荐用户触发方式：

```text
我现在连接上了 jadx-mcp，可以使用了。
目标样本已经在 Jadx 中打开
帮我进行第一步。
```

### 路径 B：直接分析本地反编译源码或 APK 解包目录

适用场景：

- 已经拿到了脱壳后、反编译后的目录
- 或者已经拿到了 APK 解包后的源码 / 资源目录
- 更希望直接用本地目录和编辑器分析
- 不需要依赖 Jadx 在线上下文

推荐方式：

- VS Code 全局检索
- 本地文本搜索
- 当 Phase 1 走 `local_source` 时，默认执行：
  - `endpoint_extractor.py`
  - `secret_scanner.py`
  - `native_bridge_indexer.py`
  - `env_guard_indexer.py`
- 当 Phase 1 走 `jadx_mcp_session` 时，不默认执行上述 4 个脚本

说明：

- Phase 1 不强制必须接 `jadx-mcp`
- 本阶段不把“脱壳”作为职责

### Phase 1 输出要求

必须产出：

- `file_inventory.json`
- `tech_stack.json`
- `entrypoints.json`
- `env_guard_report.json`

当 Phase 1 走 `local_source` 路径时，还应产出：

- `ai_summary.json`（4 个索引脚本执行后由 `ai_summarizer.py` 生成的压缩摘要）

可选补充：

- `raw_endpoints.json`
- `raw_secrets.json`
- `raw_native_bridges.json`
- `raw_env_guards.json`
- `frida_bypass_plan.json`
- `frida/android_phase1_bypass.js`（识别到环境对抗逻辑时生成）

## Phase 2：流量与代码对齐接入规范

### 目标

把抓包数据中的：

- URL / Path
- Header / Query / Body 字段
- sign / token / data / timestamp / encryptData

映射回代码中的：

- BaseURL
- Retrofit / OkHttp
- 请求封装器
- 参数组装逻辑
- 签名和加密点

### 推荐 MCP

- Burp MCP
- Yakit MCP

### 最低输入

- `{target_dir}`
- `{output_dir}/step1/entrypoints.json` 或 `{output_dir}/step1/file_inventory.json`
- 且满足以下之一：
  - 已连接 Burp MCP
  - 已连接 Yakit MCP
  - 提供 `{traffic_source}`

### 希望从 MCP 拿到的内容

- 历史请求列表
- 请求头、参数、响应摘要
- 登录、支付、资料、上传等场景流量
- 与认证和签名相关的字段

### 推荐用户触发方式

```text
我现在连接上了 Burp MCP。
抓包结果在 analysis_runs/current_run/traffic/traffic.json
目标目录是 sample_target/decompiled
帮我进行第二步。
```

### 可选脚本增强

- `endpoint_extractor.py`
  - 用于补静态 URL、Path、deeplink、provider 线索
- `env_guard_indexer.py`
  - 用于回看代理、证书校验、抓包检测线索

### Phase 2 输出要求

必须产出：

- `api_endpoints.json`
- `protocol_map.json`
- `traffic_alignment.json`

同时建议补齐以下字段级输出，供后续综合分析阶段直接消费：

- `field_role`
- `location`
- `builder_path`
- `crypto_entry_candidate`
- `related_endpoint_group`
- `value_shape`
- `related_native_candidate`
- `replay_relevant`
- `matched_field_flows`

## Phase 3：SO 与 JNI 深度分析接入规范

### 目标

围绕以下问题做 native 深挖：

- JNI 入口在哪里
- Java 层怎么调用 native
- sign / encrypt / data / token 相关逻辑是否下沉到 so
- so 中算法、Key、IV、Salt、参数顺序是什么
- 是否存在 native 层对抗逻辑

### 推荐 MCP

- `ida-mcp`
- `ghidra-mcp`

### 最低输入

以下材料必须同时满足：

- `{output_dir}/step1/file_inventory.json`
- `{output_dir}/step2/protocol_map.json` 或 `{output_dir}/step2/api_endpoints.json`
- `{output_dir}/step1/entrypoints.json`、`{output_dir}/step1/raw_native_bridges.json`、`{native_analysis_source}` 或可直接分析的 so/JNI 伪代码至少一个

在上述材料齐全后，以下 native 后端至少具备一个即可：

- 已连接 `ida-mcp`
- 已连接 `ghidra-mcp`
- 提供 `{native_analysis_source}`

MCP 负责深入取证，不能替代 Phase 1/2 的交接产物；没有反编译上下文时只能标记 native 局部分析，不能声称完成 Java → JNI → 业务字段链路。

### 希望从 MCP 拿到的内容

- JNI 符号与入口
- 交叉引用
- 关键函数伪代码
- `RegisterNatives`、`System.loadLibrary` 关系
- 关键字符串与常量

### 推荐用户触发方式

```text
我现在连接上了 ida-mcp，可以使用了。
IDA 工程在 sample_target/native/sample.i64
帮我进行第三步。
```

或：

```text
我现在连接上了 ghidra-mcp，可以使用了。
Ghidra 工程在 sample_target/native/sample.gpr
帮我进行第三步。
```

### 可选脚本增强

- `native_bridge_indexer.py`
  - 用于补 JNI、WebView、JSBridge、桥接面线索
  - 仅作为入口补证据，不替代 `ida-mcp` / `ghidra-mcp` 的 so 分析

### Phase 3 输出要求

必须产出：

- `crypto_native_analysis.json`
- `jni_analysis.json`

同时建议补齐以下还原字段，供 Phase 4 直接消费：

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

## Phase 4：弱加密与高风险漏洞筛查接入规范

### 目标

基于前 1-3 步结果形成风险结论，包括：

- 弱加密
- 硬编码密钥
- 认证授权问题
- 数据安全问题
- 业务逻辑问题
- 组件与 Deeplink 风险

### MCP 策略

- 无强制 MCP
- 必要时可以回调：
  - `jadx-mcp`
  - `ida-mcp`
  - `ghidra-mcp`

### 最低输入

- `{output_dir}/step1/file_inventory.json`
- Phase 2 的 `protocol_map.json`、`traffic_alignment.json` 或 `api_endpoints.json` 至少一个
- Phase 3 的 `crypto_native_analysis.json`、`jni_analysis.json` 或 Phase 1 的 `raw_native_bridges.json` 至少一个

### 可选脚本增强

- `secret_scanner.py`
- `env_guard_indexer.py`

### Phase 4 输出要求

- `vuln_analysis.json`
- `risk_matrix.json`
- `secrets_report.json`（若存在 `raw_secrets.json` 或相关静态证据，应补齐）
- `jsbridge_analysis.json`（若存在 WebView / JSBridge 线索，应补齐）

建议在 `vuln_analysis.json` 中进一步固化以下结构：

- `crypto_findings`
- `signature_findings`
- `crypto_restoration`
- `packet_risks`
- `source_phase_2_fields`
- `source_phase_3_fields`
- `gap_filled_by_phase4`

## Phase 5：最小验证 POC 设计接入规范

### 目标

基于 Phase 4 结果做最小影响验证设计，包括：

- data 加解密验证
- 签名绕过验证
- 越权访问验证
- 参数篡改验证
- 未授权访问验证

### MCP 策略

- Burp MCP / Yakit MCP 可选
- 主要用于查看历史请求、回放授权测试流量和整理验证样本

### 最低输入

- `{output_dir}/step4/vuln_analysis.json`
- 已明确的授权范围
- Phase 1-4 中至少两类支撑材料；`risk_matrix.json` 可作为补充，不能替代 `vuln_analysis.json`

### 输出要求

- `validation_cases.json`
- `test_plan.md`
- `repro_steps.md`
- `poc_scripts_index.json`

如材料完整，还应尽量生成：

- `pocs/{vuln_id}/validate_request.py`
- `pocs/{vuln_id}/runtime_observe.js`
- `pocs/{vuln_id}/README.md`

## Phase 6：渗透报告汇总接入规范

### 目标

把 1-5 步产物汇总成可交付报告。

### MCP 策略

- 无强制 MCP
- 如需补证据，可回调前序 MCP，但不改变本阶段以“汇总与交付”为主的定位

### 最低输入

- `{output_dir}/step1/file_inventory.json`
- Phase 1-5 至少四类结果，且能覆盖报告中的主要结论；不足时必须标记报告为不完整

### 输出要求

- `security_report.md`
- `findings.json`
- 配套全量附件

## 可选补充 MCP

### Chrome MCP / Playwright MCP

不作为 6 阶段主流程的强制接入项，但可用于：

- 登录流程自动化
- Token 获取路径观察
- H5 页面行为联动
- 浏览器端辅助验证

### UniDbg MCP

不作为主流程必选项，但可用于：

- 静态无法还原的 native 分支
- 寄存器 / 内存 / 断点辅助判断

## MCP 与脚本层的关系

两者不是替代关系，而是分工关系：

- MCP：提供工具上下文与交互能力
- 阶段文档：规定方法论、步骤、输出要求
- 本地脚本：做高覆盖率批量命中和结构化索引

对应关系如下：

- `endpoint_extractor.py`
  - 适合补 Phase 1、Phase 2 的接口与路径线索
- `secret_scanner.py`
  - 适合补 Phase 1、Phase 4 的敏感信息线索
- `native_bridge_indexer.py`
  - 适合补 Phase 1、Phase 3 的 JNI / bridge 线索
- `env_guard_indexer.py`
  - 适合补 Phase 1 的环境对抗线索
- `ai_summarizer.py`
  - 4 个索引脚本执行后运行，生成 `ai_summary.json` 压缩摘要
- `sign_rebuilder.py`
  - Phase 5 签名重算，读取 Phase 3/4 产物生成 sign

## 推荐最小闭环

如果先做一个最小可用版，建议如下：

1. Phase 1：`jadx-mcp` 或本地目录分析
2. Phase 2：Burp MCP / Yakit MCP
3. Phase 3：`ida-mcp` / `ghidra-mcp`
4. Phase 4-6：基于前序产物完成风险判断、POC 设计和报告交付

其中，Phase 4 除主输出外，还应尽量将 `raw_secrets.json`、WebView / JSBridge 线索整理为 `secrets_report.json`、`jsbridge_analysis.json`，供 Phase 6 直接消费。

若 token 紧张、目录过大，再补本地脚本索引。

## 当前统一上下文变量

```text
{target_name}      目标 App 名称
{apk_path}         APK 文件路径，可选，仅用于补充样本元信息
{target_dir}       脱壳后、反编译后的目录
{traffic_source}   Burp / Yakit 导出结果或本地抓包整理文件
{native_analysis_source}  IDA / Ghidra 工程、so 样本或伪代码材料
{output_dir}       输出目录
```

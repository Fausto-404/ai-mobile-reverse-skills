<h1 align="center">ai-mobile-reverse-skills</h1>
<p align="center">
  <code>移动安全分析Skills</code>
</p>
<div align="center">

<p align="center">
  <a href="https://github.com/Fausto-404/ai-mobile-reverse-skills/releases">
    <img src="https://img.shields.io/github/v/release/Fausto-404/ai-mobile-reverse-skills?style=flat-square&label=release&color=blue&cacheSeconds=3600" alt="Release">
  </a>

  <a href="https://github.com/Fausto-404/ai-mobile-reverse-skills/stargazers">
    <img src="https://img.shields.io/github/stars/Fausto-404/ai-mobile-reverse-skills?style=flat-square&label=stars&color=brightgreen&cacheSeconds=3600" alt="GitHub Stars">
  </a>

  <a href="https://github.com/Fausto-404/ai-mobile-reverse-skills/network/members">
    <img src="https://img.shields.io/github/forks/Fausto-404/ai-mobile-reverse-skills?style=flat-square&label=forks&color=orange&cacheSeconds=3600" alt="GitHub Forks">
  </a>

  <a href="https://github.com/Fausto-404/ai-mobile-reverse-skills/releases">
    <img src="https://img.shields.io/github/downloads/Fausto-404/ai-mobile-reverse-skills/total?style=flat-square&label=downloads&color=success&cacheSeconds=3600" alt="Downloads">
  </a>
</p>

</div>

<p align="center">
  <strong>面向移动安全分析场景的 6 阶段总控 Skill。用于统一调度 APK 静态侦察、流量与代码对齐、SO/JNI 深度分析、加密与漏洞综合分析、验证设计与报告交付流程。支持 JADX MCP、Burp/Yakit MCP、IDA/Ghidra MCP。</strong>
</p>


## 一、适用场景

- Android APK 静态逆向与安全画像
- 反编译代码、抓包结果、接口字段之间的联动分析
- JNI / SO / native 加密、签名、风控逻辑定位
- 弱加密、认证授权、组件安全、JSBridge、敏感信息等风险分析
- 授权测试环境下的最小验证方案与 POC 设计
- 移动端渗透测试报告和结构化 Findings 交付

## 二、架构设计

主要由以下几个核心模块构成：

- 根总控 `SKILL.md`：负责阶段识别、运行模式、任务路由和执行约束
- 6 个阶段 Agent：覆盖从 APK 静态侦察到最终安全报告的完整流程
- MCP 接入规范：支持 JADX、Burp/Yakit、IDA/Ghidra 等工具联动
- 本地分析脚本：负责接口、敏感信息、JNI、环境检测、Native 目标等线索提取
- 结构化输出：各阶段通过 JSON / Markdown 产物自动向后续阶段传递分析结果

```text
ai-mobile-reverse-skills/
├── SKILL.md                                  # 总控入口
├── README.md                                 # 使用说明
├── USER-README.md                            # 快速使用说明
├── agents/                                   # 六阶段 Agent
│   ├── agent-01-sample-recon.md              # 第一阶段：APK 静态侦察
│   ├── agent-02-protocol-mapper.md           # 第二阶段：流量与代码对齐
│   ├── agent-03-crypto-native-analyzer.md    # 第三阶段：SO / JNI 深度分析
│   ├── agent-04-crypto-vuln-analyzer.md      # 第四阶段：漏洞综合分析
│   ├── agent-05-validation-designer.md       # 第五阶段：最小验证 POC 设计
│   └── agent-06-reporter.md                  # 第六阶段：安全报告汇总
├── docs/                                     # MCP 与状态说明
├── schemas/                                  # 阶段输入输出规则
├── templates/                                # 状态、报告、复现模板
└── tools/
    ├── frida/                                # Frida 辅助脚本
    ├── poc_templates/                        # POC 模板
    └── scripts/                              # 本地分析与自动化脚本
        ├── run_phase1.py                     # Phase 1 本地一键执行
        ├── endpoint_extractor.py             # 接口 / URL / 字段线索
        ├── secret_scanner.py                 # 硬编码密钥 / Token / 凭证
        ├── native_bridge_indexer.py          # JNI / JSBridge / Native 线索
        ├── env_guard_indexer.py              # Root / Frida / SSL Pinning 等检测
        ├── resolve_native_target.py          # 自动收敛目标 SO
        ├── ghidra_target_loader.py           # Ghidra 自动导入
        ├── ida_target_loader.py              # IDA 自动导入
        └── sign_rebuilder.py                 # 签名算法重建
```
<img width="1542" height="1024" alt="image" src="https://github.com/user-attachments/assets/ee33618f-7873-4460-a990-c9efa0567f46" />


## 三、如何使用这个仓库

仓库核心入口：

```text
ai-mobile-reverse-skills/SKILL.md
```

将 `ai-mobile-reverse-skills/` 放到支持 `SKILL.md` 的 Codex / AI Skill 搜索目录中，或者直接让当前 workspace 中的 AI 读取该目录。

如果只是第一次使用，建议先看：

```text
ai-mobile-reverse-skills/USER-README.md
```

正式执行时，直接告诉 AI 运行模式，然后从第一阶段开始。

例如：

```text
run_mode: step_by_step
```

然后：

```text
开始第一步
```

AI 会返回当前阶段需要填写的标准输入模板。

如果你已经有本地反编译目录，也可以直接给出：

```text
step: 1
analysis_mode: local_source
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: no
```

如果使用已经打开的 JADX MCP：

```text
step: 1
analysis_mode: jadx_mcp_session
output_dir: analysis_runs/current_run
jadx_mcp: yes
```

### 本地 Phase 1 一键分析

如果使用本地反编译目录，可以直接执行：

```bash
python ai-mobile-reverse-skills/tools/scripts/run_phase1.py \
  --target-dir sample_target/decompiled \
  --output-dir analysis_runs/current_run
```

它会自动完成 Phase 1 的基础索引与标准产物生成。

## 四、阶段流程说明

| 阶段 | Agent | 目标 | 主要输出 |
|---|---|---|---|
| Phase 1 | SampleRecon | APK 静态侦察、技术栈识别、环境检测、敏感入口与 SO 线索初筛 | `file_inventory.json`、`tech_stack.json`、`entrypoints.json`、`env_guard_report.json` |
| Phase 2 | ProtocolMapper | 将抓包请求、接口字段、签名参数和代码实现对齐 | `api_endpoints.json`、`protocol_map.json`、`traffic_alignment.json` |
| Phase 3 | CryptoNativeAnalyzer | 分析 JNI / SO / native 加密和签名逻辑 | `crypto_native_analysis.json`、`jni_analysis.json` |
| Phase 4 | CryptoVulnAnalyzer | 综合前序证据，分析弱加密与高风险漏洞 | `vuln_analysis.json`、`risk_matrix.json` |
| Phase 5 | ValidationDesigner | 在授权环境下设计最小验证方案和 POC | `validation_cases.json`、`test_plan.md`、`repro_steps.md` |
| Phase 6 | Reporter | 汇总 Phase 1-5，生成最终报告和 Findings | `security_report.md`、`findings.json` |

所有模式都从 Phase 1 开始，自动链也不会跳过第一阶段。

![阶段流程](https://i-blog.csdnimg.cn/direct/625a635a779845ea8461726b75abae9e.png)

## 五、MCP 接入说明

MCP 用于给 AI 提供真实工具上下文。

| MCP | 主要用途 | 典型阶段 |
|---|---|---|
| `jadx-mcp` | 读取 Manifest、类、方法、资源、字符串和调用链 | Phase 1、Phase 4 |
| Burp MCP / Yakit MCP | 读取抓包请求、Header、Body、响应和接口场景 | Phase 2、Phase 5 |
| `ida-mcp` / `ghidra-mcp` | 分析 SO、JNI、伪代码、交叉引用和 native 加密逻辑 | Phase 3 |

![MCP 接入](https://i-blog.csdnimg.cn/direct/2d222bef41924711b782fbac97bd80cf.png)

完整说明：

```text
ai-mobile-reverse-skills/docs/MCP-INTEGRATION.md
```

## 六、运行模式

### 6.1 逐阶段步进

适合希望人工控制每一步分析过程的场景。

```text
run_mode: step_by_step
```

特点：

- 每个阶段结束后默认暂停
- 人工检查当前结果后再继续
- 适合复杂样本或需要人工持续调整分析方向的场景

### 6.2 自动链

适合前置材料比较完整，希望系统尽量自动推进的场景。

```text
run_mode: auto_chain
auto_chain_mode: A/B/C
```

| 模式 | 自动化范围 | 适合情况 |
|---|---|---|
| A | Phase 1 人工确认，Phase 2-6 自动推进 | Phase 1 后需要人工完成代理、抓包、MCP 等准备 |
| B | Phase 1-3 人工确认，Phase 4-6 自动推进 | 前三阶段人工深挖，后续自动完成漏洞收口、验证与报告 |
| C | Phase 1-6 尽量自动推进 | 启动前已经准备好反编译目录、抓包和 MCP 环境 |

如果缺少关键输入，例如抓包结果、Native 分析环境或前序阶段产物，自动链会在对应阶段暂停并提示缺失项。
 
## 七、更新说明
### 2026/8/14 — v1.1

- **重构根 `SKILL.md`**：总控聚焦阶段路由、运行模式、状态和安全边界，阶段细节下沉，降低总控上下文占用
- **新增 `schemas/phase-contracts.json`**：将六阶段最低输入、必要输出、可选输入输出和阻塞条件改为机器可读契约
- **新增 `run_phase1.py`**：为 `local_source` 路径提供 Phase 1 确定性执行入口，并行运行四个本地索引器
- **新增 `phase1_artifact_builder.py`**：自动生成 `file_inventory.json`、`tech_stack.json`、`entrypoints.json` 等标准交接资产
- **新增 `phase_guard.py`**：检查必要产物的存在性、非空状态和 JSON 可解析性，生成 `phase_gate.json` 并维护 `analysis_state.json`
- **优化 Blackboard 初始化**：空白模板与示例数据分离，避免演示 Fact / Intent / Hint 被误当作真实分析结论
- **调整 auto_chain 质量门**：Phase 1-3 关注新增 Fact，Phase 4-6 改以必要产物与 Phase Gate 为主，减少无意义 `stall_warning`
- **修正 SM3 降级行为**：缺少 `gmssl` 时显式失败，不再错误回退为 SHA-256
- 在不改变六阶段核心分析模型的前提下，进一步增强自动化编排、阶段交接可靠性和上下文效率

### 2026/6/28 - v1.0
- 新增 `session_blackboard.json`：各阶段关键发现（密钥、native 目标、加密算法）写入共享黑板，下游阶段直接读取，无需重复推导
- 新增 Phase 2 → Phase 3 Intent 定向信号：Phase 2 将锁定的目标 so 和字段写入黑板，Phase 3 直接从指定目标开始分析
- 新增 Guardian L1-L5 证据深度标注：每条漏洞标注可利用程度（Phase 4 静态最高判到 L4 可直接出 PoC / L3 需 Frida 确认 / L2 调用链待补全；L5 为 Phase 5 运行时确认），`risk_matrix.json` 同步输出 Phase 5 优先级工作队列
- 新增 auto_chain 质量门：阶段完成后自动检查新增发现数，为零时向下游写入预警，各阶段质量可感知
- 新增 `ida_target_loader.py`：IDA 版 so 自动化拉取，与 `ghidra_target_loader.py` 输入通用，Phase 2 选定的 so 自动 headless 建库分析并拉起 IDA GUI，交给 `ida_pro_mcp` 接手；macOS/Windows 标准路径下自动定位 IDA，兼容 9.x（`ida`/`idat`）与 8.x（`ida64`/`idat64`）

### 2026/5/20 - v0.2
- 新增 `ai_summarizer.py`：4 个索引脚本执行后自动生成压缩摘要，减少 AI token 消耗
- 新增 `sign_rebuilder.py`：支持 17 种算法和 pipeline 链式组合，Phase 5 直接生成 sign 复现请求
- `ghidra_target_loader.py` 支持 macOS 和 Windows，用户需提前填写 `ghidra_root`

### 2026/4/23 - v0.1
初版发布








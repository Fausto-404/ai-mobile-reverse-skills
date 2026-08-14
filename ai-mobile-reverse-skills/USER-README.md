# AI Mobile Reverse Skills 用户快速说明
这是一套面向移动安全分析的 6 阶段工作流，用来把 APK 静态侦察、流量与代码对齐、SO / JNI 深度分析、漏洞收口、验证设计和报告交付组织成一条可逐步执行、也可自动推进的流程。

## 先记住两件事
1. 所有模式都从第一步开始，不会跳过 Phase 1。
2. 运行方式只有两类：`step_by_step` 和 `auto_chain`。

## 开始前你至少要准备什么
- 反编译目录，或已打开的 `jadx-mcp` 会话
- 一个统一的 `output_dir`
- 如果要做流量对齐：
  - 已准备好的抓包结果，或已接通 `burp-mcp` / `yakit-mcp`
- 如果要做 Ghidra 自动导入：
  - 已提前确认 `ghidra_root`
  - 已具备 APK 解包源码目录，并且目录中存在 `lib/<abi>/*.so`

## 第一步：先选模式
逐阶段步进模式：
```text
run_mode: step_by_step
```
适合每一步都想人工复核、想随时停下来调整分析重点的场景。

自动链模式：
```text
run_mode: auto_chain
auto_chain_mode: A/B/C
```
含义：
- `A`：第一阶段后人工准备抓包和 MCP，第二阶段起自动推进到第六阶段
- `B`：前 1-3 阶段人工确认，第四阶段起自动推进到第六阶段
- `C`：从第一阶段开始尽量全流程自动推进，适合前置准备已完成的场景

## 第二步：再进入第一阶段
无论哪种模式，后面都先发第一步模板：
```text
step: 1
analysis_mode: local_source/jadx_mcp_session
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: yes/no
```
参数说明：
- `analysis_mode`
  - `local_source`：分析本地反编译目录
  - `jadx_mcp_session`：直接消费 `jadx-mcp` 当前会话
- `target_dir`：反编译后的主分析目录
- `output_dir`：统一输出目录，后续阶段默认继承
- `jadx_mcp`：当前是否已接好 `jadx-mcp`

## 典型启动顺序
最常见的启动方式是两段式：

1. 先发模式：
```text
run_mode: step_by_step
```
或：
```text
run_mode: auto_chain
auto_chain_mode: A/B/C
```

2. 再发第一步模板：
```text
step: 1
analysis_mode: local_source/jadx_mcp_session
target_dir: sample_target/decompiled
output_dir: analysis_runs/current_run
jadx_mcp: yes/no
```

这样系统就能知道：
- 你想怎么跑
- 从哪里读材料
- 结果往哪里写

## 这 6 个阶段分别做什么
1. `Phase 1`：APK 静态侦察、技术栈识别、环境检测、可疑 so 初筛
2. `Phase 2`：流量与代码对齐，收敛关键字段和目标 so
3. `Phase 3`：SO / JNI 深度分析，具备 APK 解包源码时可自动拉取 so 并导入 Ghidra
4. `Phase 4`：加密链路与高风险问题综合收口
5. `Phase 5`：最小验证思路与 POC 模板设计
6. `Phase 6`：汇总结果并生成标准化报告

## 结果写到哪里
默认写到：
```text
{output_dir}/
├── step1/
├── step2/
├── step3/
├── step4/
├── step5/
└── step6/
```
另外会有：
```text
{output_dir}/analysis_state.json
```
它不是分析结果文件，而是流程状态文件，用来记录：
- 当前运行模式
- 当前做到第几步
- 哪一步已完成
- 哪一步等待确认
- 哪一步被阻塞

如果后面中断了，通常也是先看它，再决定从哪一步继续。

## 脚本什么时候会自动用到
Phase 1 如果是：
```text
analysis_mode: local_source
```
默认会执行这 4 个脚本：
- `endpoint_extractor.py`
- `secret_scanner.py`
- `native_bridge_indexer.py`
- `env_guard_indexer.py`

Phase 1 如果是：
```text
analysis_mode: jadx_mcp_session
```
则不默认执行这 4 个脚本，优先直接使用 `jadx-mcp` 上下文。

Phase 2 / 3 还会自动用到：
- `resolve_native_target.py`
  - 第二阶段后用于收敛第三阶段优先分析的 so
- `ghidra_target_loader.py`
  - 第三阶段用于自动导入目标 so 到 Ghidra
- `ida_target_loader.py`
  - 第三阶段用于自动导入目标 so 到 IDA（与 ghidra loader 二选一，输入通用）

换句话说：
- 前 4 个脚本主要服务本地代码分析
- 后 3 个脚本主要服务 Native 自动推进

## 如果要自动导入 Ghidra
SO 自动化依赖两类材料：
- 反编译代码上下文，用来判断为什么要分析某个 so
- APK 解包源码目录，用来从 `lib/<abi>/*.so` 中自动拉取目标 so

如果只有反编译目录，没有 APK 解包源码目录，系统可以收敛候选 so 名称，但不能自动化拉取 so。用户显式提供的 `.so` 可以作为 native 分析材料使用，但不属于”自动化拉取 so”。

首次使用前，只需要提前确认一个参数：
```text
ghidra_root
```
它是你本机 Ghidra 安装根目录。支持 macOS 和 Windows。

**查找 Ghidra 安装路径的命令：**

macOS：
```bash
# 如果装在 /Applications（默认位置，大部分情况不用手动配）
ls /Applications/Ghidra.app/Contents/MacOS

# 如果不确定装在哪
mdfind -name “ghidraRun” 2>/dev/null | head -5
```

Windows（PowerShell）：
```bash
# 常见安装位置
dir “C:\Program Files\ghidra*” /s /b 2>$null | findstr “ghidraRun.bat”
dir “%USERPROFILE%\ghidra*” /s /b 2>$null | findstr “ghidraRun.bat”
dir “%USERPROFILE%\Desktop\ghidra*” /s /b 2>$null | findstr “ghidraRun.bat”
dir “%USERPROFILE%\Downloads\ghidra*” /s /b 2>$null | findstr “ghidraRun.bat”

# 或者全局搜索
where /r C:\ ghidraRun.bat 2>$null
```

拿到路径后，取 `ghidraRun` / `ghidraRun.bat` 所在的目录，填到 `analysis_state.json` 的 `native_runtime.ghidra_root` 字段：

```json
{
  "native_runtime": {
    "ghidra_root": "/Applications/Ghidra.app",
    "ghidra_project_dir": "",
    "ghidra_project_name": ""
  }
}
```

macOS 填：
```json
"ghidra_root": "/Applications/Ghidra.app"
```

Windows 填：
```json
"ghidra_root": "C:\\Users\\xxx\\ghidra_11.0_PUBLIC"
```

`ghidra_project_dir` 和 `ghidra_project_name` 留空即可，系统会自动推导。
填好之后，Phase 3 就能自动拉取 so 并导入 Ghidra，不需要再手动操作。

## 自动链什么时候会停
即使你选了 `auto_chain`，系统也不会在缺关键条件时硬往下跑。常见暂停点包括：
- 抓包材料不存在，且 `burp-mcp` / `yakit-mcp` 不可用
- 第三阶段需要 Ghidra 自动导入，但 `ghidra_root` 没配置
- 前序阶段关键结果没生成，例如缺少目标 so 收敛结果

这时通常会写状态、提示缺什么，然后停在当前最早阻塞阶段。

## 最常见的 3 种用法
用法 1：一步一步来
```text
run_mode: step_by_step
```
然后发第一步模板。

用法 2：前面人工分析，后面自动收口
```text
run_mode: auto_chain
auto_chain_mode: B
```
然后发第一步模板。前 1-3 步人工确认，第四步后自动继续。

用法 3：准备都做完了，尽量自动跑
```text
run_mode: auto_chain
auto_chain_mode: C
```
然后发第一步模板。系统会从第一步开始尽量连续推进。

## 卡住了先看哪里
优先看：
- `{output_dir}/analysis_state.json`
- 当前阶段目录下的 JSON / MD 文件

如果你需要完整规则，再看：
- `README.md`
- `SKILL.md`
- `docs/STATE-MODEL.md`

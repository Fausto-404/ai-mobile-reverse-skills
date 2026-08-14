# Scripts Layer

本目录放置的是服务当前 6 个阶段主流程的本地脚本工具，不单独构成新阶段。

这些脚本与配套模板的职责是：
- 对反编译目录做批量扫描
- 生成结构化原始命中结果
- 为 Phase 1、Phase 2、Phase 3、Phase 4 提供辅助输入
- 可选读取 `file_inventory.json`，优先按资产清单扫描

当前默认规则：
- 当 Phase 1 使用 `local_source` 时，默认执行 4 个索引脚本，随后生成核心交接产物并校验阶段门
- 当 Phase 1 使用 `jadx_mcp_session` 时，不默认执行前 4 个索引脚本
- `resolve_native_target.py`、`ghidra_target_loader.py` 与 `ida_target_loader.py` 保持原有自动化逻辑

Python 脚本只负责“扫描和索引”，不直接输出最终漏洞结论。  
Frida 模板负责为授权环境下的运行时绕过提供基础资产，不替代具体目标的定向分析。
对于 Phase 3，脚本层只负责补 JNI / bridge / loadLibrary 线索；so 逆向分析主路径应使用 `ida-mcp` 或 `ghidra-mcp`。

## 当前脚本

### 1. endpoint_extractor.py

作用：
- 提取 URL、Path、BaseURL、Retrofit 注解、请求封装器、WebSocket、上传下载相关线索
- 同时提取 `sign`、`data`、`encryptData`、`timestamp`、`nonce`、`salt`、`iv`、`hmac` 等字段名痕迹
- 同时标记 `Cipher`、`MessageDigest`、`Mac`、`Signature`、`CryptoJS`、`JSEncrypt`、`SM2/3/4` 等加密包装器线索

主要服务阶段：
- Phase 1：APK 静态侦察
- Phase 2：流量与代码对齐

输出：
- `raw_endpoints.json`

### 2. secret_scanner.py

作用：
- 提取硬编码密钥、API Key、Token、证书材料、测试环境 URL、内网 IP、调试标记
- 补充识别 HMAC key、AES / DES / SM4 key、IV、Salt、nonce、AndroidKeyStore alias、公私钥命名变量等加密材料

主要服务阶段：
- Phase 1：APK 静态侦察
- Phase 4：弱加密与高风险漏洞筛查

输出：
- `raw_secrets.json`

### 3. native_bridge_indexer.py

作用：
- 提取 `System.loadLibrary`
- 提取 `native` 方法声明
- 提取 JNI 符号、`RegisterNatives`
- 提取 `addJavascriptInterface`、`evaluateJavascript`、`loadUrl("javascript:")`
- 额外识别 OpenSSL / EVP / AES / RSA / HMAC / SHA / MD5 / SM2 / SM3 / SM4 等 native 加密符号和库痕迹

主要服务阶段：
- Phase 1：APK 静态侦察
- Phase 3：SO 与 JNI 深度分析的前置线索补充

输出：
- `raw_native_bridges.json`

### 4. env_guard_indexer.py

作用：
- 提取 Root 检测、模拟器检测、代理 / VPN 检测、SSL Pinning、Frida / 调试检测、签名校验、多开检测等环境对抗线索

主要服务阶段：
- Phase 1：APK 静态侦察
- Phase 2：流量与代码对齐（前置准备参考）

输出：
- `raw_env_guards.json`
- `env_guard_report.json`
- `frida_bypass_plan.json`
- `frida/android_phase1_bypass.js`

### 5. ghidra_target_loader.py

作用：
- 基于 APK 解包源码目录中的 `lib/<abi>/*.so` 和 `selected_native_target.json` 定位目标 so
- 自动解析当前应优先分析的 so
- 通过 `analyzeHeadless` 将该 so 导入指定 Ghidra 项目
- 尝试拉起或切到 Ghidra GUI，并打开对应项目
- 生成 `ghidra_loader_result.json`，供 Phase 3 继续消费

主要服务阶段：
- Phase 3：SO 与 JNI 深度分析

说明：
- 该脚本负责“找目标 so + 导入 Ghidra 项目 + 尽量拉起 GUI”
- `ghidra_root` 需用户通过 `--ghidra-root` 或 `GHIDRA_INSTALL_DIR` 提供
- 它不保证 Ghidra GUI 一定自动把焦点切到对应 program 标签页
- GUI 的最终焦点行为依赖本机 Ghidra 版本、操作系统和当前工作区状态

输出：
- `ghidra_loader_result.json`

### 5b. ida_target_loader.py

作用：
- `ghidra_target_loader.py` 的 IDA 对应版，**输入完全通用**（同一份 `selected_native_target.json`）
- 基于 APK 解包源码目录中的 `lib/<abi>/*.so` 和 `selected_native_target.json` 定位目标 so
- 通过 `idat` headless（`-A -o<db> -S<quit_script>`）创建 `.i64` 数据库并跑完 auto-analysis
- 尝试拉起或切到 IDA GUI，并打开生成的数据库
- 生成 `ida_loader_result.json`，供 Phase 3 / `ida_pro_mcp` 继续消费

主要服务阶段：
- Phase 3：SO 与 JNI 深度分析（使用 `ida_pro_mcp` 时）

说明：
- 该脚本负责“找目标 so + headless 建库分析 + 尽量拉起 GUI”
- `ida_root` 通过 `--ida-root` 或 `IDA_DIR` / `IDADIR` 提供；macOS（`/Applications/IDA*.app`）与 Windows（`Program Files\IDA*`）标准安装路径下可自动探测
- 兼容 IDA 9.x 统一二进制（`ida`/`idat`）与 8.x 及更早（`ida64`/`idat64`）
- `--noanalysis` 可跳过 headless 建库，直接用 GUI 打开 so；`--overwrite` 覆盖已有数据库
- MCP 驱动分析需 IDA 内已安装 `ida_pro_mcp` 插件

输出：
- `ida_loader_result.json`

### 6. resolve_native_target.py

作用：
- 读取 Phase 1 / Phase 2 产物
- 自动收敛当前最值得进入 Phase 3 分析的 so 文件
- 生成候选列表和最终选择结果
- 为 `ghidra_target_loader.py` / `ida_target_loader.py` 提供稳定输入（两者输入通用）

主要服务阶段：
- Phase 2：流量与代码对齐结束后的 native 目标收敛
- Phase 3：SO 与 JNI 深度分析前置准备

输出：
- `native_target_candidates.json`
- `selected_native_target.json`

### 7. ai_summarizer.py

作用：
- 读取 Phase 1 的 4 个 `raw_*.json` 输出
- 生成压缩后的 AI 友好摘要，作为 AI 消费的入口层
- 去重、按优先级排序、提取 top-N 条目
- 跨数据源关联分析（如 SSL Pinning + 加密字段、Java/Native 加密链路等）
- 输出 `quick_overview` 概览，让 AI 在读详细数据前先掌握全局

主要服务阶段：
- Phase 1：APK 静态侦察（4 个索引脚本执行后运行）
- 为后续所有阶段提供压缩后的结构化输入

输出：
- `ai_summary.json`

设计原则：
- 不替代 raw 数据，而是做 top-N 压缩 + 跨源关联
- AI 优先读 `ai_summary.json`，仅在需要深入时回溯 `raw_*.json`
- 每个压缩条目都保留 `source` 和 `line`，可直接定位到原始代码

### 8. phase1_artifact_builder.py

作用：
- 根据目标目录和 4 个 `raw_*.json` 结果生成 `file_inventory.json`、`tech_stack.json`、`entrypoints.json`
- 生成确定性的最低基线，供 Phase 2/3/4 继续消费；Phase 1 Agent 可在此基础上补充语义证据

主要服务阶段：
- Phase 1：本地目录模式的核心交接产物生成

输出：
- `file_inventory.json`
- `tech_stack.json`
- `entrypoints.json`

### 9. phase_guard.py

作用：
- 按 `schemas/phase-contracts.json` 检查当前阶段必要产物是否存在、非空且 JSON 可解析
- 写入 `{output_dir}/stepN/phase_gate.json` 和 `{output_dir}/analysis_state.json`

说明：
- 只负责阶段门和状态维护，不代替 Agent 执行分析，也不自动发起网络请求
- `--status completed` 但产物不完整时返回失败；`blocked`/`failed` 用于记录阻塞或执行失败

### 10. sign_rebuilder.py

作用：
- 读取 Phase 3/4 还原出的算法、Key、IV、字段顺序
- 根据 sign config 重算请求签名
- 支持 17 种算法：md5/sha1/sha256/sha512/sm3、hmac 系列、AES/DES/SM4 对称加密、RSA/ECDSA 非对称签名
- 支持 pipeline 链式操作（如 md5 → base64）
- 支持从 `vuln_analysis.json` / `crypto_native_analysis.json` 自动生成 config

主要服务阶段：
- Phase 5：最小验证 POC 设计（签名绕过验证）

输出：
- 返回 sign 值，可直接用于 POC 脚本的 `maybe_rebuild_signature()`

## 配套 Frida 模板

目录：

- `../frida/android_phase1_bypass.js`

作用：

- 为 Phase 1 识别到的 Root / 模拟器 / 代理 / SSL Pinning 检测提供最小可改造绕过模板
- 为 Phase 2 的抓包前置准备提供基础 hook 资产

说明：

- 模板默认面向授权环境
- 应结合 `raw_env_guards.json` 与 `entrypoints.json` 做裁剪，而不是无差别照搬

## 统一使用方式

默认传入的是统一输出根目录，脚本会自行写入对应阶段目录：

- Phase 1 脚本写入 `{output_dir}/step1/`
- `resolve_native_target.py` 写入 `{output_dir}/step2/`
- `ghidra_target_loader.py` / `ida_target_loader.py` 写入 `{output_dir}/step3/`
- 读取旧版 `{output_dir}/<artifact>` 平铺结果时仅作为兼容兜底

示例：

```bash
# 推荐入口：并行运行 4 个索引脚本，完成后自动生成 AI 摘要
python3 run_phase1.py --target-dir sample_target/decompiled --output-dir analysis_runs/current_run

# 需要单独重跑某个索引器时，再直接调用对应脚本
python3 endpoint_extractor.py --target-dir sample_target/decompiled --output-dir analysis_runs/current_run
python3 resolve_native_target.py --output-dir analysis_runs/current_run --target-dir sample_target/decompiled
# 二选一：用 Ghidra 拉取
python3 ghidra_target_loader.py --output-dir analysis_runs/current_run --target-dir sample_target/apk_unpacked --project-dir analysis_runs/current_run/ghidra_projects --project-name sample_project --ghidra-root sample_tools/Ghidra/ghidra_x.y.z_PUBLIC
# 或：用 IDA 拉取（macOS/Windows 标准路径下 --ida-root 可省略）
python3 ida_target_loader.py --output-dir analysis_runs/current_run --target-dir sample_target/apk_unpacked --ida-root "/Applications/IDA Professional 9.3.app"
```

`sign_rebuilder.py` 的 SM3 实现依赖 `gmssl`。缺少该依赖时会明确报错，不会用 SHA-256 伪装成 SM3。

如果已经有 `file_inventory.json`，也可以这样用：

```bash
python3 run_phase1.py \
  --target-dir sample_target/decompiled \
  --output-dir analysis_runs/current_run \
  --inventory analysis_runs/current_run/step1/file_inventory.json
```

`ai_summarizer.py` 的 `--top-n` 参数控制每个类别保留的最大条目数（默认 25）：

```bash
python3 ai_summarizer.py --output-dir analysis_runs/current_run --top-n 30
```

## 设计原则

- 纯本地执行
- 优先使用标准库
- 先保证覆盖率，再交给 Agent 做语义分析
- 输出统一 JSON，方便被后续阶段消费

## Sample Output Schema

以下结构不是完整字段表，而是后续 Agent 消费时应重点依赖的最小公共字段。

### raw_endpoints.json

```json
{
  "scan_meta": {
    "tool": "endpoint_extractor.py",
    "target_dir": "sample_target/decompiled",
    "file_source": "inventory|walk"
  },
  "type_statistics": {
    "full_url": 10,
    "retrofit_annotation": 6,
    "crypto_field_key": 4,
    "crypto_wrapper_hint": 3
  },
  "base_url_candidates": [
    {
      "value": "https://api.example.com",
      "source_file": "smali/.../Api.smali",
      "source_line": 42,
      "reason": "base_url"
    }
  ],
  "by_file": {
    "smali/.../Api.smali": {
      "hit_count": 3,
      "hits": [
        {
          "type": "retrofit_annotation",
          "value": "POST /auth/login",
          "line": 42,
          "context": "..."
        },
        {
          "type": "crypto_field_key",
          "value": "sign",
          "line": 57,
          "context": "..."
        }
      ]
    }
  },
  "all_hits": []
}
```

### raw_secrets.json

```json
{
  "scan_meta": {
    "tool": "secret_scanner.py",
    "target_dir": "sample_target/decompiled",
    "scan_rules_count": 40
  },
  "severity_statistics": {
    "Critical": 3,
    "High": 8
  },
  "category_statistics": {
    "secret": 2,
    "cloud_key": 1,
    "crypto_material": 3
  },
  "by_file": {
    "assets/config.json": {
      "hit_count": 2,
      "hits": [
        {
          "category": "crypto_material",
          "sub_type": "hmac_key_assignment",
          "severity": "Critical",
          "value": "abcd1234...",
          "masked_value": "abcd...1234",
          "line": 10,
          "confidence": "high",
          "is_placeholder": false,
          "context": "..."
        }
      ]
    }
  },
  "all_hits": []
}
```

### raw_native_bridges.json

```json
{
  "scan_meta": {
    "tool": "native_bridge_indexer.py",
    "target_dir": "sample_target/decompiled"
  },
  "type_statistics": {
    "load_library": 2,
    "native_method": 5,
    "native_crypto_symbol": 4,
    "java_crypto_bridge": 3
  },
  "libraries": [
    {
      "library": "native-lib",
      "occurrences": [
        {
          "source_file": "smali/.../MainActivity.smali",
          "source_line": 18,
          "type": "load_library"
        }
      ]
    }
  ],
  "by_file": {
    "smali/.../Bridge.smali": {
      "hit_count": 4,
      "hits": [
        {
          "type": "add_javascript_interface",
          "value": "appBridge",
          "line": 66,
          "context": "..."
        },
        {
          "type": "native_crypto_symbol",
          "value": "EVP_EncryptInit_ex(ctx, ...)",
          "line": 91,
          "context": "..."
        }
      ]
    }
  },
  "all_hits": []
}
```

### raw_env_guards.json

```json
{
  "scan_meta": {
    "tool": "env_guard_indexer.py",
    "target_dir": "sample_target/decompiled"
  },
  "guard_statistics": {
    "root_detection": 4,
    "ssl_pinning_or_cert_check": 3
  },
  "by_file": {
    "smali/.../SecurityCheck.smali": {
      "hit_count": 3,
      "hits": [
        {
          "guard_type": "root_detection",
          "match": "RootBeer",
          "line": 21,
          "pattern": "RootBeer",
          "bypass_hint": "...",
          "context": "..."
        }
      ]
    }
  },
  "all_hits": []
}
```

## Agent Consumption Notes

**推荐消费路径**（AI 优先读摘要，仅在需要深入时回溯原始数据）：

- Phase 1 优先读：
  - `ai_summary.json`（压缩摘要，包含跨源关联信号）
  - 需要深入时回溯 `raw_*.json`
- Phase 2 重点消费：
  - `ai_summary.json` → `endpoints` 和 `env_guards` 部分
  - 需要完整接口列表时回溯 `raw_endpoints.json`
- Phase 3 重点消费：
  - `ai_summary.json` → `native_bridges` 部分
  - 需要完整 JNI 符号时回溯 `raw_native_bridges.json`
- Phase 4 重点消费：
  - `ai_summary.json` → `secrets` 和 `cross_source_signals` 部分
  - 需要完整密钥列表时回溯 `raw_secrets.json`

`ai_summary.json` 中每个压缩条目都保留了 `source`（文件路径）和 `line`（行号），可直接定位到原始代码。`full_data` 字段指向对应的完整 `raw_*.json` 文件。

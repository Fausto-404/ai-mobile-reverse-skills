# Frida Assets

本目录放置服务 Phase 1 / Phase 2 的 Frida 模板资产。

这些文件的定位不是“一键通杀脚本”，而是：

- 根据 Phase 1 识别到的环境对抗逻辑，快速生成最小可改造模板
- 为授权环境下的 Root / 模拟器 / 代理 / SSL Pinning 绕过提供通用基础
- 为 Phase 2 抓包前置准备提供可复用脚本骨架

## 当前模板

### android_phase1_bypass.js

作用：

- 绕过常见 Root 检测
- 绕过常见模拟器检测
- 屏蔽常见代理 / 抓包环境探测
- 绕过常见 SSL Pinning / 证书校验实现

适用场景：

- 已完成 Phase 1 静态侦察
- 已定位到会阻塞抓包或运行时观察的环境检测
- 需要在授权环境中进行最小化绕过验证

使用建议：

- 优先结合 `raw_env_guards.json`、`entrypoints.json`、`frida_bypass_plan.json` 定位命中点后再裁剪脚本
- 不要把模板原样视为所有目标都适用
- 若目标已命中自定义检测逻辑，应基于具体类名、方法名、字符串再补定向 hook

说明：

- 这里的 `android_phase1_bypass.js` 是基础模板
- 实际项目应由 Phase 1 根据检测命中生成一份项目定制版模板，默认输出到 `{output_dir}/frida/android_phase1_bypass.js`
- 生成后的脚本会在文件头写明启用了哪些模块、依据哪些命中生成

示例：

```bash
frida -U -f com.example.app -l tools/frida/android_phase1_bypass.js
frida -U -n com.example.app -l tools/frida/android_phase1_bypass.js
```

## 配套产物建议

当 Phase 1 识别到环境对抗逻辑时，建议同时产出：

- `raw_env_guards.json`
- `env_guard_report.json`
- `frida_bypass_plan.json`
- `frida/android_phase1_bypass.js`

其中：

- `env_guard_report.json` 负责沉淀命中点、影响面、建议优先级
- `frida_bypass_plan.json` 负责把命中点映射到 Frida hook 计划

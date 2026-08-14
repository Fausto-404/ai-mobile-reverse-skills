# POC Templates

该目录提供 Phase 5 可复用的最小 POC 脚本模板。

设计原则：
- 仅面向授权测试环境
- 默认使用占位 URL、占位 token、占位业务参数
- 不内嵌真实生产目标或真实敏感值
- 以“验证存在性”为目标，而不是扩大影响

推荐使用方式：
- `python_http_validation.py.tmpl`
  - 用于未授权访问、越权访问、参数篡改、签名绕过等基于 HTTP 请求的最小验证
- `frida_runtime_observe.js.tmpl`
  - 用于仍需运行时确认输入、输出、Key、IV、参数顺序的观察型脚本
- `CASE_README.md.tmpl`
  - 用于为每个漏洞目录补充运行说明、止损点和手工补齐项

推荐输出目录：
- `pocs/{vuln_id}/validate_request.py`
- `pocs/{vuln_id}/runtime_observe.js`
- `pocs/{vuln_id}/README.md`

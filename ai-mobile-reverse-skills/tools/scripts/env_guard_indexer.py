#!/usr/bin/env python3
"""Index environment-detection and anti-analysis clues from a decompiled mobile app tree."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TEXT_SUFFIXES = {".java",".kt",".kts",".smali",".xml",".json",".txt",".properties",".yml",".yaml",".js",".c",".cc",".cpp",".h",".hpp",}

EXCLUDE_DIRS = {"node_modules", ".git", "__pycache__", ".idea", "build", "dist", "out"}

GUARD_RULES = {
    "root_detection": [
        r"\bsu\b",
        r"magisk",
        r"zygisk",
        r"riru",
        r"KernelSU",
        r"rootcloak",
        r"busybox",
        r"test-keys",
        r"RootBeer",
        r"isDeviceRooted",
        r"Superuser\.apk",
        r"/system/xbin/su",
        r"/system/bin/su",
    ],
    "emulator_detection": [
        r"goldfish",
        r"ranchu",
        r"ro\.kernel\.qemu",
        r"sdk_gphone",
        r"Genymotion",
        r"generic_x86",
        r"isEmulator",
        r"Build\.FINGERPRINT",
        r"Build\.MODEL",
        r"Build\.MANUFACTURER",
        r"Build\.PRODUCT",
        r"Build\.HARDWARE",
    ],
    "proxy_or_vpn_detection": [
        r"http\.proxyHost",
        r"http\.proxyPort",
        r"ProxySelector",
        r"VpnService",
        r"tun0",
        r"ppp0",
        r"isVpnUsed",
        r"burp",
        r"charles",
        r"mitmproxy",
        r"ProxyInfo",
        r"NetworkCapabilities",
        r"WifiConfiguration",
        r"connectivityManager",
    ],
    "ssl_pinning_or_cert_check": [
        r"CertificatePinner",
        r"checkServerTrusted",
        r"X509TrustManager",
        r"HostnameVerifier",
        r"pinSha256",
        r"SSLSocketFactory",
        r"sslPinning",
        r"OkHostnameVerifier",
        r"TrustManagerFactory",
        r"network_security_config",
        r"PinningTrustManager",
    ],
    "frida_or_debug_detection": [
        r"frida",
        r"xposed",
        r"lsposed",
        r"edxposed",
        r"substrate",
        r"sandhook",
        r"TracerPid",
        r"ptrace",
        r"isDebuggerConnected",
        r"/proc/self/maps",
        r"gdbserver",
        r"android\.os\.Debug",
        r"Debug\.waitForDebugger",
        r"ro\.debuggable",
        r"ro\.secure",
        r"debuggerd",
        r"anti[_-]?debug",
    ],
    "signature_check": [
        r"SigningInfo",
        r"GET_SIGNATURES",
        r"getPackageInfo",
        r"Signature",
        r"certificate",
        r"sha256",
        r"sha1",
        r"PackageManager",
        r"getPackageArchiveInfo",
        r"signatures\[",
    ],
    "integrity_or_attestation": [
        r"SafetyNet",
        r"PlayIntegrity",
        r"IntegrityManager",
        r"MEETS_DEVICE_INTEGRITY",
        r"MEETS_BASIC_INTEGRITY",
        r"attestation",
        r"DeviceIntegrity",
        r"AppIntegrity",
    ],
    "multi_open_detection": [
        r"dualapp",
        r"parallel",
        r"virtualapp",
        r"multiopen",
        r"clone",
        r"isParallel",
        r"VirtualApp",
        r"DualApp",
    ],
    "anti_tamper_or_packer": [
        r"libjiagu",
        r"secneo",
        r"shell[_-]?app",
        r"packer",
        r"dex2oat",
        r"classloader",
        r"PathClassLoader",
        r"DexClassLoader",
        r"InMemoryDexClassLoader",
    ],
}

COMPILED_RULES = {
    guard_type: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for guard_type, patterns in GUARD_RULES.items()
}

BYPASS_HINTS = {
    "root_detection": "关注 su / Magisk / test-keys / RootBeer 等分支，可在运行时绕过对应检查点。",
    "emulator_detection": "关注 Build、ro.kernel.qemu、设备型号与硬件信息判断，可在运行时伪造环境特征。",
    "proxy_or_vpn_detection": "关注代理配置、VPN 接口名和 Burp/Charles 字符串判断，可在运行时屏蔽命中分支。",
    "ssl_pinning_or_cert_check": "关注 CertificatePinner、TrustManager、HostnameVerifier 实现，可在运行时替换校验逻辑。",
    "frida_or_debug_detection": "关注 ptrace、TracerPid、maps、frida/xposed 关键字，优先定位检测入口再继续调试。",
    "signature_check": "关注签名摘要和包信息校验位置，抓包或重打包前需确认是否会触发。",
    "integrity_or_attestation": "关注 SafetyNet、PlayIntegrity 和 attestation 调用点，后续自动化测试前需确认是否会拦截环境。",
    "multi_open_detection": "关注双开、虚拟容器、克隆环境判断逻辑，后续测试环境需避免误触发。",
    "anti_tamper_or_packer": "关注加固、动态加载和类加载链路，结合 Phase 1 的样本画像判断是否存在壳或运行时装载。",
}

GUARD_METADATA = {
    "root_detection": {
        "severity": "High",
        "priority": 90,
        "phase2_blocking": True,
        "hook_strategy": "root_bypass",
        "impact": "可能阻塞启动、登录、抓包或运行时调试。",
    },
    "emulator_detection": {
        "severity": "High",
        "priority": 85,
        "phase2_blocking": True,
        "hook_strategy": "emulator_bypass",
        "impact": "可能导致测试环境被拒绝或关键流程不可达。",
    },
    "proxy_or_vpn_detection": {
        "severity": "High",
        "priority": 88,
        "phase2_blocking": True,
        "hook_strategy": "proxy_bypass",
        "impact": "可能阻塞代理抓包、Burp/Yakit 联动或联网请求。",
    },
    "ssl_pinning_or_cert_check": {
        "severity": "Critical",
        "priority": 95,
        "phase2_blocking": True,
        "hook_strategy": "ssl_pinning_bypass",
        "impact": "会直接导致 HTTPS 抓包失败或证书不被信任。",
    },
    "frida_or_debug_detection": {
        "severity": "High",
        "priority": 84,
        "phase2_blocking": True,
        "hook_strategy": "debug_bypass",
        "impact": "可能阻塞 Frida 注入、调试附加或运行时观测。",
    },
    "signature_check": {
        "severity": "Medium",
        "priority": 75,
        "phase2_blocking": True,
        "hook_strategy": "manual_signature_review",
        "impact": "重打包、替换证书或调试改包时可能触发退出或限流。",
    },
    "integrity_or_attestation": {
        "severity": "Medium",
        "priority": 72,
        "phase2_blocking": True,
        "hook_strategy": "manual_attestation_review",
        "impact": "可能导致登录、风控或关键业务链路被服务端拒绝。",
    },
    "multi_open_detection": {
        "severity": "Medium",
        "priority": 60,
        "phase2_blocking": False,
        "hook_strategy": "manual_multi_open_review",
        "impact": "多开、平行空间或虚拟容器环境下可能触发限制。",
    },
    "anti_tamper_or_packer": {
        "severity": "Medium",
        "priority": 70,
        "phase2_blocking": True,
        "hook_strategy": "manual_packer_review",
        "impact": "可能影响类加载、反编译可见性或运行时插桩稳定性。",
    },
}

FRIDA_MODULES = {
    "root_bypass": {
        "placeholder": "__ENABLE_ROOT__",
        "description": "隐藏 su / Magisk / test-keys / Root 包信息与常见命令执行。",
        "guard_types": ["root_detection"],
    },
    "emulator_bypass": {
        "placeholder": "__ENABLE_EMULATOR__",
        "description": "伪造 Build 与系统属性，降低模拟器环境命中概率。",
        "guard_types": ["emulator_detection"],
    },
    "proxy_bypass": {
        "placeholder": "__ENABLE_PROXY__",
        "description": "隐藏常见 Java 层代理属性，降低代理/抓包环境命中概率。",
        "guard_types": ["proxy_or_vpn_detection"],
    },
    "ssl_pinning_bypass": {
        "placeholder": "__ENABLE_SSL__",
        "description": "替换常见 TrustManager / HostnameVerifier / okhttp3 CertificatePinner 校验。",
        "guard_types": ["ssl_pinning_or_cert_check"],
    },
    "debug_bypass": {
        "placeholder": "__ENABLE_DEBUG__",
        "description": "关闭常见 Debug 调试状态检测，降低运行时调试阻塞。",
        "guard_types": ["frida_or_debug_detection"],
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="Decompiled target directory")
    parser.add_argument("--output-dir", required=True, help="Analysis output root; env guard artifacts are written to step1/ by default")
    parser.add_argument("--inventory", help="Optional file_inventory.json path")
    parser.add_argument("--max-size-kb", type=int, default=2048, help="Skip files larger than this size")
    return parser.parse_args()


def resolve_phase_output_dir(output_dir: Path, phase_dir: str) -> Path:
    return output_dir if output_dir.name == phase_dir else output_dir / phase_dir


def is_excluded_dir(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return any(part in EXCLUDE_DIRS for part in parts)


def should_scan(path: Path, max_size_kb: int) -> bool:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name != "AndroidManifest.xml":
        return False
    try:
        return path.stat().st_size <= max_size_kb * 1024
    except OSError:
        return False


def collect_files(target_dir: Path, inventory_path: str | None, max_size_kb: int) -> tuple[list[tuple[Path, str]], str]:
    files: list[tuple[Path, str]] = []
    source = "walk"
    if inventory_path:
        inventory_file = Path(inventory_path).expanduser()
        if inventory_file.is_file():
            try:
                inventory = json.loads(inventory_file.read_text(encoding="utf-8"))
                file_inv = inventory.get("file_inventory")
                if not isinstance(file_inv, dict):
                    file_inv = {
                        key: value
                        for key, value in inventory.items()
                        if key.endswith("_files") and isinstance(value, list)
                    }
                for entries in file_inv.values():
                    for rel in entries:
                        if not isinstance(rel, str):
                            continue
                        clean_rel = rel.replace("[LARGE] ", "")
                        full = target_dir / clean_rel
                        if full.is_file() and not is_excluded_dir(clean_rel) and should_scan(full, max_size_kb):
                            files.append((full, clean_rel))
                if files:
                    source = "inventory"
                    return files, source
            except Exception:
                pass

    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue
        rel_path = str(path.relative_to(target_dir))
        if is_excluded_dir(rel_path):
            continue
        if should_scan(path, max_size_kb):
            files.append((path, rel_path))
    return files, source


def get_context(lines: list[str], line_idx: int, before: int = 1, after: int = 1) -> str:
    start = max(0, line_idx - before)
    end = min(len(lines), line_idx + after + 1)
    ctx_lines = []
    for idx in range(start, end):
        prefix = ">>> " if idx == line_idx else "    "
        ctx_lines.append(f"{prefix}{idx + 1}: {lines[idx].rstrip()}")
    return "\n".join(ctx_lines)


def add_hit(
    hits: list[dict],
    seen: set[tuple],
    guard_type: str,
    match_value: str,
    line_no: int,
    context: str,
    source_file: str,
    pattern: str,
) -> None:
    key = (source_file, guard_type, line_no, match_value.lower())
    if key in seen:
        return
    seen.add(key)
    hits.append(
        {
            "guard_type": guard_type,
            "match": match_value,
            "line": line_no,
            "context": context[:600],
            "source_file": source_file,
            "pattern": pattern,
            "bypass_hint": BYPASS_HINTS[guard_type],
        }
    )


def scan_file(path: Path, rel_path: str) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    if not text.strip():
        return []

    hits: list[dict] = []
    seen: set[tuple] = set()
    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        context = get_context(lines, line_no - 1)
        for guard_type, patterns in COMPILED_RULES.items():
            for pattern in patterns:
                for match in pattern.finditer(line):
                    add_hit(hits, seen, guard_type, match.group(0), line_no, context, rel_path, pattern.pattern)

    return hits


def group_hits_by_guard_type(all_hits: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for hit in all_hits:
        grouped.setdefault(hit["guard_type"], []).append(hit)
    return grouped


def build_env_guard_report(
    target_dir: Path,
    file_source: str,
    inventory_path: str | None,
    max_size_kb: int,
    scanned_files: int,
    skipped_large_files: list[str],
    all_hits: list[dict],
) -> dict:
    grouped = group_hits_by_guard_type(all_hits)
    ordered_guard_types = sorted(
        grouped.keys(),
        key=lambda guard_type: GUARD_METADATA.get(guard_type, {}).get("priority", 0),
        reverse=True,
    )

    findings: list[dict] = []
    for index, guard_type in enumerate(ordered_guard_types, start=1):
        hits = grouped[guard_type]
        meta = GUARD_METADATA[guard_type]
        findings.append(
            {
                "id": f"ENV-{index:03d}",
                "guard_type": guard_type,
                "severity": meta["severity"],
                "priority": meta["priority"],
                "phase2_blocking": meta["phase2_blocking"],
                "hook_strategy": meta["hook_strategy"],
                "impact": meta["impact"],
                "bypass_hint": BYPASS_HINTS[guard_type],
                "hit_count": len(hits),
                "sample_matches": [hit["match"] for hit in hits[:5]],
                "evidence_locations": [
                    {
                        "source_file": hit["source_file"],
                        "line": hit["line"],
                        "match": hit["match"],
                        "context": hit["context"],
                    }
                    for hit in hits[:10]
                ],
            }
        )

    return {
        "scan_meta": {
            "tool": "env_guard_indexer.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_dir": str(target_dir),
            "file_source": file_source,
            "inventory_path": inventory_path,
            "max_size_kb": max_size_kb,
            "total_text_files_scanned": scanned_files,
            "skipped_large_files": skipped_large_files,
        },
        "summary": {
            "total_guard_types_detected": len(ordered_guard_types),
            "total_hits": len(all_hits),
            "phase2_blocking_guard_types": [
                guard_type
                for guard_type in ordered_guard_types
                if GUARD_METADATA.get(guard_type, {}).get("phase2_blocking")
            ],
            "suggested_frida_modules": [
                module_name
                for module_name, module in FRIDA_MODULES.items()
                if any(guard_type in grouped for guard_type in module["guard_types"])
            ],
        },
        "findings": findings,
    }


def build_frida_bypass_plan(all_hits: list[dict]) -> dict:
    grouped = group_hits_by_guard_type(all_hits)
    modules = []
    for module_name, module in FRIDA_MODULES.items():
        related_guard_types = [guard_type for guard_type in module["guard_types"] if guard_type in grouped]
        evidence_refs = []
        for guard_type in related_guard_types:
            for hit in grouped[guard_type][:5]:
                evidence_refs.append(
                    {
                        "guard_type": guard_type,
                        "source_file": hit["source_file"],
                        "line": hit["line"],
                        "match": hit["match"],
                    }
                )
        modules.append(
            {
                "module": module_name,
                "enabled": bool(related_guard_types),
                "description": module["description"],
                "related_guard_types": related_guard_types,
                "related_hits": sum(len(grouped[guard_type]) for guard_type in related_guard_types),
                "evidence_refs": evidence_refs,
            }
        )

    manual_review = []
    for guard_type in grouped:
        hook_strategy = GUARD_METADATA[guard_type]["hook_strategy"]
        if hook_strategy.startswith("manual_"):
            manual_review.append(
                {
                    "guard_type": guard_type,
                    "hook_strategy": hook_strategy,
                    "bypass_hint": BYPASS_HINTS[guard_type],
                    "hit_count": len(grouped[guard_type]),
                }
            )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "template_source": "tools/frida/android_phase1_bypass.js",
        "modules": modules,
        "manual_review": manual_review,
    }


def build_generated_script_header(plan: dict) -> str:
    lines = [
        "// Generated by env_guard_indexer.py",
        f"// Template source: {plan['template_source']}",
        f"// Generated at: {plan['generated_at']}",
        "//",
        "// This is a project-specific Frida bypass template generated from detected",
        "// environment-guard clues. Keep only the modules that match the current target,",
        "// then add class-specific hooks for custom logic when needed.",
        "//",
        "// Enabled modules:",
    ]
    for module in plan["modules"]:
        status = "enabled" if module["enabled"] else "disabled"
        lines.append(f"// - {module['module']}: {status} | {module['description']}")
        for evidence in module.get("evidence_refs", [])[:3]:
            lines.append(
                f"//   evidence: {evidence['guard_type']} @ {evidence['source_file']}:{evidence['line']} ({evidence['match']})"
            )
    if plan["manual_review"]:
        lines.append("//")
        lines.append("// Manual review required:")
        for item in plan["manual_review"]:
            lines.append(
                f"// - {item['guard_type']}: {item['hook_strategy']} | {item['bypass_hint']}"
            )
    lines.append("")
    return "\n".join(lines)


def render_frida_script(template_path: Path, enabled_modules: dict[str, bool], plan: dict) -> str:
    template = template_path.read_text(encoding="utf-8")
    rendered = template
    for module in FRIDA_MODULES.values():
        placeholder = module["placeholder"]
        enabled = any(enabled_modules.get(guard_type, False) for guard_type in module["guard_types"])
        rendered = rendered.replace(placeholder, "true" if enabled else "false")
    return build_generated_script_header(plan) + rendered


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_dir = resolve_phase_output_dir(output_root, "step1")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_hits: list[dict] = []
    by_file: dict[str, dict] = {}
    guard_counter: Counter[str] = Counter()
    scanned_files = 0
    skipped_large_files: list[str] = []

    files, file_source = collect_files(target_dir, args.inventory, args.max_size_kb)
    for path, rel_path in files:
        scanned_files += 1
        file_hits = scan_file(path, rel_path)
        if not file_hits:
            continue
        by_file[rel_path] = {
            "file_size_kb": round(path.stat().st_size / 1024, 2),
            "hit_count": len(file_hits),
            "hits": file_hits,
        }
        for hit in file_hits:
            all_hits.append(hit)
            guard_counter[hit["guard_type"]] += 1

    result = {
        "scan_meta": {
            "tool": "env_guard_indexer.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_dir": str(target_dir),
            "file_source": file_source,
            "inventory_path": args.inventory,
            "max_size_kb": args.max_size_kb,
            "total_text_files_scanned": scanned_files,
            "skipped_large_files": skipped_large_files,
        },
        "total_hits": len(all_hits),
        "guard_statistics": dict(guard_counter),
        "by_file": by_file,
        "all_hits": all_hits,
    }

    output_path = output_dir / "raw_env_guards.json"
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    report = build_env_guard_report(
        target_dir=target_dir,
        file_source=file_source,
        inventory_path=args.inventory,
        max_size_kb=args.max_size_kb,
        scanned_files=scanned_files,
        skipped_large_files=skipped_large_files,
        all_hits=all_hits,
    )
    report_path = output_dir / "env_guard_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    plan = build_frida_bypass_plan(all_hits)
    plan_path = output_dir / "frida_bypass_plan.json"
    plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")

    frida_dir = output_dir / "frida"
    frida_dir.mkdir(parents=True, exist_ok=True)
    template_path = Path(__file__).resolve().parents[1] / "frida" / "android_phase1_bypass.js"
    enabled_modules = {guard_type: guard_type in group_hits_by_guard_type(all_hits) for guard_type in GUARD_METADATA}
    rendered_frida = render_frida_script(template_path, enabled_modules, plan)
    rendered_frida_path = frida_dir / "android_phase1_bypass.js"
    rendered_frida_path.write_text(rendered_frida, encoding="utf-8")

    print(output_path)
    print(report_path)
    print(plan_path)
    print(rendered_frida_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

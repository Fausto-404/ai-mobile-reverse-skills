#!/usr/bin/env python3
"""Compress Phase 1 raw_* JSON outputs into an AI-friendly summary layer.

Reads the 4 raw output files produced by Phase 1 index scripts and generates
a single compressed summary JSON that is optimized for LLM consumption:
- Deduplicated, priority-ranked top-N items per category
- Aggregated statistics instead of raw hit lists
- Clear pointer back to full data files for deep dives

Usage:
    python ai_summarizer.py --output-dir analysis_runs/current_run
    python ai_summarizer.py --output-dir analysis_runs/current_run --top-n 30
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_TOP_N = 25
DEFAULT_TOP_ENDPOINTS = 30
DEFAULT_TOP_SECRETS = 20
DEFAULT_TOP_BRIDGES = 15
DEFAULT_TOP_GUARDS = 10

PHASE_DIR = "step1"

# Types that represent actual API endpoints (vs metadata hits)
ENDPOINT_VALUE_TYPES = {
    "full_url",
    "base_url",
    "env_url",
    "base_url_builder",
    "protocol_relative_url",
    "retrofit_annotation",
    "path_fragment",
    "business_path",
    "no_slash_api_path",
    "generic_path",
    "axios_call",
    "fetch_call",
    "xhr_open",
    "method_call",
    "request_url_property",
    "uri_parse",
    "websocket_url",
    "websocket_constructor",
    "okhttp_url",
    "upload_call",
    "download_call",
    "graphql_endpoint",
    "socket_url_var",
    "mqtt_url",
    "content_uri",
    "webview_src",
    "function_call_url",
}

# Types that represent request wrapper / framework clues
WRAPPER_TYPES = {
    "request_wrapper_def",
    "crypto_wrapper_hint",
}

# Types that represent header / crypto field names
FIELD_TYPES = {
    "header_key",
    "crypto_field_key",
}

# Types that represent deeplink / manifest configuration
MANIFEST_TYPES = {
    "deeplink_scheme",
    "deeplink_host",
    "deeplink_port",
    "deeplink_path",
    "provider_authority",
    "network_security_config",
    "exported_component",
    "browsable_category",
}

# Severity priority for sorting
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def phase_dir(output_dir: Path) -> Path:
    return output_dir if output_dir.name == PHASE_DIR else output_dir / PHASE_DIR


def read_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def deduplicate_by_value(items: list[dict], value_key: str = "value") -> list[dict]:
    """Keep first occurrence of each unique value."""
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        val = item.get(value_key, "")
        if val not in seen:
            seen.add(val)
            result.append(item)
    return result


def severity_sort_key(item: dict) -> tuple:
    sev = item.get("severity", "Info")
    return (SEVERITY_ORDER.get(sev, 99), item.get("value", ""))


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}...{value[-4:]}"


# ---------------------------------------------------------------------------
# Endpoint summarizer
# ---------------------------------------------------------------------------


def summarize_endpoints(raw: dict | None, top_n: int) -> dict:
    if raw is None:
        return {
            "available": False,
            "base_urls": [],
            "api_endpoints": [],
            "retrofit_endpoints": [],
            "deeplink_configs": [],
            "request_wrappers": [],
            "crypto_field_names": [],
            "header_field_names": [],
            "statistics": {},
        }

    all_hits: list[dict] = raw.get("all_hits", [])
    by_type: dict[str, list[dict]] = defaultdict(list)
    for hit in all_hits:
        by_type[hit["type"]].append(hit)

    # --- base URLs ---
    base_urls = []
    for hit in by_type.get("base_url", []) + by_type.get("base_url_builder", []) + by_type.get("env_url", []):
        base_urls.append({"url": hit["value"], "source": hit["source_file"], "line": hit["line"]})
    for cand in raw.get("base_url_candidates", []):
        base_urls.append({"url": cand["value"], "source": cand.get("source_file", ""), "line": cand.get("source_line", 0)})
    # dedupe by url
    seen_urls: set[str] = set()
    unique_base: list[dict] = []
    for item in base_urls:
        if item["url"] not in seen_urls:
            seen_urls.add(item["url"])
            unique_base.append(item)

    # --- API endpoints (full URLs + paths) ---
    api_hits = (
        by_type.get("full_url", [])
        + by_type.get("path_fragment", [])
        + by_type.get("business_path", [])
        + by_type.get("no_slash_api_path", [])
        + by_type.get("generic_path", [])
    )
    api_hits_deduped = deduplicate_by_value(api_hits)[:top_n]

    # --- retrofit annotations ---
    retrofit_hits = deduplicate_by_value(by_type.get("retrofit_annotation", []))[:top_n]

    # --- request wrappers ---
    wrapper_hits = deduplicate_by_value(
        by_type.get("request_wrapper_def", []) + by_type.get("crypto_wrapper_hint", [])
    )[:15]

    # --- deeplink / manifest ---
    deeplink_hits = []
    for mtype in MANIFEST_TYPES:
        deeplink_hits.extend(by_type.get(mtype, []))
    deeplink_deduped = deduplicate_by_value(deeplink_hits)[:top_n]

    # --- crypto / header field names ---
    crypto_fields = deduplicate_by_value(by_type.get("crypto_field_key", []))
    header_fields = deduplicate_by_value(by_type.get("header_key", []))

    # --- statistics ---
    type_stats = raw.get("type_statistics", {})

    return {
        "available": True,
        "total_raw_hits": raw.get("total_raw_hits", 0),
        "base_urls": unique_base[:15],
        "api_endpoints": [
            {
                "value": h["value"],
                "type": h["type"],
                "source": h["source_file"],
                "line": h["line"],
            }
            for h in api_hits_deduped
        ],
        "retrofit_endpoints": [
            {
                "value": h["value"],
                "source": h["source_file"],
                "line": h["line"],
            }
            for h in retrofit_hits
        ],
        "deeplink_configs": [
            {
                "value": h["value"],
                "type": h["type"],
                "source": h["source_file"],
                "line": h["line"],
            }
            for h in deeplink_deduped
        ],
        "request_wrappers": [
            {
                "value": h["value"][:120],
                "type": h["type"],
                "source": h["source_file"],
                "line": h["line"],
            }
            for h in wrapper_hits
        ],
        "crypto_field_names": [h["value"] for h in crypto_fields[:20]],
        "header_field_names": [h["value"] for h in header_fields[:20]],
        "statistics": {
            "endpoint_types": {
                k: v for k, v in sorted(type_stats.items(), key=lambda x: -x[1])
                if k in ENDPOINT_VALUE_TYPES
            },
            "wrapper_count": sum(type_stats.get(t, 0) for t in WRAPPER_TYPES),
            "manifest_config_count": sum(type_stats.get(t, 0) for t in MANIFEST_TYPES),
        },
        "full_data": f"{PHASE_DIR}/raw_endpoints.json",
    }


# ---------------------------------------------------------------------------
# Secrets summarizer
# ---------------------------------------------------------------------------


def summarize_secrets(raw: dict | None, top_n: int) -> dict:
    if raw is None:
        return {
            "available": False,
            "critical_findings": [],
            "high_findings": [],
            "by_category": {},
            "statistics": {},
        }

    all_hits: list[dict] = raw.get("all_hits", [])

    # Separate real vs placeholder
    real_hits = [h for h in all_hits if not h.get("is_placeholder")]
    placeholder_count = len(all_hits) - len(real_hits)

    # Sort by severity
    real_hits.sort(key=severity_sort_key)

    # --- critical & high ---
    critical = [h for h in real_hits if h["severity"] == "Critical"]
    high = [h for h in real_hits if h["severity"] == "High"]

    def format_secret_hit(h: dict) -> dict:
        return {
            "category": h.get("category", ""),
            "sub_type": h.get("sub_type", ""),
            "severity": h["severity"],
            "masked_value": h.get("masked_value", mask_value(h.get("value", ""))),
            "confidence": h.get("confidence", "medium"),
            "source": h.get("source_file", ""),
            "line": h.get("line", 0),
        }

    # --- by category (only non-placeholder) ---
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for h in real_hits:
        by_cat[h.get("category", "unknown")].append(h)

    category_summary = {}
    for cat, hits in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        sev_counts = Counter(h["severity"] for h in hits)
        # Keep top 5 per category
        top_hits = sorted(hits, key=severity_sort_key)[:5]
        category_summary[cat] = {
            "total": len(hits),
            "critical": sev_counts.get("Critical", 0),
            "high": sev_counts.get("High", 0),
            "medium": sev_counts.get("Medium", 0),
            "top_findings": [format_secret_hit(h) for h in top_hits],
        }

    sev_counts_all = Counter(h["severity"] for h in real_hits)
    cat_counts = Counter(h.get("category", "unknown") for h in real_hits)

    return {
        "available": True,
        "total_real_hits": len(real_hits),
        "total_placeholder_hits": placeholder_count,
        "critical_findings": [format_secret_hit(h) for h in critical[:top_n]],
        "high_findings": [format_secret_hit(h) for h in high[:top_n]],
        "by_category": category_summary,
        "statistics": {
            "by_severity": dict(sev_counts_all),
            "by_category": dict(cat_counts),
            "scan_rules_count": raw.get("scan_meta", {}).get("scan_rules_count", 0),
        },
        "full_data": f"{PHASE_DIR}/raw_secrets.json",
    }


# ---------------------------------------------------------------------------
# Native bridge summarizer
# ---------------------------------------------------------------------------


def summarize_native_bridges(raw: dict | None, top_n: int) -> dict:
    if raw is None:
        return {
            "available": False,
            "loaded_libraries": [],
            "native_methods": [],
            "webview_bridges": [],
            "native_crypto_signals": [],
            "statistics": {},
        }

    all_hits: list[dict] = raw.get("all_hits", [])
    by_type: dict[str, list[dict]] = defaultdict(list)
    for hit in all_hits:
        by_type[hit["type"]].append(hit)

    # --- loaded libraries ---
    libraries_raw = raw.get("libraries", [])
    loaded_libs = []
    for lib in libraries_raw[:top_n]:
        occ_count = len(lib.get("occurrences", []))
        sources = list({o["source_file"] for o in lib.get("occurrences", []) if o.get("source_file")})[:3]
        loaded_libs.append({
            "library": lib["library"],
            "load_count": occ_count,
            "sources": sources,
        })

    # --- native method declarations ---
    native_methods = deduplicate_by_value(by_type.get("native_method", []))[:top_n]

    # --- JNI symbols ---
    jni_symbols = deduplicate_by_value(by_type.get("jni_symbol", []))[:top_n]

    # --- RegisterNatives ---
    register_natives = len(by_type.get("register_natives", []))
    jni_native_method_struct = len(by_type.get("jni_native_method_struct", []))

    # --- WebView / JSBridge ---
    js_interfaces = deduplicate_by_value(by_type.get("add_javascript_interface", []))
    evaluate_js = deduplicate_by_value(by_type.get("evaluate_javascript", []))
    load_url_js = deduplicate_by_value(by_type.get("load_url_javascript", []))
    js_annotations = len(by_type.get("javascript_interface_annotation", []))
    js_enabled = len(by_type.get("webview_javascript_enabled", []))
    bridge_libs = deduplicate_by_value(by_type.get("bridge_library_marker", []))

    # --- native crypto ---
    crypto_symbols = deduplicate_by_value(by_type.get("native_crypto_symbol", []))[:top_n]
    crypto_libs = deduplicate_by_value(by_type.get("native_crypto_library", []))[:10]
    java_crypto_bridge = deduplicate_by_value(by_type.get("java_crypto_bridge", []))[:top_n]

    type_stats = raw.get("type_statistics", {})

    return {
        "available": True,
        "total_raw_hits": raw.get("total_hits", 0),
        "loaded_libraries": loaded_libs,
        "native_methods": [
            {"method": h["value"], "source": h["source_file"], "line": h["line"]}
            for h in native_methods
        ],
        "jni_symbols": [h["value"] for h in jni_symbols],
        "dynamic_registration": {
            "register_natives_count": register_natives,
            "jni_native_method_struct_count": jni_native_method_struct,
        },
        "webview_bridges": {
            "js_interfaces": [
                {"name": h["value"], "source": h["source_file"], "line": h["line"]}
                for h in js_interfaces
            ],
            "evaluate_javascript": [
                {"value": h["value"][:80], "source": h["source_file"], "line": h["line"]}
                for h in evaluate_js
            ],
            "load_url_javascript": [
                {"value": h["value"][:80], "source": h["source_file"], "line": h["line"]}
                for h in load_url_js
            ],
            "js_interface_annotations": js_annotations,
            "javascript_enabled_count": js_enabled,
            "bridge_libraries": [h["value"][:100] for h in bridge_libs],
        },
        "native_crypto_signals": {
            "crypto_symbols": [h["value"][:100] for h in crypto_symbols],
            "crypto_libraries": [h["value"][:80] for h in crypto_libs],
            "java_crypto_bridge_calls": [h["value"][:100] for h in java_crypto_bridge],
        },
        "statistics": {
            k: v for k, v in sorted(type_stats.items(), key=lambda x: -x[1])
        },
        "full_data": f"{PHASE_DIR}/raw_native_bridges.json",
    }


# ---------------------------------------------------------------------------
# Env guard summarizer
# ---------------------------------------------------------------------------


def summarize_env_guards(
    raw: dict | None,
    report: dict | None,
    frida_plan: dict | None,
    top_n: int,
) -> dict:
    if raw is None:
        return {
            "available": False,
            "detected_guard_types": [],
            "phase2_blocking": [],
            "frida_recommendations": [],
            "statistics": {},
        }

    all_hits: list[dict] = raw.get("all_hits", [])

    # Group by guard_type
    by_guard: dict[str, list[dict]] = defaultdict(list)
    for hit in all_hits:
        by_guard[hit["guard_type"]].append(hit)

    # Use env_guard_report.json findings if available (already sorted by priority)
    if report and "findings" in report:
        findings = report["findings"]
    else:
        # Fallback: build from raw hits
        guard_meta = {
            "root_detection": {"severity": "High", "priority": 90, "phase2_blocking": True},
            "emulator_detection": {"severity": "High", "priority": 85, "phase2_blocking": True},
            "proxy_or_vpn_detection": {"severity": "High", "priority": 88, "phase2_blocking": True},
            "ssl_pinning_or_cert_check": {"severity": "Critical", "priority": 95, "phase2_blocking": True},
            "frida_or_debug_detection": {"severity": "High", "priority": 84, "phase2_blocking": True},
            "signature_check": {"severity": "Medium", "priority": 75, "phase2_blocking": True},
            "integrity_or_attestation": {"severity": "Medium", "priority": 72, "phase2_blocking": True},
            "multi_open_detection": {"severity": "Medium", "priority": 60, "phase2_blocking": False},
            "anti_tamper_or_packer": {"severity": "Medium", "priority": 70, "phase2_blocking": True},
        }
        findings = []
        for guard_type, hits in sorted(by_guard.items(), key=lambda x: -guard_meta.get(x[0], {}).get("priority", 0)):
            meta = guard_meta.get(guard_type, {})
            findings.append({
                "guard_type": guard_type,
                "severity": meta.get("severity", "Medium"),
                "priority": meta.get("priority", 50),
                "phase2_blocking": meta.get("phase2_blocking", False),
                "hit_count": len(hits),
                "sample_matches": [h["match"] for h in hits[:5]],
            })

    # Extract blocking guard types
    phase2_blocking = [f for f in findings if f.get("phase2_blocking")]

    # Frida recommendations
    frida_modules = []
    if frida_plan:
        for mod in frida_plan.get("modules", []):
            if mod.get("enabled"):
                frida_modules.append({
                    "module": mod["module"],
                    "description": mod.get("description", ""),
                    "related_guard_types": mod.get("related_guard_types", []),
                    "hit_count": mod.get("related_hits", 0),
                })

    # Manual review items
    manual_review = []
    if frida_plan:
        for item in frida_plan.get("manual_review", []):
            manual_review.append({
                "guard_type": item["guard_type"],
                "bypass_hint": item.get("bypass_hint", ""),
                "hit_count": item.get("hit_count", 0),
            })

    # Top evidence per guard type (condensed)
    guard_summaries = []
    for f in findings[:top_n]:
        evidence_sample = []
        if "evidence_locations" in f:
            evidence_sample = [
                {"source": e["source_file"], "line": e["line"], "match": e["match"][:60]}
                for e in f["evidence_locations"][:3]
            ]
        else:
            hits = by_guard.get(f["guard_type"], [])
            evidence_sample = [
                {"source": h["source_file"], "line": h["line"], "match": h["match"][:60]}
                for h in hits[:3]
            ]
        guard_summaries.append({
            "guard_type": f["guard_type"],
            "severity": f.get("severity", "Medium"),
            "priority": f.get("priority", 50),
            "phase2_blocking": f.get("phase2_blocking", False),
            "hit_count": f.get("hit_count", 0),
            "sample_matches": f.get("sample_matches", [])[:3],
            "evidence": evidence_sample,
            "hook_strategy": f.get("hook_strategy", ""),
            "bypass_hint": f.get("bypass_hint", ""),
            "impact": f.get("impact", ""),
        })

    sev_counts = Counter(f.get("severity", "Medium") for f in findings)

    return {
        "available": True,
        "total_guard_types_detected": len(findings),
        "total_hits": len(all_hits),
        "phase2_blocking_count": len(phase2_blocking),
        "detected_guard_types": guard_summaries,
        "phase2_blocking": [
            {
                "guard_type": f["guard_type"],
                "severity": f.get("severity"),
                "hit_count": f.get("hit_count", 0),
                "hook_strategy": f.get("hook_strategy", ""),
                "impact": f.get("impact", ""),
            }
            for f in phase2_blocking
        ],
        "frida_recommendations": frida_modules,
        "manual_review_items": manual_review,
        "statistics": {
            "by_severity": dict(sev_counts),
            "guard_types_detected": [f["guard_type"] for f in findings],
            "suggested_frida_modules": [m["module"] for m in frida_modules],
        },
        "full_data": {
            "raw": f"{PHASE_DIR}/raw_env_guards.json",
            "report": f"{PHASE_DIR}/env_guard_report.json",
            "frida_plan": f"{PHASE_DIR}/frida_bypass_plan.json",
        },
    }


# ---------------------------------------------------------------------------
# Cross-source correlation
# ---------------------------------------------------------------------------


def build_correlations(
    endpoints: dict,
    secrets: dict,
    bridges: dict,
    guards: dict,
) -> dict:
    """Find cross-cutting signals across the 4 raw sources."""

    signals: list[dict] = []

    # 1. If SSL pinning detected AND crypto fields found → traffic alignment will be harder
    ssl_blocking = any(
        f["guard_type"] == "ssl_pinning_or_cert_check"
        for f in guards.get("phase2_blocking", [])
    )
    crypto_fields = endpoints.get("crypto_field_names", [])
    if ssl_blocking and crypto_fields:
        signals.append({
            "signal": "ssl_pinning_with_crypto_fields",
            "severity": "High",
            "description": "SSL Pinning 检测存在且代码中有加密字段，Phase 2 抓包前需先绕过 SSL Pinning",
            "action": "先启用 Frida SSL Pinning bypass，再接入 Burp/Yakit MCP",
        })

    # 2. If native crypto symbols found AND Java crypto bridge found → Phase 3 likely needed
    native_crypto = bridges.get("native_crypto_signals", {})
    has_native_crypto = bool(native_crypto.get("crypto_symbols") or native_crypto.get("crypto_libraries"))
    has_java_bridge = bool(native_crypto.get("java_crypto_bridge_calls"))
    if has_native_crypto and has_java_bridge:
        signals.append({
            "signal": "java_native_crypto_chain",
            "severity": "High",
            "description": "Java 层和 Native 层均发现加密调用，Phase 3 需要分析 JNI → SO 链路",
            "action": "Phase 2 后用 resolve_native_target.py 收敛目标 SO",
        })

    # 3. If root/emulator detection AND frida bypass generated → ready for runtime
    frida_modules = guards.get("frida_recommendations", [])
    has_root_or_emu = any(
        f["guard_type"] in ("root_detection", "emulator_detection")
        for f in guards.get("detected_guard_types", [])
    )
    if has_root_or_emu and frida_modules:
        signals.append({
            "signal": "runtime_bypass_ready",
            "severity": "Medium",
            "description": "已检测到 Root/模拟器对抗且已生成 Frida bypass 脚本，可运行时绕过",
            "action": f"使用 {PHASE_DIR}/frida/android_phase1_bypass.js 注入目标 App",
        })

    # 4. If JSBridge found → WebView attack surface
    js_bridges = bridges.get("webview_bridges", {})
    has_jsbridge = bool(js_bridges.get("js_interfaces") or js_bridges.get("bridge_libraries"))
    if has_jsbridge:
        signals.append({
            "signal": "webview_jsbridge_surface",
            "severity": "High",
            "description": f"发现 {len(js_bridges.get('js_interfaces', []))} 个 JSBridge 接口，"
                          f"{js_bridges.get('javascript_enabled_count', 0)} 处 JS 启用，Phase 4 需重点审计",
            "action": "Phase 4 生成 jsbridge_analysis.json",
        })

    # 5. If cloud keys found → high severity immediate finding
    cloud_cats = secrets.get("by_category", {}).get("cloud_key", {})
    if cloud_cats and cloud_cats.get("critical", 0) > 0:
        signals.append({
            "signal": "cloud_credentials_leaked",
            "severity": "Critical",
            "description": f"发现 {cloud_cats['critical']} 个 Critical 级云凭证泄露",
            "action": "Phase 4 标记为 Critical 漏洞，需立即处理",
        })

    # 6. If loaded libraries include crypto-related SO names
    crypto_lib_names = {"libssl", "libcrypto", "libnative", "libsecurity", "libencrypt"}
    loaded_libs = bridges.get("loaded_libraries", [])
    crypto_libs = [
        lib for lib in loaded_libs
        if any(hint in lib["library"].lower() for hint in crypto_lib_names)
    ]
    if crypto_libs:
        signals.append({
            "signal": "crypto_native_libraries_loaded",
            "severity": "Medium",
            "description": f"加载了 {len(crypto_libs)} 个疑似加密相关 SO: "
                          + ", ".join(lib["library"] for lib in crypto_libs[:3]),
            "action": "Phase 3 优先分析这些 SO",
        })

    return {
        "total_signals": len(signals),
        "signals": signals,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_summary(output_root: Path, top_n: int) -> dict:
    step = phase_dir(output_root)

    raw_endpoints = read_json(step / "raw_endpoints.json")
    raw_secrets = read_json(step / "raw_secrets.json")
    raw_bridges = read_json(step / "raw_native_bridges.json")
    raw_guards = read_json(step / "raw_env_guards.json")
    env_report = read_json(step / "env_guard_report.json")
    frida_plan = read_json(step / "frida_bypass_plan.json")

    endpoints_summary = summarize_endpoints(raw_endpoints, top_n)
    secrets_summary = summarize_secrets(raw_secrets, top_n)
    bridges_summary = summarize_native_bridges(raw_bridges, top_n)
    guards_summary = summarize_env_guards(raw_guards, env_report, frida_plan, top_n)

    correlations = build_correlations(
        endpoints_summary, secrets_summary, bridges_summary, guards_summary
    )

    # Source availability
    sources_available = {
        "raw_endpoints": raw_endpoints is not None,
        "raw_secrets": raw_secrets is not None,
        "raw_native_bridges": raw_bridges is not None,
        "raw_env_guards": raw_guards is not None,
        "env_guard_report": env_report is not None,
        "frida_bypass_plan": frida_plan is not None,
    }
    available_count = sum(1 for v in sources_available.values() if v)

    return {
        "summary_meta": {
            "tool": "ai_summarizer.py",
            "generated_at": utc_now(),
            "output_dir": str(output_root),
            "top_n": top_n,
            "sources_available": sources_available,
            "sources_coverage": f"{available_count}/{len(sources_available)}",
        },
        "quick_overview": {
            "has_urls": endpoints_summary["available"],
            "total_raw_endpoint_hits": endpoints_summary.get("total_raw_hits", 0),
            "base_url_count": len(endpoints_summary.get("base_urls", [])),
            "has_secrets": secrets_summary["available"],
            "real_secret_count": secrets_summary.get("total_real_hits", 0),
            "critical_secret_count": len(secrets_summary.get("critical_findings", [])),
            "has_native_bridges": bridges_summary["available"],
            "loaded_library_count": len(bridges_summary.get("loaded_libraries", [])),
            "jsbridge_interface_count": len(
                bridges_summary.get("webview_bridges", {}).get("js_interfaces", [])
            ),
            "has_env_guards": guards_summary["available"],
            "guard_type_count": guards_summary.get("total_guard_types_detected", 0),
            "phase2_blocking_count": guards_summary.get("phase2_blocking_count", 0),
            "cross_signals": correlations.get("total_signals", 0),
        },
        "endpoints": endpoints_summary,
        "secrets": secrets_summary,
        "native_bridges": bridges_summary,
        "env_guards": guards_summary,
        "cross_source_signals": correlations,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Analysis output root (e.g. analysis_runs/current_run)",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"Max items per category (default: {DEFAULT_TOP_N})",
    )
    parser.add_argument(
        "--output-file",
        default="ai_summary.json",
        help="Output filename inside step1/ (default: ai_summary.json)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_dir).expanduser().resolve()
    step = phase_dir(output_root)

    if not step.is_dir():
        print(f"[-] step1 directory not found: {step}")
        print("    Run the Phase 1 index scripts first.")
        return 1

    summary = build_summary(output_root, args.top_n)

    out_path = step / args.output_file
    out_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    overview = summary["quick_overview"]
    print(f"[+] AI summary written: {out_path}")
    print(f"    Sources: {summary['summary_meta']['sources_coverage']}")
    print(f"    Endpoints: {overview['total_raw_endpoint_hits']} raw hits, {overview['base_url_count']} base URLs")
    print(f"    Secrets: {overview['real_secret_count']} real, {overview['critical_secret_count']} critical")
    print(f"    Native: {overview['loaded_library_count']} libs, {overview['jsbridge_interface_count']} JSBridge interfaces")
    print(f"    Guards: {overview['guard_type_count']} types, {overview['phase2_blocking_count']} blocking Phase 2")
    print(f"    Cross signals: {overview['cross_signals']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

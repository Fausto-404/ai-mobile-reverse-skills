#!/usr/bin/env python3
"""Build the three deterministic Phase 1 handoff artifacts from local scan results."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


EXCLUDE_DIRS = {".git", ".idea", "__pycache__", "node_modules", "build", "dist", "out"}
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
TEXT_SUFFIXES = {
    ".java", ".kt", ".kts", ".smali", ".xml", ".json", ".txt", ".properties",
    ".yml", ".yaml", ".ini", ".cfg", ".conf", ".gradle", ".js", ".jsx",
    ".ts", ".tsx", ".html", ".htm", ".vue", ".md",
}
NATIVE_SUFFIXES = {".so", ".dylib", ".dll", ".a"}
MAX_ENTRYPOINT_HITS = 2000


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="Decompiled or unpacked app directory")
    parser.add_argument("--output-dir", required=True, help="Analysis output root")
    parser.add_argument("--max-size-kb", type=int, default=2048, help="Skip files larger than this size")
    parser.add_argument("--analysis-mode", default="local_source", choices=("local_source", "jadx_mcp_session"))
    return parser.parse_args()


def phase_dir(output_dir: Path) -> Path:
    return output_dir if output_dir.name == "step1" else output_dir / "step1"


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def is_excluded(path: Path, root: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in EXCLUDE_DIRS for part in relative_parts)


def walk_files(root: Path, max_size_kb: int) -> tuple[list[dict[str, Any]], list[str]]:
    files: list[dict[str, Any]] = []
    skipped_large: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or is_excluded(path, root):
            continue
        relative = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_size_kb * 1024:
            skipped_large.append(relative)
            continue
        suffix = path.suffix.lower()
        files.append({
            "path": relative,
            "size_bytes": size,
            "extension": suffix or "<none>",
            "is_text_candidate": suffix in TEXT_SUFFIXES,
            "is_native_candidate": suffix in NATIVE_SUFFIXES,
        })
    return files, skipped_large


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_scan_outputs(step: Path) -> dict[str, dict[str, Any]]:
    names = ("raw_endpoints", "raw_secrets", "raw_native_bridges", "raw_env_guards")
    return {name: read_json(step / f"{name}.json") or {} for name in names}


def build_file_inventory(root: Path, files: list[dict[str, Any]], skipped_large: list[str], args: argparse.Namespace) -> dict[str, Any]:
    categories: dict[str, list[str]] = defaultdict(list)
    for item in files:
        suffix = item["extension"]
        if suffix in {".java"}:
            category = "java"
        elif suffix in {".kt", ".kts"}:
            category = "kotlin"
        elif suffix == ".smali":
            category = "smali"
        elif suffix == ".xml":
            category = "xml"
        elif suffix in {".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue"}:
            category = "javascript_h5"
        elif item["is_native_candidate"]:
            category = "native"
        elif suffix in {".json", ".properties", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".gradle"}:
            category = "config"
        else:
            category = "other"
        categories[category].append(item["path"])

    abi_libs: dict[str, list[str]] = defaultdict(list)
    for item in files:
        match = re.search(r"(?:^|/)lib/([^/]+)/([^/]+\.so)$", item["path"], re.IGNORECASE)
        if match:
            abi_libs[match.group(1)].append(match.group(2))

    return {
        "scan_meta": {
            "tool": "phase1_artifact_builder.py",
            "generated_at": utc_now(),
            "target_dir": str(root),
            "file_source": "walk",
            "analysis_mode": args.analysis_mode,
            "max_size_kb": args.max_size_kb,
            "skipped_large_files": skipped_large,
        },
        "analysis_mode": args.analysis_mode,
        "input_mode": "decompiled_or_unpacked_directory",
        "asset_source": "local_filesystem",
        "target_dir": str(root),
        "total_files": len(files),
        "files": files,
        "file_inventory": dict(categories),
        "counts": {key: len(value) for key, value in categories.items()},
        "abi_libs": dict(abi_libs),
        "input_limits": {
            "max_size_kb": args.max_size_kb,
            "skipped_large_file_count": len(skipped_large),
        },
    }


def manifest_metadata(root: Path, files: list[dict[str, Any]]) -> dict[str, Any]:
    manifest_paths = [root / item["path"] for item in files if item["path"].lower().endswith("androidmanifest.xml")]
    metadata: dict[str, Any] = {
        "package_name": "",
        "version_name": "",
        "version_code": "",
        "target_sdk": "",
        "min_sdk": "",
        "permissions": [],
        "components": [],
        "manifest_files": [str(path.relative_to(root).as_posix()) for path in manifest_paths],
    }
    for manifest in manifest_paths:
        try:
            tree = ElementTree.parse(manifest)
            root_node = tree.getroot()
        except (OSError, ElementTree.ParseError):
            continue
        metadata["package_name"] = root_node.attrib.get("package", metadata["package_name"])
        for key, output_key in (
            ("versionName", "version_name"),
            ("versionCode", "version_code"),
            ("targetSdkVersion", "target_sdk"),
            ("minSdkVersion", "min_sdk"),
        ):
            value = root_node.attrib.get(ANDROID_NS + key, "")
            if value:
                metadata[output_key] = value
        for permission in root_node.findall("uses-permission"):
            name = permission.attrib.get(ANDROID_NS + "name", "")
            if name:
                metadata["permissions"].append(name)
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for component in root_node.iter(tag):
                name = component.attrib.get(ANDROID_NS + "name", "")
                if name:
                    metadata["components"].append({
                        "type": tag,
                        "name": name,
                        "exported": component.attrib.get(ANDROID_NS + "exported", ""),
                    })
    metadata["permissions"] = sorted(set(metadata["permissions"]))
    metadata["components"] = sorted(metadata["components"], key=lambda item: (item["type"], item["name"]))
    return metadata


def build_tech_stack(root: Path, files: list[dict[str, Any]], raw_native: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    paths = [item["path"].lower() for item in files]
    path_text = "\n".join(paths)
    sdk_signals = []
    for name, patterns in {
        "webview_or_hybrid": ("webview", "h5", "html", "assets/www"),
        "jni_or_native": (".so", ".smali", "jni", "native"),
        "react_native": ("reactnative", "index.android.bundle"),
        "flutter": ("flutter_assets", "libflutter.so"),
        "weex_or_uniapp": ("weex", "uniapp"),
    }.items():
        if any(pattern in path_text for pattern in patterns):
            sdk_signals.append(name)
    return {
        "scan_meta": {
            "tool": "phase1_artifact_builder.py",
            "generated_at": utc_now(),
            "target_dir": str(root),
            "analysis_mode": args.analysis_mode,
        },
        "manifest": manifest_metadata(root, files),
        "framework_signals": sorted(sdk_signals),
        "features": {
            "webview_or_hybrid": "webview_or_hybrid" in sdk_signals,
            "jni_or_native": "jni_or_native" in sdk_signals or bool(raw_native.get("libraries")),
            "native_libraries_detected": len(raw_native.get("libraries", [])) if isinstance(raw_native.get("libraries", []), list) else 0,
        },
        "third_party_sdk_candidates": [],
        "notes": [
            "This deterministic handoff is a baseline; the Phase 1 Agent may enrich it with MCP context and semantic analysis."
        ],
    }


def hit_list(raw: dict[str, Any]) -> list[dict[str, Any]]:
    value = raw.get("all_hits", [])
    return value if isinstance(value, list) else []


def build_entrypoints(root: Path, scans: dict[str, dict[str, Any]], args: argparse.Namespace) -> dict[str, Any]:
    endpoint_hits = hit_list(scans["raw_endpoints"])
    secret_hits = hit_list(scans["raw_secrets"])
    native_hits = hit_list(scans["raw_native_bridges"])
    guard_hits = hit_list(scans["raw_env_guards"])

    def select(items: list[dict[str, Any]], predicate: Any) -> list[dict[str, Any]]:
        selected = [item for item in items if predicate(item)]
        return selected[:MAX_ENTRYPOINT_HITS]

    crypto_terms = re.compile(r"sign|encrypt|decrypt|cipher|crypto|hash|hmac|token|secret|key|auth|verify", re.I)
    auth_terms = re.compile(r"login|logout|register|auth|token|session|password|captcha|verify", re.I)
    web_terms = re.compile(r"webview|javascript|jsbridge|h5|html", re.I)
    file_terms = re.compile(r"upload|download|file|path|provider|uri", re.I)

    entries = {
        "environment_guards": guard_hits[:MAX_ENTRYPOINT_HITS],
        "hardcoded_findings": secret_hits[:MAX_ENTRYPOINT_HITS],
        "crypto_signature_entries": select(endpoint_hits, lambda item: bool(crypto_terms.search(str(item.get("value", ""))))),
        "auth_entries": select(endpoint_hits, lambda item: bool(auth_terms.search(str(item.get("value", ""))))),
        "jni_native_entries": native_hits[:MAX_ENTRYPOINT_HITS],
        "webview_h5_entries": select(endpoint_hits + native_hits, lambda item: bool(web_terms.search(json.dumps(item, ensure_ascii=False)))),
        "upload_download_file_entries": select(endpoint_hits, lambda item: bool(file_terms.search(str(item.get("value", ""))))),
    }
    total = sum(len(value) for value in entries.values())
    return {
        "scan_meta": {
            "tool": "phase1_artifact_builder.py",
            "generated_at": utc_now(),
            "target_dir": str(root),
            "analysis_mode": args.analysis_mode,
        },
        "coverage": {
            "endpoint_hits": len(endpoint_hits),
            "secret_hits": len(secret_hits),
            "native_hits": len(native_hits),
            "environment_guard_hits": len(guard_hits),
            "entrypoint_records": total,
        },
        "entries": entries,
        "notes": [
            "Entries retain source_file and line when supplied by the raw indexers.",
            "Semantic call-chain enrichment remains the responsibility of agent-01-sample-recon.md.",
        ],
    }


def main() -> int:
    args = parse_args()
    root = Path(args.target_dir).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"Target directory not found: {root}")
    output_root = Path(args.output_dir).expanduser().resolve()
    step = phase_dir(output_root)
    step.mkdir(parents=True, exist_ok=True)

    files, skipped_large = walk_files(root, args.max_size_kb)
    scans = load_scan_outputs(step)
    inventory = build_file_inventory(root, files, skipped_large, args)
    tech_stack = build_tech_stack(root, files, scans["raw_native_bridges"], args)
    entrypoints = build_entrypoints(root, scans, args)

    write_json(step / "file_inventory.json", inventory)
    write_json(step / "tech_stack.json", tech_stack)
    write_json(step / "entrypoints.json", entrypoints)
    print(f"[+] file_inventory.json: {len(files)} files")
    print(f"[+] tech_stack.json: {len(tech_stack['framework_signals'])} framework signals")
    print(f"[+] entrypoints.json: {entrypoints['coverage']['entrypoint_records']} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

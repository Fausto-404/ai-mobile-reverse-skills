#!/usr/bin/env python3
"""Index JNI, native loading, and WebView bridge clues from a decompiled app tree."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TEXT_SUFFIXES = {
    ".java",
    ".kt",
    ".kts",
    ".smali",
    ".xml",
    ".json",
    ".txt",
    ".properties",
    ".yml",
    ".yaml",
    ".js",
    ".html",
    ".htm",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
}

EXCLUDE_DIRS = {"node_modules", ".git", "__pycache__", ".idea", "build", "dist", "out"}

LOAD_LIBRARY_RE = re.compile(r"System\.loadLibrary\(\s*['\"]([^'\"]+)['\"]\s*\)")
LOAD_SO_RE = re.compile(r"System\.load\(\s*['\"]([^'\"]+\.so)['\"]\s*\)")
NATIVE_DECL_RE = re.compile(r"\bnative\s+[A-Za-z0-9_<>\[\].]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
JNI_SYMBOL_RE = re.compile(r"\bJava_[A-Za-z0-9_]+\b")
REGISTER_NATIVES_RE = re.compile(r"\bRegisterNatives\b")
JNI_NATIVE_METHOD_RE = re.compile(r"\bJNINativeMethod\b")
JNI_EXPORT_RE = re.compile(r"\bJNIEXPORT\b|\bJNICALL\b")
JNI_FIND_CLASS_RE = re.compile(r"\bFindClass\b|\bGetMethodID\b|\bGetStaticMethodID\b|\bGetFieldID\b|\bGetStaticFieldID\b")
JNI_CALL_METHOD_RE = re.compile(r"\bCall(?:Object|Void|Boolean|Int|Long|StaticObject|StaticVoid|StaticBoolean|StaticInt|StaticLong)Method\b")
ADD_JS_INTERFACE_RE = re.compile(r"addJavascriptInterface\(\s*[^,]+,\s*['\"]([^'\"]+)['\"]\s*\)")
EVALUATE_JS_RE = re.compile(r"evaluateJavascript\(\s*['\"]([^'\"]+)['\"]")
LOAD_URL_JS_RE = re.compile(r"loadUrl\(\s*['\"](javascript:[^'\"]+)['\"]")
JS_INTERFACE_ANNOTATION_RE = re.compile(r"@JavascriptInterface")
WEBVIEW_ENABLE_JS_RE = re.compile(r"setJavaScriptEnabled\(\s*true\s*\)")
WEBVIEW_CLIENT_RE = re.compile(r"\b(?:WebViewClient|WebChromeClient|shouldOverrideUrlLoading|shouldInterceptRequest|onJsPrompt|onReceivedSslError|onConsoleMessage|postWebMessage|WebMessagePort|addWebMessageListener)\b")
WEBVIEW_RISKY_SETTING_RE = re.compile(r"\b(?:setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|setMixedContentMode|setWebContentsDebuggingEnabled)\b")
BRIDGE_LIBRARY_RE = re.compile(r"\b(?:WebViewJavascriptBridge|dsBridge|JSBridge|BridgeWebView|registerHandler|callHandler|JsBridge|BridgeHandler|invokeHandler|postMessage)\b")
NATIVE_CRYPTO_SYMBOL_RE = re.compile(
    r"\b(?:EVP_(?:Encrypt|Decrypt|Cipher|Digest|PKEY|MD|sha|aes)[A-Za-z0-9_]*|AES_[A-Za-z0-9_]+|RSA_[A-Za-z0-9_]+|HMAC(?:_[A-Za-z0-9_]+)?|SHA(?:1|224|256|384|512)|MD5(?:_[A-Za-z0-9_]+)?|SM[234]_[A-Za-z0-9_]+|PKCS5_PBKDF2_HMAC|RAND_bytes)\b"
)
NATIVE_CRYPTO_LIBRARY_RE = re.compile(r"\b(?:libssl\.so|libcrypto\.so|openssl|boringssl|mbedtls|wolfssl|gmssl)\b", re.IGNORECASE)
JAVA_CRYPTO_BRIDGE_RE = re.compile(
    r"\b(?:Cipher\.getInstance|MessageDigest\.getInstance|Mac\.getInstance|Signature\.getInstance|SecretKeySpec|IvParameterSpec|KeyStore\.getInstance|getInstance\(['\"]AndroidKeyStore['\"]|Base64\.(?:encode|decode)|encodeToString|decode)\b"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="Decompiled target directory")
    parser.add_argument("--output-dir", required=True, help="Analysis output root; raw_native_bridges.json is written to step1/ by default")
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
    hit_type: str,
    value: str,
    line_no: int,
    context: str,
    source_file: str,
    pattern: str,
) -> None:
    key = (source_file, hit_type, line_no, value)
    if key in seen:
        return
    seen.add(key)
    hits.append(
        {
            "type": hit_type,
            "value": value,
            "line": line_no,
            "context": context[:600],
            "source_file": source_file,
            "pattern": pattern,
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

        for match in LOAD_LIBRARY_RE.finditer(line):
            add_hit(hits, seen, "load_library", match.group(1), line_no, context, rel_path, "LOAD_LIBRARY_RE")
        for match in LOAD_SO_RE.finditer(line):
            add_hit(hits, seen, "load_so", match.group(1), line_no, context, rel_path, "LOAD_SO_RE")
        for match in NATIVE_DECL_RE.finditer(line):
            add_hit(hits, seen, "native_method", match.group(1), line_no, context, rel_path, "NATIVE_DECL_RE")
        for match in JNI_SYMBOL_RE.finditer(line):
            add_hit(hits, seen, "jni_symbol", match.group(0), line_no, context, rel_path, "JNI_SYMBOL_RE")
        if REGISTER_NATIVES_RE.search(line):
            add_hit(hits, seen, "register_natives", "RegisterNatives", line_no, context, rel_path, "REGISTER_NATIVES_RE")
        if JNI_NATIVE_METHOD_RE.search(line):
            add_hit(hits, seen, "jni_native_method_struct", "JNINativeMethod", line_no, context, rel_path, "JNI_NATIVE_METHOD_RE")
        if JNI_EXPORT_RE.search(line):
            add_hit(hits, seen, "jni_export_marker", stripped[:160], line_no, context, rel_path, "JNI_EXPORT_RE")
        if JNI_FIND_CLASS_RE.search(line):
            add_hit(hits, seen, "jni_lookup_api", stripped[:160], line_no, context, rel_path, "JNI_FIND_CLASS_RE")
        if JNI_CALL_METHOD_RE.search(line):
            add_hit(hits, seen, "jni_call_api", stripped[:160], line_no, context, rel_path, "JNI_CALL_METHOD_RE")
        for match in ADD_JS_INTERFACE_RE.finditer(line):
            add_hit(hits, seen, "add_javascript_interface", match.group(1), line_no, context, rel_path, "ADD_JS_INTERFACE_RE")
        for match in EVALUATE_JS_RE.finditer(line):
            add_hit(hits, seen, "evaluate_javascript", match.group(1), line_no, context, rel_path, "EVALUATE_JS_RE")
        for match in LOAD_URL_JS_RE.finditer(line):
            add_hit(hits, seen, "load_url_javascript", match.group(1), line_no, context, rel_path, "LOAD_URL_JS_RE")
        if JS_INTERFACE_ANNOTATION_RE.search(line):
            add_hit(hits, seen, "javascript_interface_annotation", "@JavascriptInterface", line_no, context, rel_path, "JS_INTERFACE_ANNOTATION_RE")
        if WEBVIEW_ENABLE_JS_RE.search(line):
            add_hit(hits, seen, "webview_javascript_enabled", "setJavaScriptEnabled(true)", line_no, context, rel_path, "WEBVIEW_ENABLE_JS_RE")
        if WEBVIEW_CLIENT_RE.search(line):
            add_hit(hits, seen, "webview_hook_point", stripped[:160], line_no, context, rel_path, "WEBVIEW_CLIENT_RE")
        if WEBVIEW_RISKY_SETTING_RE.search(line):
            add_hit(hits, seen, "webview_risky_setting", stripped[:160], line_no, context, rel_path, "WEBVIEW_RISKY_SETTING_RE")
        if BRIDGE_LIBRARY_RE.search(line):
            add_hit(hits, seen, "bridge_library_marker", stripped[:160], line_no, context, rel_path, "BRIDGE_LIBRARY_RE")
        if NATIVE_CRYPTO_SYMBOL_RE.search(line):
            add_hit(hits, seen, "native_crypto_symbol", stripped[:200], line_no, context, rel_path, "NATIVE_CRYPTO_SYMBOL_RE")
        if NATIVE_CRYPTO_LIBRARY_RE.search(line):
            add_hit(hits, seen, "native_crypto_library", stripped[:200], line_no, context, rel_path, "NATIVE_CRYPTO_LIBRARY_RE")
        if JAVA_CRYPTO_BRIDGE_RE.search(line):
            add_hit(hits, seen, "java_crypto_bridge", stripped[:200], line_no, context, rel_path, "JAVA_CRYPTO_BRIDGE_RE")

    return hits


def summarize_libraries(all_hits: list[dict]) -> list[dict]:
    libraries: dict[str, dict] = {}
    for hit in all_hits:
        if hit["type"] not in {"load_library", "load_so"}:
            continue
        key = hit["value"]
        libraries.setdefault(key, {"library": key, "occurrences": []})
        libraries[key]["occurrences"].append(
            {
                "source_file": hit["source_file"],
                "source_line": hit["line"],
                "type": hit["type"],
            }
        )
    return sorted(libraries.values(), key=lambda item: item["library"])


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_dir = resolve_phase_output_dir(output_root, "step1")
    output_dir.mkdir(parents=True, exist_ok=True)

    by_file: dict[str, dict] = {}
    all_hits: list[dict] = []
    type_counter: Counter[str] = Counter()
    skipped_large_files: list[str] = []
    scanned_files = 0

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
            type_counter[hit["type"]] += 1

    result = {
        "scan_meta": {
            "tool": "native_bridge_indexer.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_dir": str(target_dir),
            "file_source": file_source,
            "inventory_path": args.inventory,
            "max_size_kb": args.max_size_kb,
            "total_text_files_scanned": scanned_files,
            "skipped_large_files": skipped_large_files,
        },
        "total_hits": len(all_hits),
        "type_statistics": dict(type_counter),
        "libraries": summarize_libraries(all_hits),
        "by_file": by_file,
        "all_hits": all_hits,
    }

    output_path = output_dir / "raw_native_bridges.json"
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

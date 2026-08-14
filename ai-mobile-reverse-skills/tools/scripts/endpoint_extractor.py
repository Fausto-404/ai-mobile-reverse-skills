#!/usr/bin/env python3
"""Extract endpoint, URL, request-wrapper, and protocol clues from a decompiled mobile app tree."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCAN_EXTENSIONS = {
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
    ".ini",
    ".cfg",
    ".conf",
    ".gradle",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".htm",
    ".vue",
}

EXCLUDE_DIRS = {"node_modules", ".git", "__pycache__", ".idea", "build", "dist", "out"}
IGNORE_PATH_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".css",
    ".ico",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
}

RE_FULL_HTTP = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
RE_FULL_WS = re.compile(r"wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
RE_BASEURL = re.compile(
    r"(?:baseURL|baseUrl|BASE_URL|base_url|apiHost|apiBaseUrl|serverUrl|host|HOST|domain|DOMAIN|server|SERVER)\s*[:=]\s*['\"]([^'\"\n]+)['\"]",
    re.IGNORECASE,
)
RE_BASEURL_BUILDER = re.compile(r"\bbaseUrl\s*\(\s*['\"]([^'\"\n]+)['\"]\s*\)")
RE_ENV_URL = re.compile(
    r"(?:dev|test|prod|production|staging|uat|sit|pre|release|online)\s*[:=]\s*['\"](https?://[^'\"\n]+)['\"]",
    re.IGNORECASE,
)
RE_RETROFIT = re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\((['\"])(.+?)\2\)")
RE_PATH_FRAGMENT = re.compile(
    r"(?:['\"`])(\/(?:api|v[0-9]+|rest|service|gateway|auth|user|order|pay|config|upload|download)[A-Za-z0-9_./{}-]*)(?:['\"`])"
)
RE_GENERIC_PATH = re.compile(r"(?:['\"`])((?:\/[A-Za-z][A-Za-z0-9_-]+){2,})(?:['\"`])")
RE_NO_SLASH_API = re.compile(
    r"(?:['\"`])((?:api|rest|service|gateway|auth|user|order|pay|v[0-9]+)/[A-Za-z0-9_./{}-]+)(?:['\"`])"
)
RE_BUSINESS_PATH = re.compile(
    r"(?:['\"`])(\/(?:login|logout|register|user|order|pay|cart|goods|product|member|coupon|sms|captcha|auth|upload|download|config|query|list|detail)[A-Za-z0-9_./{}-]*)(?:['\"`])",
    re.IGNORECASE,
)
RE_PROTOCOL_RELATIVE = re.compile(r"(?:['\"`])(//[A-Za-z0-9.-]+(?:/[^\s'\"`]*)?)(?:['\"`])")
RE_AXIOS = re.compile(r"axios\s*\.\s*(?:get|post|put|delete|patch|request|head|options)\s*\(\s*['\"]([^'\"\n]+)['\"]")
RE_FETCH = re.compile(r"fetch\s*\(\s*['\"]([^'\"\n]+)['\"]")
RE_XHR_OPEN = re.compile(r"\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"\n]+)['\"]", re.IGNORECASE)
RE_METHOD_CALL = re.compile(r"(?:request|http|service|api|ajax|client)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"\n]+)['\"]", re.IGNORECASE)
RE_FUNC_CALL = re.compile(
    r"(?:request|http|service|api|fetchApi|doRequest)\s*\(\s*(?:\{[^}]*url\s*:\s*['\"]([^'\"\n]+)['\"]|['\"]([^'\"\n]+)['\"])",
    re.DOTALL,
)
RE_REQUEST_URL_PROP = re.compile(r"\burl\s*[:=]\s*['\"]([^'\"\n]+)['\"]")
RE_URI_PARSE = re.compile(r"Uri\.parse\(\s*['\"]([^'\"\n]+)['\"]\s*\)")
RE_CONTENT_URI = re.compile(r"content://[A-Za-z0-9._/\-]+", re.IGNORECASE)
RE_WEBVIEW_SRC = re.compile(r"<web-view[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_GRAPHQL_ENDPOINT = re.compile(r"['\"]([^'\"\n]*graphql[^'\"\n]*)['\"]", re.IGNORECASE)
RE_SOCKET_URL_VAR = re.compile(r"(?i)socket[_-]?url\s*[:=]\s*['\"]([^'\"]+)['\"]")
RE_MQTT_URL = re.compile(r"(?:tcp|ssl|mqtt|mqtts)://[A-Za-z0-9._:/?#@!$&'()*+,;=%-]+", re.IGNORECASE)
RE_HEADER_KEY = re.compile(r"['\"](Authorization|token|sign|sig|timestamp|nonce|deviceId|session|encryptData|data)['\"]")
RE_CRYPTO_FIELD_KEY = re.compile(
    r"['\"](sign|sig|signature|data|encryptData|ciphertext|payload|token|timestamp|nonce|salt|iv|hmac|mac|secretKey)['\"]",
    re.IGNORECASE,
)
RE_WRAPPER_DEF = re.compile(
    r"(?:Retrofit\.Builder|OkHttpClient|Request\.Builder|Interceptor|fetch\(|XMLHttpRequest|axios\.|WebSocket\(|shouldInterceptRequest|shouldOverrideUrlLoading)"
)
RE_CRYPTO_WRAPPER = re.compile(
    r"\b(?:Cipher\.getInstance|MessageDigest\.getInstance|Mac\.getInstance|Signature\.getInstance|SecretKeySpec|IvParameterSpec|KeyGenerator|KeyPairGenerator|KeyStore|getInstance\(['\"]AndroidKeyStore['\"]|CryptoJS\.|JSEncrypt|sm2|sm3|sm4|HmacSHA256|HmacSHA1|PBKDF2|Base64\.(?:encode|decode)|encodeToString|decode)\b"
)
RE_WEBSOCKET = re.compile(r"WebSocket\s*\(\s*['\"]([^'\"\n]+)['\"]")
RE_OKHTTP_URL = re.compile(r"\burl\s*\(\s*['\"]([^'\"\n]+)['\"]\s*\)")
RE_UPLOAD_CALL = re.compile(r"upload(?:File)?\s*\(\s*(?:\{[^}]*url\s*:\s*['\"]([^'\"\n]+)['\"]|['\"]([^'\"\n]+)['\"])", re.IGNORECASE | re.DOTALL)
RE_DOWNLOAD_CALL = re.compile(r"download(?:File)?\s*\(\s*(?:\{[^}]*url\s*:\s*['\"]([^'\"\n]+)['\"]|['\"]([^'\"\n]+)['\"])", re.IGNORECASE | re.DOTALL)
RE_MANIFEST_SCHEME = re.compile(r"android:scheme\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_MANIFEST_HOST = re.compile(r"android:host\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_MANIFEST_PORT = re.compile(r"android:port\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_MANIFEST_PATH = re.compile(r"android:(?:path|pathPrefix|pathPattern)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_PROVIDER_AUTHORITIES = re.compile(r"android:authorities\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_NETWORK_SECURITY_CONFIG = re.compile(r"android:networkSecurityConfig\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_MANIFEST_EXPORTS = re.compile(r"<(?:activity|service|receiver|provider)[^>]+android:exported\s*=\s*['\"]true['\"][^>]*android:name\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_MANIFEST_BROWSABLE = re.compile(r"<category[^>]+android:name\s*=\s*['\"]android\.intent\.category\.BROWSABLE['\"]", re.IGNORECASE)

EXCLUDE_URL_PATTERNS = [
    re.compile(r"\.(?:png|jpg|jpeg|gif|svg|ico|webp|bmp|css|map|woff2?|ttf|eot)(?:\?|$)", re.IGNORECASE),
    re.compile(r"(?:registry\.npmjs\.org|unpkg\.com|cdn\.jsdelivr\.net|github\.com|mozilla\.org)", re.IGNORECASE),
    re.compile(r"(?:example\.com|127\.0\.0\.1|localhost)", re.IGNORECASE),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="Decompiled app directory")
    parser.add_argument("--output-dir", required=True, help="Analysis output root; raw_endpoints.json is written to step1/ by default")
    parser.add_argument("--inventory", help="Optional file_inventory.json path")
    parser.add_argument("--max-size-kb", type=int, default=2048, help="Skip files larger than this size")
    return parser.parse_args()


def resolve_phase_output_dir(output_dir: Path, phase_dir: str) -> Path:
    return output_dir if output_dir.name == phase_dir else output_dir / phase_dir


def is_excluded_dir(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return any(part in EXCLUDE_DIRS for part in parts)


def should_scan(path: Path, max_size_kb: int) -> bool:
    if path.suffix.lower() not in SCAN_EXTENSIONS and path.name != "AndroidManifest.xml":
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


def should_exclude_url(url: str) -> bool:
    return any(pattern.search(url) for pattern in EXCLUDE_URL_PATTERNS)


def clean_value(value: str) -> str:
    return value.rstrip("',\");>} ]\\").strip()


def normalize_path(value: str) -> str | None:
    value = clean_value(value)
    if not value:
        return None
    if not value.startswith("/"):
        value = f"/{value}"
    lowered = value.lower()
    if value in {"/", "//"}:
        return None
    if value.startswith("/pages/") or value.startswith("/components/") or value.startswith("/assets/"):
        return None
    for suffix in IGNORE_PATH_SUFFIXES:
        if lowered.endswith(suffix):
            return None
    return value


def get_context(lines: list[str], line_idx: int, before: int = 1, after: int = 1) -> str:
    start = max(0, line_idx - before)
    end = min(len(lines), line_idx + after + 1)
    ctx_lines = []
    for idx in range(start, end):
        prefix = ">>> " if idx == line_idx else "    "
        ctx_lines.append(f"{prefix}{idx + 1}: {lines[idx].rstrip()}")
    return "\n".join(ctx_lines)


def add_hit(
    store: list[dict],
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
    store.append(
        {
            "type": hit_type,
            "value": value,
            "line": line_no,
            "context": context,
            "source_file": source_file,
            "pattern": pattern,
        }
    )


def add_content_hits(
    content: str,
    lines: list[str],
    rel_path: str,
    hits: list[dict],
    seen: set[tuple],
    hit_type: str,
    pattern: re.Pattern[str],
    path_like: bool = False,
    skip_excluded_url: bool = False,
) -> None:
    for match in pattern.finditer(content):
        value = next((group for group in match.groups() if group), match.group(0))
        value = clean_value(value)
        if path_like:
            normalized = normalize_path(value)
            if not normalized:
                continue
            value = normalized
        if skip_excluded_url and should_exclude_url(value):
            continue
        line_idx = content[: match.start()].count("\n")
        add_hit(hits, seen, hit_type, value, line_idx + 1, get_context(lines, line_idx), rel_path, pattern.pattern[:120])


def extract_from_file(path: Path, rel_path: str) -> list[dict]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    if not content.strip():
        return []

    lines = content.splitlines()
    hits: list[dict] = []
    seen: set[tuple] = set()

    add_content_hits(content, lines, rel_path, hits, seen, "full_url", RE_FULL_HTTP, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "websocket_url", RE_FULL_WS, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "base_url", RE_BASEURL, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "base_url_builder", RE_BASEURL_BUILDER, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "env_url", RE_ENV_URL, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "path_fragment", RE_PATH_FRAGMENT, path_like=True)
    add_content_hits(content, lines, rel_path, hits, seen, "generic_path", RE_GENERIC_PATH, path_like=True)
    add_content_hits(content, lines, rel_path, hits, seen, "business_path", RE_BUSINESS_PATH, path_like=True)
    add_content_hits(content, lines, rel_path, hits, seen, "no_slash_api_path", RE_NO_SLASH_API, path_like=True)
    add_content_hits(content, lines, rel_path, hits, seen, "protocol_relative_url", RE_PROTOCOL_RELATIVE, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "axios_call", RE_AXIOS, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "fetch_call", RE_FETCH, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "xhr_open", RE_XHR_OPEN, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "method_call", RE_METHOD_CALL, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "request_url_property", RE_REQUEST_URL_PROP, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "uri_parse", RE_URI_PARSE, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "content_uri", RE_CONTENT_URI)
    add_content_hits(content, lines, rel_path, hits, seen, "webview_src", RE_WEBVIEW_SRC, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "graphql_endpoint", RE_GRAPHQL_ENDPOINT, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "socket_url_var", RE_SOCKET_URL_VAR, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "mqtt_url", RE_MQTT_URL, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "websocket_constructor", RE_WEBSOCKET, skip_excluded_url=True)
    add_content_hits(content, lines, rel_path, hits, seen, "okhttp_url", RE_OKHTTP_URL, skip_excluded_url=True)

    if path.name == "AndroidManifest.xml":
        add_content_hits(content, lines, rel_path, hits, seen, "deeplink_scheme", RE_MANIFEST_SCHEME)
        add_content_hits(content, lines, rel_path, hits, seen, "deeplink_host", RE_MANIFEST_HOST)
        add_content_hits(content, lines, rel_path, hits, seen, "deeplink_port", RE_MANIFEST_PORT)
        add_content_hits(content, lines, rel_path, hits, seen, "deeplink_path", RE_MANIFEST_PATH, path_like=True)
        add_content_hits(content, lines, rel_path, hits, seen, "provider_authority", RE_PROVIDER_AUTHORITIES)
        add_content_hits(content, lines, rel_path, hits, seen, "network_security_config", RE_NETWORK_SECURITY_CONFIG)
        add_content_hits(content, lines, rel_path, hits, seen, "exported_component", RE_MANIFEST_EXPORTS)
        add_content_hits(content, lines, rel_path, hits, seen, "browsable_category", RE_MANIFEST_BROWSABLE)

    for pattern, hit_type in ((RE_UPLOAD_CALL, "upload_call"), (RE_DOWNLOAD_CALL, "download_call")):
        for match in pattern.finditer(content):
            value = match.group(1) or match.group(2)
            if not value:
                continue
            value = clean_value(value)
            if should_exclude_url(value):
                continue
            line_idx = content[: match.start()].count("\n")
            add_hit(hits, seen, hit_type, value, line_idx + 1, get_context(lines, line_idx, after=2), rel_path, pattern.pattern[:120])

    for match in RE_RETROFIT.finditer(content):
        method = match.group(1)
        path_value = normalize_path(match.group(3)) or clean_value(match.group(3))
        line_idx = content[: match.start()].count("\n")
        add_hit(
            hits,
            seen,
            "retrofit_annotation",
            f"{method} {path_value}",
            line_idx + 1,
            get_context(lines, line_idx),
            rel_path,
            "RE_RETROFIT",
        )

    for match in RE_FUNC_CALL.finditer(content):
        value = match.group(1) or match.group(2)
        if not value:
            continue
        value = clean_value(value)
        if should_exclude_url(value):
            continue
        line_idx = content[: match.start()].count("\n")
        add_hit(hits, seen, "function_call_url", value, line_idx + 1, get_context(lines, line_idx), rel_path, "RE_FUNC_CALL")

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if RE_WRAPPER_DEF.search(line):
            add_hit(hits, seen, "request_wrapper_def", stripped[:160], line_idx + 1, get_context(lines, line_idx), rel_path, "RE_WRAPPER_DEF")
        for match in RE_HEADER_KEY.finditer(line):
            add_hit(hits, seen, "header_key", match.group(1), line_idx + 1, get_context(lines, line_idx), rel_path, "RE_HEADER_KEY")
        for match in RE_CRYPTO_FIELD_KEY.finditer(line):
            add_hit(hits, seen, "crypto_field_key", match.group(1), line_idx + 1, get_context(lines, line_idx), rel_path, "RE_CRYPTO_FIELD_KEY")
        if RE_CRYPTO_WRAPPER.search(line):
            add_hit(hits, seen, "crypto_wrapper_hint", stripped[:200], line_idx + 1, get_context(lines, line_idx), rel_path, "RE_CRYPTO_WRAPPER")

    return hits


def build_base_url_candidates(all_hits: list[dict]) -> list[dict]:
    candidates: dict[tuple[str, str, int], dict] = {}
    for hit in all_hits:
        if hit["type"] not in {"full_url", "base_url", "env_url", "protocol_relative_url"}:
            continue
        value = hit["value"]
        if hit["type"] == "protocol_relative_url":
            value = f"https:{value}"
        parts = urlsplit(value)
        if not parts.netloc:
            continue
        base_value = f"{parts.scheme or 'https'}://{parts.netloc}"
        key = (base_value, hit["source_file"], hit["line"])
        candidates[key] = {
            "value": base_value,
            "source_file": hit["source_file"],
            "source_line": hit["line"],
            "reason": hit["type"],
        }
    return sorted(candidates.values(), key=lambda item: (item["value"], item["source_file"], item["source_line"]))


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
        file_hits = extract_from_file(path, rel_path)
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
            "tool": "endpoint_extractor.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_dir": str(target_dir),
            "file_source": file_source,
            "inventory_path": args.inventory,
            "max_size_kb": args.max_size_kb,
            "total_files_scanned": scanned_files,
            "skipped_large_files": skipped_large_files,
        },
        "total_raw_hits": len(all_hits),
        "type_statistics": dict(type_counter),
        "base_url_candidates": build_base_url_candidates(all_hits),
        "by_file": by_file,
        "all_hits": all_hits,
    }

    output_path = output_dir / "raw_endpoints.json"
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

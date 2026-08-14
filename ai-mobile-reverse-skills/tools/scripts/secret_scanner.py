#!/usr/bin/env python3
"""Scan a decompiled mobile app tree for hardcoded secrets and sensitive configuration."""

from __future__ import annotations

import argparse
import json
import os
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
    ".ini",
    ".cfg",
    ".conf",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".htm",
    ".vue",
    ".gradle",
    ".md",
    ".log",
}

CERT_SUFFIXES = {
    ".jks": ("certificate_material", "jks_file", "Critical"),
    ".bks": ("certificate_material", "bks_file", "Critical"),
    ".p12": ("certificate_material", "p12_file", "Critical"),
    ".keystore": ("certificate_material", "keystore_file", "Critical"),
    ".pem": ("certificate_material", "pem_file", "High"),
    ".cer": ("certificate_material", "cer_file", "High"),
    ".crt": ("certificate_material", "crt_file", "High"),
    ".der": ("certificate_material", "der_file", "High"),
    ".key": ("certificate_material", "key_file", "Critical"),
    ".pfx": ("certificate_material", "pfx_file", "Critical"),
    ".env": ("config_material", "env_file", "High"),
}

EXCLUDE_DIRS = {
    ".git",
    ".idea",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    "out",
}

PLACEHOLDER_PATTERNS = [
    re.compile(r"^x{3,}$", re.IGNORECASE),
    re.compile(r"^test", re.IGNORECASE),
    re.compile(r"^demo", re.IGNORECASE),
    re.compile(r"^sample", re.IGNORECASE),
    re.compile(r"^example", re.IGNORECASE),
    re.compile(r"^placeholder", re.IGNORECASE),
    re.compile(r"^your[_-]?", re.IGNORECASE),
    re.compile(r"change[_-]?me", re.IGNORECASE),
    re.compile(r"replace[_-]?me", re.IGNORECASE),
    re.compile(r"^fake", re.IGNORECASE),
    re.compile(r"^dummy", re.IGNORECASE),
    re.compile(r"^null$", re.IGNORECASE),
    re.compile(r"^none$", re.IGNORECASE),
]

KNOWN_TEST_VALUES = {
    "13800138000",
    "13800000000",
    "18888888888",
    "test@test.com",
    "test@example.com",
    "admin@admin.com",
    "000000000000000000",
    "111111111111111111",
    "123456",
    "12345678",
    "1234567890",
    "abcdefg",
    "abcdefgh",
}

SCAN_RULES = [
    (
        "wechat",
        "wechat_appid",
        re.compile(r"\bwx[a-f0-9]{16}\b", re.IGNORECASE),
        "Medium",
        None,
        0,
    ),
    (
        "wechat",
        "wechat_appsecret",
        re.compile(r"(?i)(?:appsecret|wechat[_-]?secret|wx[_-]?secret)\s*[:=]\s*['\"]([a-f0-9]{32})['\"]"),
        "Critical",
        None,
        1,
    ),
    (
        "wechat",
        "wechat_mchid",
        re.compile(r"(?i)(?:mch_?id|merchant_?id)\s*[:=]\s*['\"]([0-9]{7,12})['\"]"),
        "High",
        ["pay", "wechat", "wxpay", "payment", "微信支付"],
        1,
    ),
    (
        "wechat",
        "wechat_pay_key",
        re.compile(r"(?i)(?:mch_?key|pay_?key|api_?key)\s*[:=]\s*['\"]([A-Za-z0-9]{24,64})['\"]"),
        "Critical",
        ["pay", "wechat", "wxpay", "payment", "微信支付"],
        1,
    ),
    (
        "secret",
        "app_secret_assignment",
        re.compile(
            r"(?i)(?:app[_-]?secret|client[_-]?secret|secret[_-]?key|access[_-]?secret)\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"
        ),
        "Critical",
        None,
        1,
    ),
    (
        "crypto_material",
        "hmac_key_assignment",
        re.compile(r"(?i)(?:hmac[_-]?key|mac[_-]?key|sign[_-]?key|signature[_-]?key)\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"),
        "Critical",
        ["hmac", "mac", "sign", "signature", "encrypt", "crypto"],
        1,
    ),
    (
        "crypto_material",
        "aes_key_assignment",
        re.compile(r"(?i)(?:aes[_-]?key|des[_-]?key|sm4[_-]?key|secretkeyspec)\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"),
        "Critical",
        ["aes", "des", "sm4", "cipher", "encrypt", "decrypt"],
        1,
    ),
    (
        "crypto_material",
        "iv_assignment",
        re.compile(r"(?i)(?:iv|init(?:ialization)?[_-]?vector)\s*[:=]\s*['\"]([^'\"\n]{4,})['\"]"),
        "High",
        ["aes", "cbc", "gcm", "cipher", "encrypt", "decrypt", "ivparameter"],
        1,
    ),
    (
        "crypto_material",
        "salt_assignment",
        re.compile(r"(?i)(?:salt|nonce|aad)\s*[:=]\s*['\"]([^'\"\n]{4,})['\"]"),
        "Medium",
        ["sign", "encrypt", "pbkdf2", "hkdf", "gcm", "hmac", "aes"],
        1,
    ),
    (
        "crypto_material",
        "android_keystore_alias",
        re.compile(r"(?i)(?:androidkeystore|keystore|key[_-]?alias|alias)\s*[:=]\s*['\"]([^'\"\n]{3,})['\"]"),
        "Medium",
        ["androidkeystore", "keystore", "keygenparameter", "keygenerator", "keystore.getinstance"],
        1,
    ),
    (
        "crypto_material",
        "pem_inline_key_name",
        re.compile(r"(?i)(?:public[_-]?key|private[_-]?key|rsa[_-]?key|sm2[_-]?key)\s*[:=]\s*['\"]([^'\"\n]{16,})['\"]"),
        "High",
        ["rsa", "sm2", "keyfactory", "publickey", "privatekey", "keystore"],
        1,
    ),
    (
        "api_key",
        "api_key_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|app[_-]?key|client[_-]?key|access[_-]?key|ak|sk)\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"
        ),
        "High",
        None,
        1,
    ),
    (
        "token",
        "token_assignment",
        re.compile(
            r"(?i)(?:token|auth[_-]?token|authorization|session[_-]?token|refresh[_-]?token|id[_-]?token)\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"
        ),
        "High",
        None,
        1,
    ),
    (
        "credential",
        "password_assignment",
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\n]{3,})['\"]"),
        "High",
        None,
        1,
    ),
    (
        "jwt",
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"),
        "High",
        None,
        0,
    ),
    (
        "private_key",
        "pem_private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        "Critical",
        None,
        0,
    ),
    (
        "public_key",
        "pem_public_key",
        re.compile(r"-----BEGIN PUBLIC KEY-----"),
        "Medium",
        None,
        0,
    ),
    (
        "certificate",
        "pem_certificate",
        re.compile(r"-----BEGIN CERTIFICATE-----"),
        "Medium",
        None,
        0,
    ),
    (
        "cloud_key",
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Critical",
        None,
        0,
    ),
    (
        "cloud_key",
        "tencent_access_key",
        re.compile(r"AKID[0-9A-Za-z]{13,20}"),
        "Critical",
        None,
        0,
    ),
    (
        "cloud_key",
        "aliyun_access_key",
        re.compile(r"LTAI[0-9A-Za-z]{12,20}"),
        "Critical",
        None,
        0,
    ),
    (
        "cloud_key",
        "firebase_api_key",
        re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
        "Critical",
        None,
        0,
    ),
    (
        "cloud_key",
        "aws_secret_key",
        re.compile(r"(?i)(?:aws[_-]?secret|secretaccesskey)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{32,48})['\"]"),
        "Critical",
        ["aws", "s3", "amazon"],
        1,
    ),
    (
        "cloud_key",
        "azure_storage_conn",
        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+", re.IGNORECASE),
        "Critical",
        None,
        0,
    ),
    (
        "cloud_key",
        "azure_sas_token",
        re.compile(r"sv=[^&\s]+&ss=[^&\s]+&srt=[^&\s]+&sp=[^&\s]+&se=[^&\s]+&sig=[^\s'\"`]+", re.IGNORECASE),
        "Critical",
        None,
        0,
    ),
    (
        "cloud_key",
        "gcp_service_account",
        re.compile(r"\"type\"\s*:\s*\"service_account\""),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "github_token",
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}"),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "slack_token",
        re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "stripe_key",
        re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"),
        "High",
        None,
        0,
    ),
    (
        "third_party",
        "gitlab_token",
        re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "sendgrid_key",
        re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}"),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "telegram_bot_token",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "twilio_sid",
        re.compile(r"\bAC[a-f0-9]{32}\b", re.IGNORECASE),
        "Critical",
        None,
        0,
    ),
    (
        "third_party",
        "sentry_dsn",
        re.compile(r"https://[A-Za-z0-9]+@[A-Za-z0-9.-]+/\d+"),
        "High",
        None,
        0,
    ),
    (
        "third_party",
        "oauth_client_secret",
        re.compile(r"(?i)(?:oauth[_-]?client[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"]([^'\"\n]{10,})['\"]"),
        "High",
        ["oauth", "openid", "oidc", "auth"],
        1,
    ),
    (
        "china_service",
        "dingtalk_appkey_or_secret",
        re.compile(r"(?i)(?:ding[_-]?(?:app[_-]?key|app[_-]?secret)|dingtalk[_-]?(?:app[_-]?key|app[_-]?secret))\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"),
        "High",
        None,
        1,
    ),
    (
        "china_service",
        "feishu_appid_or_secret",
        re.compile(r"(?i)(?:feishu[_-]?(?:app[_-]?id|app[_-]?secret)|lark[_-]?(?:app[_-]?id|app[_-]?secret))\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"),
        "High",
        None,
        1,
    ),
    (
        "china_service",
        "wecom_corpsecret",
        re.compile(r"(?i)(?:corp[_-]?secret|wecom[_-]?secret)\s*[:=]\s*['\"]([^'\"\n]{16,})['\"]"),
        "High",
        ["wecom", "wework", "企微", "企业微信"],
        1,
    ),
    (
        "china_service",
        "alipay_appid",
        re.compile(r"\b2088[0-9]{12}\b"),
        "Medium",
        ["alipay", "支付宝", "payment", "pay"],
        0,
    ),
    (
        "china_service",
        "map_key",
        re.compile(r"(?i)(?:amap|gaode|tencent[_-]?map|qq[_-]?map|baidu[_-]?map)[_-]?(?:key|ak)\s*[:=]\s*['\"]([^'\"\n]{8,})['\"]"),
        "Medium",
        None,
        1,
    ),
    (
        "webhook",
        "dingtalk_webhook",
        re.compile(r"https://oapi\.dingtalk\.com/robot/send\?access_token=[A-Za-z0-9]{32,}"),
        "High",
        None,
        0,
    ),
    (
        "webhook",
        "feishu_webhook",
        re.compile(r"https://open\.feishu\.cn/open-apis/bot/v2/hook/[A-Za-z0-9-]{20,}"),
        "High",
        None,
        0,
    ),
    (
        "database",
        "jdbc_connection",
        re.compile(r"jdbc:[a-z0-9]+://[^\s'\"`]+", re.IGNORECASE),
        "Critical",
        None,
        0,
    ),
    (
        "database",
        "mongodb_connection",
        re.compile(r"mongodb(?:\+srv)?://[^\s'\"`]+", re.IGNORECASE),
        "Critical",
        None,
        0,
    ),
    (
        "database",
        "redis_connection",
        re.compile(r"redis://[^\s'\"`]+", re.IGNORECASE),
        "High",
        None,
        0,
    ),
    (
        "database",
        "postgres_connection",
        re.compile(r"postgres(?:ql)?://[^\s'\"`]+", re.IGNORECASE),
        "Critical",
        None,
        0,
    ),
    (
        "database",
        "ftp_connection",
        re.compile(r"ftp://[^\s'\"`]+", re.IGNORECASE),
        "High",
        None,
        0,
    ),
    (
        "database",
        "ldap_connection",
        re.compile(r"ldaps?://[^\s'\"`]+", re.IGNORECASE),
        "High",
        None,
        0,
    ),
    (
        "database",
        "amqp_connection",
        re.compile(r"amqps?://[^\s'\"`]+", re.IGNORECASE),
        "High",
        None,
        0,
    ),
    (
        "database",
        "smtp_config",
        re.compile(r"(?i)(?:smtp[_.]?(?:host|server|addr)|mail[_-]?host)\s*[:=]\s*['\"]([^'\"\n]+)['\"]"),
        "Medium",
        None,
        1,
    ),
    (
        "internal_address",
        "private_ip",
        re.compile(
            r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b"
        ),
        "Medium",
        None,
        0,
    ),
    (
        "internal_address",
        "internal_domain",
        re.compile(r"\b[a-zA-Z0-9.-]+\.(?:local|lan|internal|corp|intranet)\b"),
        "High",
        None,
        0,
    ),
    (
        "infra",
        "ip_with_port",
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b"),
        "Medium",
        None,
        0,
    ),
    (
        "infra",
        "actuator_path",
        re.compile(r"/actuator(?:/[A-Za-z0-9._-]+)?"),
        "Medium",
        None,
        0,
    ),
    (
        "infra",
        "nacos_url",
        re.compile(r"https?://[^'\"\s]*/nacos(?:/|$)", re.IGNORECASE),
        "High",
        None,
        0,
    ),
    (
        "infra",
        "elastic_or_kibana",
        re.compile(r"https?://[^'\"\s]+:(?:9200|5601)\b", re.IGNORECASE),
        "Medium",
        None,
        0,
    ),
    (
        "test_environment",
        "test_env_url",
        re.compile(r"https?://[^\s'\"`]*(?:test|dev|uat|pre|staging|sit)[^\s'\"`]*", re.IGNORECASE),
        "Medium",
        None,
        0,
    ),
    (
        "debug_artifact",
        "debug_flag",
        re.compile(r"(?i)(?:debug|debuggable|isDebug|enableDebug)\s*[:=]\s*(?:true|1|yes|\"true\")"),
        "Low",
        None,
        0,
    ),
    (
        "todo_security",
        "todo_or_fixme",
        re.compile(r"(?i)(?:TODO|FIXME|HACK|XXX).*?(?:security|auth|password|secret|encrypt|签名|加密|权限|认证)"),
        "Low",
        None,
        0,
    ),
    (
        "pii",
        "email_address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "Low",
        None,
        0,
    ),
    (
        "pii",
        "phone_number",
        re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
        "Medium",
        None,
        0,
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="Decompiled target directory")
    parser.add_argument("--output-dir", required=True, help="Analysis output root; raw_secrets.json is written to step1/ by default")
    parser.add_argument("--inventory", help="Optional file_inventory.json path")
    parser.add_argument("--max-size-kb", type=int, default=2048, help="Skip files larger than this size")
    return parser.parse_args()


def resolve_phase_output_dir(output_dir: Path, phase_dir: str) -> Path:
    return output_dir if output_dir.name == phase_dir else output_dir / phase_dir


def is_excluded_dir(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return any(part in EXCLUDE_DIRS for part in parts)


def get_context(lines: list[str], line_idx: int, before: int = 1, after: int = 1) -> str:
    start = max(0, line_idx - before)
    end = min(len(lines), line_idx + after + 1)
    ctx_lines = []
    for idx in range(start, end):
        prefix = ">>> " if idx == line_idx else "    "
        ctx_lines.append(f"{prefix}{idx + 1}: {lines[idx].rstrip()}")
    return "\n".join(ctx_lines)


def should_scan_text(path: Path, max_size_kb: int) -> bool:
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
                        if not full.is_file() or is_excluded_dir(clean_rel):
                            continue
                        if full.suffix.lower() in CERT_SUFFIXES or should_scan_text(full, max_size_kb):
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
        if path.suffix.lower() in CERT_SUFFIXES or should_scan_text(path, max_size_kb):
            files.append((path, rel_path))
    return files, source


def is_placeholder(value: str) -> bool:
    lowered = value.strip().strip("\"'`").lower()
    if not lowered:
        return True
    if lowered in KNOWN_TEST_VALUES:
        return True
    if len(set(lowered)) == 1 and len(lowered) >= 4:
        return True
    return any(pattern.search(lowered) for pattern in PLACEHOLDER_PATTERNS)


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}...{value[-4:]}"


def add_hit(store: list[dict], seen: set[tuple], hit: dict) -> None:
    key = (
        hit["source_file"],
        hit["category"],
        hit["sub_type"],
        hit["line"],
        hit["value"],
    )
    if key in seen:
        return
    seen.add(key)
    store.append(hit)


def check_context_keywords(content: str, match_pos: int, keywords: list[str], window: int = 200) -> bool:
    start = max(0, match_pos - window)
    end = min(len(content), match_pos + window)
    region = content[start:end].lower()
    return any(keyword.lower() in region for keyword in keywords)


def scan_file(path: Path, rel_path: str, max_size_kb: int) -> list[dict]:
    hits: list[dict] = []
    seen: set[tuple] = set()

    ext = path.suffix.lower()
    if ext in CERT_SUFFIXES:
        category, sub_type, severity = CERT_SUFFIXES[ext]
        add_hit(
            hits,
            seen,
            {
                "category": category,
                "sub_type": sub_type,
                "severity": severity,
                "value": rel_path,
                "masked_value": rel_path,
                "line": 0,
                "context": f"发现 {ext} 文件",
                "confidence": "high",
                "is_placeholder": False,
                "source_file": rel_path,
                "pattern": f"file_extension:{ext}",
            },
        )
        return hits

    if not should_scan_text(path, max_size_kb):
        return hits

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return hits

    if not text.strip():
        return hits

    size_kb = round(path.stat().st_size / 1024, 1)
    lines = text.splitlines()

    if size_kb > 1024:
        active_rules = [rule for rule in SCAN_RULES if rule[3] in {"Critical", "High"}]
    elif size_kb > 512:
        active_rules = [rule for rule in SCAN_RULES if rule[3] in {"Critical", "High", "Medium"}]
    else:
        active_rules = SCAN_RULES

    for category, sub_type, pattern, severity, context_keywords, value_group in active_rules:
        matches = list(pattern.finditer(text))
        if len(matches) > 100:
            matches = matches[:100]

        for match in matches:
            if context_keywords and not check_context_keywords(text, match.start(), context_keywords):
                continue

            value = match.group(value_group) if value_group else match.group(0)
            placeholder = is_placeholder(value)
            confidence = "high"
            if placeholder:
                confidence = "low"
            elif severity in {"Low", "Medium"}:
                confidence = "medium"

            line_idx = text[: match.start()].count("\n")
            hit = {
                "category": category,
                "sub_type": sub_type,
                "severity": severity,
                "value": value,
                "masked_value": mask_value(value),
                "line": line_idx + 1,
                "context": get_context(lines, line_idx),
                "confidence": confidence,
                "is_placeholder": placeholder,
                "source_file": rel_path,
                "pattern": pattern.pattern[:120],
            }
            add_hit(hits, seen, hit)

    return hits


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_dir = resolve_phase_output_dir(output_root, "step1")
    output_dir.mkdir(parents=True, exist_ok=True)

    all_hits: list[dict] = []
    by_file: dict[str, dict] = {}
    severity_counter: Counter[str] = Counter()
    category_counter: Counter[str] = Counter()
    scanned_files = 0
    skipped_large_files: list[str] = []

    files, file_source = collect_files(target_dir, args.inventory, args.max_size_kb)
    for path, rel_path in files:
        try:
            size_kb = path.stat().st_size / 1024
        except OSError:
            continue

        if path.suffix.lower() not in CERT_SUFFIXES:
            scanned_files += 1

        file_hits = scan_file(path, rel_path, args.max_size_kb)
        if not file_hits:
            continue

        by_file[rel_path] = {
            "file_size_kb": round(size_kb, 2),
            "hit_count": len(file_hits),
            "hits": file_hits,
        }
        for hit in file_hits:
            all_hits.append(hit)
            severity_counter[hit["severity"]] += 1
            category_counter[hit["category"]] += 1

    non_placeholder_hits = sum(1 for hit in all_hits if not hit.get("is_placeholder", False))

    result = {
        "scan_meta": {
            "tool": "secret_scanner.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_dir": str(target_dir),
            "file_source": file_source,
            "inventory_path": args.inventory,
            "max_size_kb": args.max_size_kb,
            "total_text_files_scanned": scanned_files,
            "skipped_large_files": skipped_large_files,
            "scan_rules_count": len(SCAN_RULES),
        },
        "total_hits": len(all_hits),
        "non_placeholder_hits": non_placeholder_hits,
        "severity_statistics": dict(severity_counter),
        "category_statistics": dict(category_counter),
        "by_file": by_file,
        "all_hits": all_hits,
    }

    output_path = output_dir / "raw_secrets.json"
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

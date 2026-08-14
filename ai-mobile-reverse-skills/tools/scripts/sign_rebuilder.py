#!/usr/bin/env python3
"""Signature rebuilder for Phase 5 POC validation.

Reads a signing config (from Phase 3/4 output or manual input) and rebuilds
the sign field for a given request payload.

Supports:
  - Hash: md5, sha1, sha256, sha512, sm3
  - HMAC: hmac_md5, hmac_sha1, hmac_sha256, hmac_sha512
  - Cipher: aes_ecb, aes_cbc, des_ecb, des_cbc, sm4_cbc, sm4_ecb
  - Asymmetric: rsa_sign, ecdsa_sign
  - Encode: base64, hex, urlsafe_base64
  - Compound: chained operations (e.g., md5 then base64)

Usage:
  python3 sign_rebuilder.py --config sign_config.json --payload '{"key":"val"}'
  python3 sign_rebuilder.py --config sign_config.json --payload-file request.json
  python3 sign_rebuilder.py --config sign_config.json --traffic-file traffic.json
  python3 sign_rebuilder.py --example
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependency checks
# ---------------------------------------------------------------------------

def _has_crypto() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _has_gmssl() -> bool:
    try:
        import gmssl  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Key preprocessing
# ---------------------------------------------------------------------------

def _parse_key(raw: str, encoding: str = "utf-8") -> bytes:
    """Parse key string to bytes. Supports hex:, base64:, and raw utf-8."""
    if raw.startswith("hex:"):
        return bytes.fromhex(raw[4:])
    if raw.startswith("base64:"):
        return base64.b64decode(raw[7:])
    return raw.encode(encoding)


def _auto_pad_key(key_bytes: bytes, sizes: Tuple[int, ...] = (16, 24, 32)) -> bytes:
    """Pad or truncate key to the nearest valid AES/DES key size."""
    for size in sizes:
        if len(key_bytes) <= size:
            return key_bytes.ljust(size, b"\x00")
    # Truncate to largest
    return key_bytes[:sizes[-1]]


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

def _hash_op(algo: str, data: bytes, **_kw: Any) -> bytes:
    fn_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    fn = fn_map.get(algo)
    if fn:
        return fn(data).digest()
    if algo == "sm3":
        return _sm3_hash(data)
    raise ValueError(f"Unknown hash algorithm: {algo}")


def _sm3_hash(data: bytes) -> bytes:
    """SM3 hash via gmssl.

    SM3 and SHA-256 are not interchangeable. Failing explicitly keeps a
    missing optional dependency from producing an invalid signature.
    """
    if not _has_gmssl():
        raise RuntimeError("SM3 requires gmssl: pip install gmssl")
    from gmssl import sm3 as gmssl_sm3

    return bytes.fromhex(gmssl_sm3.sm3_hash(list(data)))


# ---------------------------------------------------------------------------
# HMAC functions
# ---------------------------------------------------------------------------

def _hmac_op(algo: str, data: bytes, key: bytes, **_kw: Any) -> bytes:
    hash_algo = algo.replace("hmac_", "")
    fn_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    fn = fn_map.get(hash_algo)
    if not fn:
        raise ValueError(f"Unknown HMAC variant: {algo}")
    return hmac.new(key, data, fn).digest()


# ---------------------------------------------------------------------------
# Cipher functions
# ---------------------------------------------------------------------------

def _cipher_op(
    algo: str,
    data: bytes,
    key: bytes,
    iv: bytes = b"",
    mode: str = "encrypt",
    padding: str = "pkcs7",
) -> bytes:
    if not _has_crypto():
        raise RuntimeError("cryptography package required: pip install cryptography")

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend

    algo_lower = algo.lower()

    # Determine algorithm and mode
    if "aes" in algo_lower:
        key_bytes = _auto_pad_key(key, (16, 24, 32))
        algo_obj = algorithms.AES(key_bytes)
        block_size = 128
    elif "sm4" in algo_lower:
        key_bytes = _auto_pad_key(key, (16,))
        try:
            from cryptography.hazmat.primitives.ciphers import algorithms as algos
            algo_obj = algos.SM4(key_bytes)
        except AttributeError:
            raise RuntimeError("SM4 requires a cryptography build with SM4 support")
        block_size = 128
    elif "des" in algo_lower and "3des" not in algo_lower:
        key_bytes = _auto_pad_key(key, (8,))
        algo_obj = algorithms.DES(key_bytes)
        block_size = 64
    elif "3des" in algo_lower or "des3" in algo_lower:
        key_bytes = _auto_pad_key(key, (16, 24))
        algo_obj = algorithms.TripleDES(key_bytes)
        block_size = 64
    else:
        raise ValueError(f"Unknown cipher algorithm: {algo}")

    # Determine mode
    if "ecb" in algo_lower:
        mode_obj = modes.ECB()
    elif "cbc" in algo_lower:
        iv_bytes = iv or key_bytes[: block_size // 8]
        mode_obj = modes.CBC(iv_bytes)
    elif "ctr" in algo_lower:
        iv_bytes = iv or b"\x00" * 16
        mode_obj = modes.CTR(iv_bytes)
    else:
        mode_obj = modes.ECB()

    cipher = Cipher(algo_obj, mode_obj, backend=default_backend())

    if mode == "encrypt":
        if padding == "pkcs7":
            padder = sym_padding.PKCS7(block_size).padder()
            data = padder.update(data) + padder.finalize()
        elif padding == "zero":
            pad_len = block_size // 8 - len(data) % (block_size // 8)
            if pad_len < block_size // 8:
                data += b"\x00" * pad_len
        return cipher.encryptor().update(data)
    else:
        result = cipher.decryptor().update(data)
        if padding == "pkcs7":
            unpadder = sym_padding.PKCS7(block_size).unpadder()
            result = unpadder.update(result) + unpadder.finalize()
        elif padding == "zero":
            result = result.rstrip(b"\x00")
        return result


# ---------------------------------------------------------------------------
# Asymmetric sign
# ---------------------------------------------------------------------------

def _asymmetric_sign(algo: str, data: bytes, key: bytes, **kw: Any) -> bytes:
    if not _has_crypto():
        raise RuntimeError("cryptography package required: pip install cryptography")

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, ec
    from cryptography.hazmat.backends import default_backend

    if algo == "rsa_sign":
        private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
        hash_algo_name = kw.get("hash_algo", "sha256")
        hash_algo = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(), "sha512": hashes.SHA512()}.get(
            hash_algo_name, hashes.SHA256()
        )
        sig_scheme = kw.get("sig_scheme", "pkcs1v15")
        if sig_scheme == "pss":
            return private_key.sign(data, asym_padding.PSS(mgf=asym_padding.MGF1(hash_algo), salt_length=asym_padding.PSS.MAX_LENGTH), hash_algo)
        return private_key.sign(data, asym_padding.PKCS1v15(), hash_algo)

    if algo == "ecdsa_sign":
        private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
        hash_algo_name = kw.get("hash_algo", "sha256")
        hash_algo = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(), "sha512": hashes.SHA512()}.get(
            hash_algo_name, hashes.SHA256()
        )
        return private_key.sign(data, ec.ECDSA(hash_algo))

    raise ValueError(f"Unknown asymmetric algorithm: {algo}")


# ---------------------------------------------------------------------------
# Encode functions
# ---------------------------------------------------------------------------

def _encode_op(encoding: str, data: bytes, **_kw: Any) -> str:
    if encoding == "hex":
        return data.hex()
    if encoding == "base64":
        return base64.b64encode(data).decode("utf-8")
    if encoding == "urlsafe_base64":
        return base64.urlsafe_b64encode(data).decode("utf-8")
    if encoding == "urlencode":
        return urllib.parse.quote(data)
    if encoding == "upper_hex":
        return data.hex().upper()
    if encoding == "raw":
        return data.decode("utf-8", errors="replace")
    raise ValueError(f"Unknown encoding: {encoding}")


# ---------------------------------------------------------------------------
# Build sign input string
# ---------------------------------------------------------------------------

def build_sign_input(
    payload: Dict[str, Any],
    fields: Optional[List[str]] = None,
    field_order: Optional[List[str]] = None,
    separator: str = "&",
    key_value_fmt: str = "key=value",
    append_key: bool = False,
    key: str = "",
    prepend_key: bool = False,
    extra_constant: str = "",
    extra_prefix: str = "",
    skip_empty: bool = False,
    url_encode_values: bool = False,
    exclude_sign_field: bool = True,
    sign_field_name: str = "sign",
    nested_path: Optional[List[str]] = None,
    json_mode: str = "",
    sort_ascii: bool = False,
) -> str:
    """Construct the string-to-sign from a request payload.

    Args:
        payload: The request body or params dict.
        fields: Which fields to include. None = all.
        field_order: Explicit ordering. None = sorted (or ascii if sort_ascii=True).
        separator: Between fields.
        key_value_fmt: "key=value", "value_only", "key_only", "key:value".
        append_key: Append secret key at end.
        prepend_key: Prepend secret key at start.
        key: The signing key.
        extra_constant: Extra string appended at end.
        extra_prefix: Extra string prepended at start.
        skip_empty: Skip fields with empty/None values.
        url_encode_values: URL-encode values before joining.
        exclude_sign_field: Remove the sign field from input.
        sign_field_name: Name of the sign field to exclude.
        nested_path: Navigate into nested dict (e.g., ["body", "data"]).
        json_mode: "json_body" = JSON-encode entire payload as input.
            "json_fields" = JSON-encode selected fields.
        sort_ascii: Sort fields by ASCII order (case-sensitive).
    """
    # Navigate nested path
    src = payload
    if nested_path:
        for p in nested_path:
            if isinstance(src, dict):
                src = src.get(p, {})
            else:
                src = {}
                break
        if not isinstance(src, dict):
            src = {}

    # JSON mode: just JSON-encode
    if json_mode == "json_body":
        return json.dumps(src, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    # Remove sign field
    working = dict(src)
    if exclude_sign_field and sign_field_name in working:
        del working[sign_field_name]

    # Determine field ordering
    if field_order:
        ordered = [(f, working.get(f, "")) for f in field_order if f in working]
    elif fields:
        ordered = [(f, working[f]) for f in sorted(fields) if f in working]
    elif sort_ascii:
        ordered = sorted(working.items(), key=lambda x: x[0])
    else:
        ordered = sorted(working.items(), key=lambda x: x[0])

    # Skip empty
    if skip_empty:
        ordered = [(k, v) for k, v in ordered if v is not None and v != ""]

    # Format parts
    if key_value_fmt == "value_only":
        parts = [str(v) for _, v in ordered]
    elif key_value_fmt == "key_only":
        parts = [str(k) for k, _ in ordered]
    elif key_value_fmt == "key:value":
        parts = [f"{k}:{v}" for k, v in ordered]
    else:  # key=value
        parts = [f"{k}={v}" for k, v in ordered]

    # URL encode values
    if url_encode_values:
        parts = [urllib.parse.quote(p, safe="=") for p in parts]

    body = separator.join(parts)

    # Assemble
    result = ""
    if extra_prefix:
        result += extra_prefix
    if prepend_key and key:
        result += key + separator
    result += body
    if append_key and key:
        result += separator + key
    if extra_constant:
        result += extra_constant

    return result


# ---------------------------------------------------------------------------
# Pipeline executor: run chained operations
# ---------------------------------------------------------------------------

def _run_pipeline(
    pipeline: List[Dict[str, Any]],
    data: str,
    key: str,
    iv: str = "",
    output_encoding: str = "hex",
) -> str:
    """Execute a chain of operations on data.

    Each step: {"op": "md5"|"sha256"|"hmac_sha256"|"aes_cbc"|"base64"|"hex"|...}
    """
    current = data.encode("utf-8")

    for step in pipeline:
        op = step.get("op", "")
        step_key = _parse_key(step.get("key", key))
        step_iv = _parse_key(step.get("iv", iv))

        if op in ("md5", "sha1", "sha256", "sha512", "sm3"):
            current = _hash_op(op, current)
        elif op.startswith("hmac_"):
            current = _hmac_op(op, current, step_key)
        elif any(c in op for c in ("aes", "des", "sm4", "3des")):
            current = _cipher_op(op, current, step_key, iv=step_iv)
        elif op in ("base64", "hex", "upper_hex", "urlsafe_base64", "urlencode", "raw"):
            current = _encode_op(op, current)
        else:
            raise ValueError(f"Unknown pipeline op: {op}")

    # Default output encoding
    if output_encoding == "base64":
        import base64
        return base64.b64encode(current).decode("ascii")
    return current.hex()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def rebuild_sign(
    config: Dict[str, Any],
    payload: Dict[str, Any],
    override_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Rebuild the sign field for a request payload.

    Config fields:
        algorithm: str — single algorithm name
            (md5, sha1, sha256, sha512, sm3,
             hmac_md5, hmac_sha1, hmac_sha256, hmac_sha512,
             aes_ecb, aes_cbc, des_ecb, des_cbc, sm4_cbc, sm4_ecb, sm4_ctr,
             rsa_sign, ecdsa_sign)
        pipeline: list[dict] — chained operations (overrides algorithm)
            [{"op": "sha256"}, {"op": "base64"}]
        key: str — signing key (supports hex: and base64: prefixes)
        iv: str — initialization vector for cipher algorithms
        key_encoding: str — "utf-8" (default), "hex", "base64"
        encoding: str — output encoding: "hex", "base64", "upper_hex", "urlsafe_base64"
        sign_field: str — field name for the result (default "sign")
        sign_location: str — "body" (default) or "header"

        # Sign input construction (passed to build_sign_input)
        fields, field_order, separator, key_value_fmt,
        append_key, prepend_key, extra_constant, extra_prefix,
        skip_empty, url_encode_values, exclude_sign_field,
        nested_path, json_mode, sort_ascii

        # Asymmetric options
        hash_algo: str — for rsa_sign/ecdsa_sign (default sha256)
        sig_scheme: str — for rsa_sign: "pkcs1v15" (default) or "pss"
        padding: str — for cipher: "pkcs7" (default), "zero", "none"

    Returns:
        {
            "sign_field": str,
            "sign_value": str,
            "sign_input": str,
            "algorithm": str,
            "pipeline": list | None,
        }
    """
    key = override_key or config.get("key", "")
    key_enc = config.get("key_encoding", "utf-8")
    key_bytes = _parse_key(key, key_enc) if key else b""
    iv = config.get("iv", "")
    iv_bytes = _parse_key(iv, key_enc) if iv else b""

    sign_field = config.get("sign_field", "sign")
    output_encoding = config.get("encoding", "hex")

    # Build the sign input string
    sign_input = build_sign_input(
        payload,
        fields=config.get("fields"),
        field_order=config.get("field_order"),
        separator=config.get("separator", "&"),
        key_value_fmt=config.get("key_value_fmt", "key=value"),
        append_key=config.get("append_key", False),
        prepend_key=config.get("prepend_key", False),
        key=key,
        extra_constant=config.get("extra_constant", ""),
        extra_prefix=config.get("extra_prefix", ""),
        skip_empty=config.get("skip_empty", False),
        url_encode_values=config.get("url_encode_values", False),
        exclude_sign_field=config.get("exclude_sign_field", True),
        sign_field_name=sign_field,
        nested_path=config.get("nested_path"),
        json_mode=config.get("json_mode", ""),
        sort_ascii=config.get("sort_ascii", False),
    )

    # Execute: pipeline mode or single algorithm
    pipeline = config.get("pipeline")
    if pipeline:
        sign_value = _run_pipeline(pipeline, sign_input, key, iv, output_encoding)
    else:
        algo = config.get("algorithm", "")
        if not algo:
            raise ValueError("config must include 'algorithm' or 'pipeline'")

        sign_value = _exec_single(
            algo, sign_input.encode("utf-8"), key_bytes, iv_bytes,
            output_encoding, config,
        )

    return {
        "sign_field": sign_field,
        "sign_value": sign_value,
        "sign_input": sign_input,
        "algorithm": config.get("algorithm", "pipeline"),
        "pipeline": pipeline,
    }


def _exec_single(
    algo: str,
    data: bytes,
    key: bytes,
    iv: bytes,
    output_encoding: str,
    config: Dict[str, Any],
) -> str:
    """Execute a single algorithm and return encoded result."""
    algo_lower = algo.lower()

    # Alias mapping: old names -> canonical names
    _ALIAS = {
        "md5_hash": "md5",
        "sha1_hash": "sha1",
        "sha256_hash": "sha256",
        "sha512_hash": "sha512",
    }
    canon = _ALIAS.get(algo_lower, algo_lower)

    # Cipher alias mapping
    _CIPHER_ALIAS = {
        "aes_cbc_sign": "aes_cbc",
        "aes_ecb_sign": "aes_ecb",
    }
    cipher_algo = _CIPHER_ALIAS.get(canon, canon)

    # Hash
    if canon in ("md5", "sha1", "sha256", "sha512", "sm3"):
        raw = _hash_op(canon, data)

    # HMAC
    elif canon.startswith("hmac_"):
        raw = _hmac_op(canon, data, key)

    # Cipher
    elif any(c in cipher_algo for c in ("aes", "des", "sm4", "3des")):
        padding = config.get("padding", "pkcs7")
        raw = _cipher_op(cipher_algo, data, key, iv=iv, padding=padding)

    # Asymmetric
    elif canon in ("rsa_sign", "ecdsa_sign"):
        raw = _asymmetric_sign(
            canon, data, key,
            hash_algo=config.get("hash_algo", "sha256"),
            sig_scheme=config.get("sig_scheme", "pkcs1v15"),
        )

    else:
        raise ValueError(f"Unknown algorithm: {algo}. Supported: md5, sha1, sha256, sha512, sm3, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha512, aes_ecb, aes_cbc, des_ecb, des_cbc, sm4_cbc, sm4_ecb, rsa_sign, ecdsa_sign")

    return _encode_op(output_encoding, raw)


def apply_sign(
    config: Dict[str, Any],
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    override_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Rebuild sign and apply it to payload or headers."""
    result = rebuild_sign(config, payload, override_key=override_key)
    location = config.get("sign_location", "body")

    if location == "header" and headers is not None:
        headers[result["sign_field"]] = result["sign_value"]
        return dict(payload)

    mutated = dict(payload)
    mutated[result["sign_field"]] = result["sign_value"]
    return mutated


# ---------------------------------------------------------------------------
# Auto-config from Phase 3/4 output
# ---------------------------------------------------------------------------

def auto_config_from_analysis(
    crypto_analysis: Optional[Dict[str, Any]] = None,
    vuln_analysis: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Try to generate a sign_config from Phase 3 crypto_native_analysis.json
    or Phase 4 vuln_analysis.json.

    Returns None if no signing info can be extracted.
    """
    # Try to extract from crypto_restoration in vuln_analysis
    if vuln_analysis:
        restoration = vuln_analysis.get("crypto_restoration", {})
        if restoration and restoration.get("algorithm_candidate"):
            algo = restoration["algorithm_candidate"].lower().replace("-", "_")
            key_source = restoration.get("key_derivation", {})
            key = ""
            if isinstance(key_source, dict):
                key = key_source.get("value", "") or key_source.get("source", "")
            elif isinstance(key_source, str):
                key = key_source

            return {
                "algorithm": _normalize_algo(algo),
                "key": key,
                "iv": restoration.get("iv_derivation", {}).get("value", "") if isinstance(restoration.get("iv_derivation"), dict) else "",
                "sign_field": "sign",
                "encoding": "hex",
                "key_value_fmt": "key=value",
                "separator": "&",
                "append_key": True,
            }

    # Try from crypto_native_analysis
    if crypto_analysis:
        for entry in crypto_analysis.get("crypto_findings", []):
            algo = entry.get("algorithm", "").lower().replace("-", "_")
            if algo:
                return {
                    "algorithm": _normalize_algo(algo),
                    "key": entry.get("key", ""),
                    "iv": entry.get("iv", ""),
                    "sign_field": entry.get("field_name", "sign"),
                    "encoding": "hex",
                    "key_value_fmt": "key=value",
                    "separator": "&",
                    "append_key": True,
                }

    return None


def _normalize_algo(algo: str) -> str:
    """Normalize algorithm names from analysis output to our internal names."""
    mapping = {
        "hmac-sha256": "hmac_sha256",
        "hmac-sha1": "hmac_sha1",
        "hmac-sha512": "hmac_sha512",
        "hmac-md5": "hmac_md5",
        "aes-cbc": "aes_cbc",
        "aes-ecb": "aes_ecb",
        "aes-ctr": "aes_ctr",
        "des-cbc": "des_cbc",
        "des-ecb": "des_ecb",
        "3des-cbc": "3des_cbc",
        "sm4-cbc": "sm4_cbc",
        "sm4-ecb": "sm4_ecb",
    }
    return mapping.get(algo, algo)


# ---------------------------------------------------------------------------
# Config examples
# ---------------------------------------------------------------------------

EXAMPLE_CONFIGS = {
    "hmac_sha256_sorted_appendkey": {
        "algorithm": "hmac_sha256",
        "key": "PLACEHOLDER_SECRET",
        "sign_field": "sign",
        "separator": "&",
        "key_value_fmt": "key=value",
        "append_key": True,
        "encoding": "hex",
    },
    "md5_concat_salt": {
        "algorithm": "md5_hash",
        "key": "",
        "sign_field": "sign",
        "field_order": ["timestamp", "data", "nonce"],
        "separator": "",
        "key_value_fmt": "value_only",
        "extra_constant": "PLACEHOLDER_SALT",
        "encoding": "hex",
    },
    "sha256_upperhex": {
        "algorithm": "sha256_hash",
        "key": "",
        "sign_field": "sign",
        "skip_empty": True,
        "encoding": "upper_hex",
    },
    "aes_cbc_base64": {
        "algorithm": "aes_cbc_sign",
        "key": "PLACEHOLDER_16BYTE_KEY",
        "iv": "PLACEHOLDER_16BYTE_IV",
        "encoding": "base64",
        "sign_field": "encryptSign",
        "field_order": ["data", "timestamp"],
        "separator": "&",
        "key_value_fmt": "key=value",
    },
    "pipeline_md5_then_base64": {
        "pipeline": [
            {"op": "md5"},
            {"op": "base64"},
        ],
        "key": "",
        "sign_field": "sign",
        "field_order": ["appId", "data", "timestamp"],
        "separator": "",
        "key_value_fmt": "value_only",
        "extra_constant": "PLACEHOLDER_SALT",
    },
    "pipeline_hmac_then_hex": {
        "pipeline": [
            {"op": "hmac_sha256"},
            {"op": "hex"},
        ],
        "key": "PLACEHOLDER_SECRET",
        "sign_field": "sign",
        "separator": "&",
        "key_value_fmt": "key=value",
        "append_key": True,
    },
    "rsa_sign_pkcs1": {
        "algorithm": "rsa_sign",
        "key": "-----BEGIN RSA PRIVATE KEY-----\nPLACEHOLDER\n-----END RSA PRIVATE KEY-----",
        "sign_field": "sign",
        "hash_algo": "sha256",
        "sig_scheme": "pkcs1v15",
        "encoding": "base64",
        "json_mode": "json_body",
    },
    "header_sign": {
        "algorithm": "hmac_sha256",
        "key": "PLACEHOLDER_SECRET",
        "sign_field": "X-Signature",
        "sign_location": "header",
        "separator": "&",
        "key_value_fmt": "key=value",
        "append_key": True,
        "encoding": "hex",
    },
    "value_only_sorted": {
        "algorithm": "md5_hash",
        "key": "",
        "sign_field": "sign",
        "key_value_fmt": "value_only",
        "separator": "",
        "skip_empty": True,
        "sort_ascii": True,
        "extra_constant": "PLACEHOLDER_SALT",
    },
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Rebuild sign field from config and payload")
    parser.add_argument("--config", help="Path to signing config JSON")
    parser.add_argument("--payload", help="JSON string of request payload")
    parser.add_argument("--payload-file", help="Path to request payload JSON file")
    parser.add_argument("--traffic-file", help="Path to traffic JSON (uses first request as payload)")
    parser.add_argument("--override-key", help="Override the key in config")
    parser.add_argument("--example", action="store_true", help="Print example configs and exit")
    parser.add_argument("--auto-config", help="Path to crypto_native_analysis.json or vuln_analysis.json to auto-generate config")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show sign input string")
    args = parser.parse_args()

    if args.example:
        print(json.dumps(EXAMPLE_CONFIGS, indent=2, ensure_ascii=False))
        return

    # Auto-config mode
    if args.auto_config:
        analysis = json.loads(Path(args.auto_config).read_text(encoding="utf-8"))
        config = auto_config_from_analysis(vuln_analysis=analysis) or auto_config_from_analysis(crypto_analysis=analysis)
        if not config:
            print("Error: could not extract signing config from analysis file", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(config, indent=2, ensure_ascii=False))
        return

    if not args.config:
        print("Error: provide --config or --auto-config or --example", file=sys.stderr)
        sys.exit(1)

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))

    # Resolve payload
    if args.payload:
        payload = json.loads(args.payload)
    elif args.payload_file:
        payload = json.loads(Path(args.payload_file).read_text(encoding="utf-8"))
    elif args.traffic_file:
        traffic = json.loads(Path(args.traffic_file).read_text(encoding="utf-8"))
        if isinstance(traffic, list) and traffic:
            payload = traffic[0].get("request", traffic[0].get("body", {}))
        elif isinstance(traffic, dict):
            payload = traffic.get("request", traffic.get("body", traffic))
        else:
            print("Error: unrecognized traffic file format", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: provide --payload, --payload-file, or --traffic-file", file=sys.stderr)
        sys.exit(1)

    result = rebuild_sign(config, payload, override_key=args.override_key)

    if args.verbose:
        print(f"sign_input: {result['sign_input']}", file=sys.stderr)
        print(f"algorithm:  {result['algorithm']}", file=sys.stderr)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

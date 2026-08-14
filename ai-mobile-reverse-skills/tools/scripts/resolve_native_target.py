#!/usr/bin/env python3
"""Select the most likely native library target for Phase 3 analysis.

Inputs:
- output_dir containing Phase 1 / 2 artifacts
- optional target_dir as a fallback search root

Outputs:
- native_target_candidates.json
- selected_native_target.json

Design goal:
- reduce manual so selection between Phase 2 and Phase 3
- produce a stable, reviewable selection artifact instead of opaque heuristics
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


ABI_PRIORITY = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
SO_NAME_RE = re.compile(r"lib[0-9A-Za-z_.-]+\.so")
LIKELY_CRYPTO_HINT_RE = re.compile(
    r"(?:sign|secure|crypto|cipher|verify|encrypt|decrypt|sm2|sm3|sm4|rsa|aes|hmac|sha|ssl|tls)",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="Analysis output root; selection artifacts are written to step2/ by default")
    parser.add_argument("--target-dir", help="Optional source root used to resolve relative .so paths")
    parser.add_argument(
        "--min-score",
        type=int,
        default=1,
        help="Minimum score for a candidate to appear in native_target_candidates.json",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict | list | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def phase_dir(output_dir: Path, phase_name: str) -> Path:
    return output_dir if output_dir.name == phase_name else output_dir / phase_name


def read_artifact(output_dir: Path, phase_name: str, filename: str) -> dict | list | None:
    """Read the new stepN location first, then fall back to legacy flat output."""
    for path in (phase_dir(output_dir, phase_name) / filename, output_dir / filename):
        data = read_json(path)
        if data is not None:
            return data
    return None


def flatten_strings(value) -> list[str]:
    items: list[str] = []
    if isinstance(value, str):
        items.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            items.extend(flatten_strings(v))
    elif isinstance(value, list):
        for v in value:
            items.extend(flatten_strings(v))
    return items


def abi_sort_key(path_str: str) -> tuple[int, str]:
    norm = path_str.replace("\\", "/")
    for idx, abi in enumerate(ABI_PRIORITY):
        if f"/{abi}/" in norm:
            return (idx, norm)
    return (len(ABI_PRIORITY), norm)


def normalize_so_path(candidate: str, target_dir: Path | None) -> str:
    candidate = candidate.strip()
    if not candidate:
        return candidate
    p = Path(candidate).expanduser()
    if p.is_absolute():
        return str(p.resolve()) if p.exists() else str(p)
    if target_dir:
        joined = (target_dir / candidate).resolve()
        if joined.exists():
            return str(joined)
        # fallback by filename search
        matches = sorted((path for path in target_dir.rglob(p.name) if path.is_file()), key=lambda x: abi_sort_key(str(x)))
        if matches:
            return str(matches[0].resolve())
    return candidate


def collect_so_candidates(output_dir: Path, target_dir: Path | None) -> dict[str, dict]:
    candidates: dict[str, dict] = {}

    def ensure(path_or_name: str) -> dict:
        normalized = normalize_so_path(path_or_name, target_dir)
        entry = candidates.setdefault(
            normalized,
            {
                "so_path": normalized,
                "so_name": Path(normalized).name,
                "score": 0,
                "reasons": [],
                "related_fields": set(),
                "related_endpoints": set(),
                "source_files": set(),
            },
        )
        return entry

    file_inventory = read_artifact(output_dir, "step1", "file_inventory.json")
    if isinstance(file_inventory, dict):
        for text in flatten_strings(file_inventory):
            for so_name in SO_NAME_RE.findall(text):
                entry = ensure(text if text.endswith(".so") else so_name)
                entry["score"] += 1
                entry["reasons"].append("phase1_inventory")

    entrypoints = read_artifact(output_dir, "step1", "entrypoints.json")
    if isinstance(entrypoints, dict):
        for text in flatten_strings(entrypoints):
            for so_name in SO_NAME_RE.findall(text):
                entry = ensure(text if text.endswith(".so") else so_name)
                entry["score"] += 2
                entry["reasons"].append("phase1_entrypoint")
            if LIKELY_CRYPTO_HINT_RE.search(text):
                for so_path, entry in candidates.items():
                    if entry["so_name"] in text:
                        entry["score"] += 1
                        entry["reasons"].append("crypto_hint_in_entrypoints")

    raw_native = read_artifact(output_dir, "step1", "raw_native_bridges.json")
    if isinstance(raw_native, dict):
        libraries = raw_native.get("libraries", [])
        if isinstance(libraries, list):
            for item in libraries:
                if not isinstance(item, dict):
                    continue
                lib = item.get("library")
                if not isinstance(lib, str):
                    continue
                so_name = lib if lib.endswith(".so") else f"lib{lib}.so"
                entry = ensure(so_name)
                entry["score"] += 3
                entry["reasons"].append("raw_native_bridges_library")
                for occ in item.get("occurrences", []):
                    if isinstance(occ, dict) and occ.get("source_file"):
                        entry["source_files"].add(occ["source_file"])

        for text in flatten_strings(raw_native):
            for so_name in SO_NAME_RE.findall(text):
                entry = ensure(text if text.endswith(".so") else so_name)
                entry["score"] += 2
                entry["reasons"].append("raw_native_bridges_symbol")

    protocol_map = read_artifact(output_dir, "step2", "protocol_map.json")
    if isinstance(protocol_map, dict):
        for section_name in ("signature_fields", "crypto_code_locations", "endpoint_parameter_map", "auth_fields"):
            section = protocol_map.get(section_name, [])
            if not isinstance(section, list):
                continue
            for item in section:
                if not isinstance(item, dict):
                    continue
                related_native = item.get("related_native_candidate")
                text_blob = " ".join(flatten_strings(item))
                matched_names = SO_NAME_RE.findall(text_blob)
                if related_native:
                    if isinstance(related_native, str):
                        matched_names.extend(SO_NAME_RE.findall(related_native))
                    elif related_native is True:
                        # generic native hint; later we will score all likely crypto libs slightly
                        for entry in candidates.values():
                            if LIKELY_CRYPTO_HINT_RE.search(entry["so_name"]):
                                entry["score"] += 1
                                entry["reasons"].append("phase2_generic_native_hint")
                    for so_name in matched_names:
                        entry = ensure(so_name)
                        entry["score"] += 4
                        entry["reasons"].append("phase2_related_native_candidate")
                        if item.get("field") or item.get("field_role"):
                            entry["related_fields"].add(item.get("field") or item.get("field_role"))
                        if item.get("endpoint_id"):
                            entry["related_endpoints"].add(item["endpoint_id"])
                        if item.get("related_endpoints"):
                            entry["related_endpoints"].update([ep for ep in item["related_endpoints"] if isinstance(ep, str)])

                crypto_entry = item.get("crypto_entry_candidate")
                if isinstance(crypto_entry, str) and LIKELY_CRYPTO_HINT_RE.search(crypto_entry):
                    for entry in candidates.values():
                        if LIKELY_CRYPTO_HINT_RE.search(entry["so_name"]):
                            entry["score"] += 1
                            entry["reasons"].append("phase2_crypto_entry_candidate")

    traffic_alignment = read_artifact(output_dir, "step2", "traffic_alignment.json")
    if isinstance(traffic_alignment, dict):
        for item in traffic_alignment.get("matched_field_flows", []):
            if not isinstance(item, dict):
                continue
            related_native = item.get("related_native_candidate")
            matched_names = SO_NAME_RE.findall(" ".join(flatten_strings(item)))
            if related_native:
                if isinstance(related_native, str):
                    matched_names.extend(SO_NAME_RE.findall(related_native))
                for so_name in matched_names:
                    entry = ensure(so_name)
                    entry["score"] += 5
                    entry["reasons"].append("phase2_traffic_alignment_native")
                    if item.get("field"):
                        entry["related_fields"].add(item["field"])
                    if item.get("endpoint_id"):
                        entry["related_endpoints"].add(item["endpoint_id"])

    return candidates


def pick_best(candidates: dict[str, dict], min_score: int) -> tuple[list[dict], dict | None]:
    rows: list[dict] = []
    for entry in candidates.values():
        if entry["score"] < min_score:
            continue
        rows.append(
            {
                "so_path": entry["so_path"],
                "so_name": entry["so_name"],
                "score": entry["score"],
                "reasons": sorted(set(entry["reasons"])),
                "related_fields": sorted(x for x in entry["related_fields"] if x),
                "related_endpoints": sorted(x for x in entry["related_endpoints"] if x),
                "source_files": sorted(entry["source_files"]),
            }
        )
    rows.sort(key=lambda item: (-item["score"], abi_sort_key(item["so_path"])))
    return rows, (rows[0] if rows else None)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir).expanduser().resolve()
    step2_dir = phase_dir(output_dir, "step2")
    target_dir = Path(args.target_dir).expanduser().resolve() if args.target_dir else None
    step2_dir.mkdir(parents=True, exist_ok=True)

    candidates = collect_so_candidates(output_dir, target_dir)
    rows, selected = pick_best(candidates, args.min_score)

    candidates_payload = {
        "scan_meta": {
            "tool": "resolve_native_target.py",
            "generated_at": utc_now(),
            "output_dir": str(output_dir),
            "step_dir": str(step2_dir),
            "target_dir": str(target_dir) if target_dir else None,
            "min_score": args.min_score,
        },
        "candidates": rows,
    }
    selected_payload = {
        "scan_meta": {
            "tool": "resolve_native_target.py",
            "generated_at": utc_now(),
        },
        "selection_status": "selected" if selected else "no_match",
        "selected_so_name": selected["so_name"] if selected else None,
        "selected_so_path": selected["so_path"] if selected else None,
        "selection_reason": (
            f"Highest scored native target based on Phase 1 inventory/entrypoints and Phase 2 native hints: {', '.join(selected['reasons'])}"
            if selected
            else "No native target could be selected from current artifacts"
        ),
        "related_fields": selected["related_fields"] if selected else [],
        "related_endpoints": selected["related_endpoints"] if selected else [],
        "confidence": "high" if selected and selected["score"] >= 8 else "medium" if selected else "low",
        "alternatives": rows[1:6] if len(rows) > 1 else [],
    }

    write_json(step2_dir / "native_target_candidates.json", candidates_payload)
    write_json(step2_dir / "selected_native_target.json", selected_payload)

    print(f"[+] candidates written: {step2_dir / 'native_target_candidates.json'}")
    print(f"[+] selected written: {step2_dir / 'selected_native_target.json'}")
    if selected:
        print(f"[+] selected so: {selected['so_name']} ({selected['so_path']})")
    else:
        print("[-] no native target selected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate phase handoff artifacts and update analysis_state.json."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = PACKAGE_ROOT / "schemas" / "phase-contracts.json"
TEMPLATE_PATH = PACKAGE_ROOT / "templates" / "analysis_state.template.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def phase_id(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("phase_"):
        return normalized
    if normalized.startswith("step"):
        normalized = normalized[4:]
    return f"phase_{normalized}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="Analysis output root")
    parser.add_argument("--phase", required=True, help="Phase number or phase_N")
    parser.add_argument(
        "--status",
        required=True,
        choices=("running", "waiting_review", "completed", "blocked", "failed"),
    )
    parser.add_argument("--target-name", default="")
    parser.add_argument("--target-dir", default="")
    parser.add_argument("--traffic-source", default="")
    parser.add_argument("--native-analysis-source", default="")
    parser.add_argument("--run-mode", choices=("step_by_step", "auto_chain"), default="")
    parser.add_argument("--auto-chain-mode", choices=("A", "B", "C"), default="")
    parser.add_argument("--analysis-mode", choices=("local_source", "jadx_mcp_session"), default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--advance", action="store_true", help="Move current_phase to the next phase after completion")
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_contract(phase: str) -> dict[str, Any]:
    data = load_json(CONTRACT_PATH)
    for item in data.get("phases", []):
        if item.get("id") == phase:
            return item
    raise ValueError(f"Unknown phase: {phase}")


def load_state(state_path: Path) -> dict[str, Any]:
    if state_path.is_file():
        return load_json(state_path)
    return load_json(TEMPLATE_PATH)


def validate_outputs(output_root: Path, required_outputs: list[str]) -> tuple[bool, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    valid = True
    for relative_path in required_outputs:
        path = output_root / relative_path
        exists = path.is_file()
        nonempty = exists and path.stat().st_size > 0
        parseable = True
        error = ""
        if nonempty and path.suffix.lower() == ".json":
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                parseable = False
                error = str(exc)
        item_valid = exists and nonempty and parseable
        valid = valid and item_valid
        checks.append({
            "path": relative_path,
            "exists": exists,
            "nonempty": nonempty,
            "parseable": parseable,
            "valid": item_valid,
            "error": error,
        })
    return valid, checks


def existing_outputs(output_root: Path, phase: str) -> list[str]:
    step_dir = output_root / f"step{phase.rsplit('_', 1)[-1]}"
    if not step_dir.is_dir():
        return []
    return sorted(path.name for path in step_dir.iterdir() if path.is_file() and path.name != "phase_gate.json")


def update_state(state: dict[str, Any], args: argparse.Namespace, phase: str, actual_outputs: list[str]) -> None:
    context = {
        "target_name": args.target_name,
        "target_dir": args.target_dir,
        "traffic_source": args.traffic_source,
        "native_analysis_source": args.native_analysis_source,
        "run_mode": args.run_mode,
        "auto_chain_mode": args.auto_chain_mode,
        "analysis_mode": args.analysis_mode,
        "output_dir": str(Path(args.output_dir).expanduser().resolve()),
    }
    for key, value in context.items():
        if value:
            state[key] = value

    state.setdefault("phases", {})
    phase_state = state["phases"].setdefault(phase, {})
    phase_number = phase.rsplit("_", 1)[-1]
    phase_state["step_dir"] = f"{state.get('output_dir', args.output_dir)}/step{phase_number}"
    phase_state["status"] = args.status
    phase_state["actual_outputs"] = actual_outputs
    phase_state["notes"] = args.notes
    state["current_phase"] = f"phase_{int(phase_number) + 1}" if args.advance and args.status == "completed" and int(phase_number) < 6 else phase
    state["overall_status"] = args.status


def main() -> int:
    args = parse_args()
    phase = phase_id(args.phase)
    output_root = Path(args.output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    contract = load_contract(phase)
    valid, checks = validate_outputs(output_root, contract.get("required_outputs", []))
    requested_status = args.status
    if args.status == "completed" and not valid:
        effective_status = "failed"
        notes = args.notes or "Required phase outputs are missing, empty, or invalid."
    else:
        effective_status = args.status
        notes = args.notes

    state_path = output_root / "analysis_state.json"
    state = load_state(state_path)
    args.status = effective_status
    args.notes = notes
    update_state(state, args, phase, existing_outputs(output_root, phase))
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    step_dir = output_root / f"step{phase.rsplit('_', 1)[-1]}"
    step_dir.mkdir(parents=True, exist_ok=True)
    gate = {
        "tool": "phase_guard.py",
        "checked_at": utc_now(),
        "phase": phase,
        "requested_status": requested_status,
        "effective_status": effective_status,
        "valid": valid,
        "required_outputs": checks,
        "analysis_state": str(state_path),
    }
    (step_dir / "phase_gate.json").write_text(json.dumps(gate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[{effective_status}] {phase}: {'valid' if valid else 'invalid'}")
    print(f"State: {state_path}")
    return 0 if effective_status != "failed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

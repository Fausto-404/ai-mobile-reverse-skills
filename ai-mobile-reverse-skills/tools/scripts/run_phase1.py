#!/usr/bin/env python3
"""Run local Phase 1 indexing, build handoff artifacts, and validate the gate."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any


INDEXERS = (
    "endpoint_extractor.py",
    "secret_scanner.py",
    "native_bridge_indexer.py",
    "env_guard_indexer.py",
)
PHASE_DIR = "step1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def phase_dir(output_dir: Path) -> Path:
    return output_dir if output_dir.name == PHASE_DIR else output_dir / PHASE_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-dir", required=True, help="Decompiled app directory")
    parser.add_argument("--output-dir", required=True, help="Analysis output root")
    parser.add_argument("--inventory", help="Optional file_inventory.json path")
    parser.add_argument("--max-size-kb", type=int, default=2048, help="Skip files larger than this size")
    parser.add_argument("--top-n", type=int, default=25, help="Top items retained by ai_summarizer.py")
    parser.add_argument("--python", default=sys.executable, help="Python interpreter for child scripts")
    parser.add_argument("--target-name", default="", help="Optional target name persisted in analysis_state.json")
    parser.add_argument(
        "--analysis-mode",
        choices=("local_source", "jadx_mcp_session"),
        default="local_source",
        help="Phase 1 input mode persisted in analysis_state.json",
    )
    parser.add_argument(
        "--run-mode",
        choices=("step_by_step", "auto_chain"),
        default="step_by_step",
        help="Workflow mode persisted in analysis_state.json",
    )
    parser.add_argument(
        "--auto-chain-mode",
        choices=("A", "B", "C"),
        default="",
        help="Optional auto_chain mode persisted in analysis_state.json",
    )
    parser.add_argument("--traffic-source", default="", help="Optional local traffic source path")
    parser.add_argument("--native-analysis-source", default="", help="Optional native analysis source path")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Generate a partial summary even if one or more indexers fail",
    )
    return parser.parse_args()


def build_command(script_dir: Path, script_name: str, args: argparse.Namespace) -> list[str]:
    command = [
        args.python,
        str(script_dir / script_name),
        "--target-dir",
        args.target_dir,
        "--output-dir",
        args.output_dir,
        "--max-size-kb",
        str(args.max_size_kb),
    ]
    if args.inventory:
        command.extend(["--inventory", args.inventory])
    return command


def run_command(command: list[str]) -> dict[str, Any]:
    started = monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as exc:
        return {
            "command": command,
            "returncode": -1,
            "duration_seconds": round(monotonic() - started, 3),
            "stdout": "",
            "stderr": str(exc),
            "status": "failed",
        }
    return {
        "command": command,
        "returncode": completed.returncode,
        "duration_seconds": round(monotonic() - started, 3),
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "status": "passed" if completed.returncode == 0 else "failed",
    }


def run_summary(args: argparse.Namespace, script_dir: Path) -> dict[str, Any]:
    command = [
        args.python,
        str(script_dir / "ai_summarizer.py"),
        "--output-dir",
        args.output_dir,
        "--top-n",
        str(args.top_n),
    ]
    result = run_command(command)
    result["tool"] = "ai_summarizer.py"
    return result


def run_artifact_builder(args: argparse.Namespace, script_dir: Path) -> dict[str, Any]:
    command = [
        args.python,
        str(script_dir / "phase1_artifact_builder.py"),
        "--target-dir",
        args.target_dir,
        "--output-dir",
        args.output_dir,
        "--max-size-kb",
        str(args.max_size_kb),
        "--analysis-mode",
        args.analysis_mode,
    ]
    result = run_command(command)
    result["tool"] = "phase1_artifact_builder.py"
    return result


def run_phase_guard(
    args: argparse.Namespace,
    script_dir: Path,
    status: str,
) -> dict[str, Any]:
    command = [
        args.python,
        str(script_dir / "phase_guard.py"),
        "--output-dir",
        args.output_dir,
        "--phase",
        "phase_1",
        "--status",
        status,
        "--target-name",
        args.target_name,
        "--target-dir",
        args.target_dir,
        "--analysis-mode",
        args.analysis_mode,
        "--run-mode",
        args.run_mode,
    ]
    for flag, value in (
        ("--auto-chain-mode", args.auto_chain_mode),
        ("--traffic-source", args.traffic_source),
        ("--native-analysis-source", args.native_analysis_source),
    ):
        if value:
            command.extend([flag, value])
    if status == "completed":
        command.append("--advance")
    result = run_command(command)
    result["tool"] = "phase_guard.py"
    return result


def main() -> int:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    output_dir = Path(args.output_dir).expanduser().resolve()
    if output_dir.name == PHASE_DIR:
        output_dir = output_dir.parent
    args.output_dir = str(output_dir)
    phase_output_dir = phase_dir(output_dir)
    phase_output_dir.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    results: list[dict[str, Any]] = []
    commands = [build_command(script_dir, name, args) for name in INDEXERS]

    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        futures = {pool.submit(run_command, command): command for command in commands}
        for future in as_completed(futures):
            result = future.result()
            result["tool"] = Path(result["command"][1]).name
            results.append(result)
    results.sort(key=lambda item: item["tool"])

    failed = [item for item in results if item["status"] != "passed"]
    artifact_result: dict[str, Any] | None = None
    if not failed or args.continue_on_error:
        artifact_result = run_artifact_builder(args, script_dir)
        if artifact_result["status"] != "passed":
            failed.append(artifact_result)

    summary_result: dict[str, Any] | None = None
    if (not failed or args.continue_on_error) and artifact_result and artifact_result["status"] == "passed":
        summary_result = run_summary(args, script_dir)
        if summary_result["status"] != "passed":
            failed.append(summary_result)

    run_status = "passed" if not failed else "failed"
    result_path = phase_output_dir / "phase1_run_result.json"
    run_result = {
        "started_at": started_at,
        "finished_at": utc_now(),
        "target_dir": str(Path(args.target_dir).expanduser().resolve()),
        "output_dir": str(output_dir),
        "parallel_indexers": results,
        "artifact_builder": artifact_result,
        "summary": summary_result,
        "status": run_status,
    }
    result_path.write_text(json.dumps(run_result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if run_status != "passed":
        phase_status = "failed"
    elif args.run_mode == "auto_chain" and args.auto_chain_mode == "C":
        phase_status = "completed"
    else:
        phase_status = "waiting_review"
    phase_gate_result = run_phase_guard(args, script_dir, phase_status)
    run_result["phase_status"] = phase_status
    run_result["phase_gate"] = phase_gate_result
    if run_status == "passed" and phase_gate_result["status"] != "passed":
        run_result["status"] = "failed"
    run_result["finished_at"] = utc_now()
    result_path.write_text(json.dumps(run_result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for item in results:
        print(f"[{item['status']}] {item['tool']} ({item['duration_seconds']}s)")
    if artifact_result:
        print(f"[{artifact_result['status']}] phase1_artifact_builder.py ({artifact_result['duration_seconds']}s)")
    if summary_result:
        print(f"[{summary_result['status']}] ai_summarizer.py ({summary_result['duration_seconds']}s)")
    print(f"[{phase_gate_result['status']}] phase_guard.py ({phase_gate_result['duration_seconds']}s)")
    print(f"Result: {result_path}")
    return 0 if run_result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

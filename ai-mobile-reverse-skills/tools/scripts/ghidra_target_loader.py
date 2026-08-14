#!/usr/bin/env python3
"""Import a selected .so into a Ghidra project and best-effort bring the GUI to front.

This script is designed to bridge the current gap between:
1. Phase 1 / Phase 2 selecting a target native library
2. Phase 3 requiring that the target be opened inside Ghidra

What it does:
- Resolve the target `.so` from an explicit path or a `selected_native_target.json`
- Import the target into a Ghidra project via `analyzeHeadless`
- Best-effort launch or foreground the Ghidra GUI and open the project
- Write a structured loader result JSON for Phase 3 consumption

What it does not guarantee:
- It cannot guarantee that Ghidra GUI will auto-focus the imported program tab
- GUI behavior depends on local Ghidra installation, OS integration, and current workspace state
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_RESULT_FILE = "ghidra_loader_result.json"
MAC_APP_CANDIDATES = [
    "/Applications/Ghidra.app",
]
ABI_PRIORITY = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]


def _find_ghidra_on_path() -> Path | None:
    """Search PATH for ghidraRun / ghidraRun.bat and derive the install root."""
    system = platform.system().lower()
    names = ["ghidraRun.bat"] if system == "windows" else ["ghidraRun"]
    # also try the non-default variant as a fallback
    if system == "windows":
        names.append("ghidraRun")
    else:
        names.append("ghidraRun.bat")

    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found).resolve().parent
    return None


def _find_ghidra_windows_standard() -> Path | None:
    """Check common Windows install locations for Ghidra."""
    patterns = []
    for env_key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        val = os.environ.get(env_key)
        if val:
            patterns.append(os.path.join(val, "Ghidra", "ghidraRun.bat"))
            patterns.append(os.path.join(val, "ghidra*", "ghidraRun.bat"))
    # Common user-level installs
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        patterns.append(os.path.join(userprofile, "ghidra*", "ghidraRun.bat"))
        patterns.append(os.path.join(userprofile, "Desktop", "ghidra*", "ghidraRun.bat"))
        patterns.append(os.path.join(userprofile, "Downloads", "ghidra*", "ghidraRun.bat"))
    # C:\ghidra_* direct installs
    patterns.append(r"C:\ghidra*\ghidraRun.bat")

    for pattern in patterns:
        for match in glob.glob(pattern):
            return Path(match).resolve().parent
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--so-path", help="Direct path to the target .so")
    parser.add_argument(
        "--selected-target-json",
        help="Path to selected_native_target.json or a compatible JSON carrying selected_so_path/selected_so_name",
    )
    parser.add_argument(
        "--target-dir",
        help="Optional search root used when JSON only contains a so name or relative path",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Analysis output root; ghidra_loader_result.json is written to step3/ by default",
    )
    parser.add_argument(
        "--ghidra-root",
        help="Ghidra installation root or Ghidra.app/Contents/MacOS path; falls back to GHIDRA_INSTALL_DIR",
    )
    parser.add_argument(
        "--project-dir",
        required=True,
        help="Directory holding the Ghidra project",
    )
    parser.add_argument(
        "--project-name",
        required=True,
        help="Ghidra project name, without .gpr suffix",
    )
    parser.add_argument(
        "--program-name",
        help="Optional imported program name override; defaults to the .so file name",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Pass -overwrite to analyzeHeadless",
    )
    parser.add_argument(
        "--noanalysis",
        action="store_true",
        help="Import only; skip auto-analysis during headless import",
    )
    parser.add_argument(
        "--no-launch-gui",
        action="store_true",
        help="Import into the project but do not launch/activate Ghidra GUI",
    )
    parser.add_argument(
        "--no-activate",
        action="store_true",
        help="Launch the project but do not try to foreground Ghidra",
    )
    return parser.parse_args()


def phase_dir(output_dir: Path, phase_name: str) -> Path:
    return output_dir if output_dir.name == phase_name else output_dir / phase_name


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"无法读取 JSON: {path} ({exc})") from exc


def find_so_by_name(root: Path, so_name: str) -> Path | None:
    matches = [path for path in root.rglob(so_name) if path.is_file()]
    if not matches:
        return None
    matches.sort(key=abi_sort_key)
    return matches[0]


def abi_sort_key(path: Path) -> tuple[int, str]:
    path_str = str(path).replace("\\", "/")
    for index, abi in enumerate(ABI_PRIORITY):
        if f"/{abi}/" in path_str:
            return (index, path_str)
    return (len(ABI_PRIORITY), path_str)


def resolve_so_path(args: argparse.Namespace) -> tuple[Path, dict]:
    resolution_meta: dict = {
        "source": None,
        "selected_target_json": None,
        "selection_reason": None,
    }

    if args.so_path:
        so_path = Path(args.so_path).expanduser().resolve()
        if not so_path.is_file():
            raise RuntimeError(f"指定的 so 文件不存在: {so_path}")
        resolution_meta["source"] = "direct_so_path"
        return so_path, resolution_meta

    if not args.selected_target_json:
        output_root = Path(args.output_dir).expanduser().resolve()
        default_selected = phase_dir(output_root, "step2") / "selected_native_target.json"
        legacy_selected = output_root / "selected_native_target.json"
        if default_selected.is_file():
            args.selected_target_json = str(default_selected)
        elif legacy_selected.is_file():
            args.selected_target_json = str(legacy_selected)
        else:
            raise RuntimeError("缺少 so 目标。请提供 --so-path 或 --selected-target-json。")

    selected_json = Path(args.selected_target_json).expanduser().resolve()
    if not selected_json.is_file():
        raise RuntimeError(f"selected target JSON 不存在: {selected_json}")

    data = load_json(selected_json)
    resolution_meta["source"] = "selected_target_json"
    resolution_meta["selected_target_json"] = str(selected_json)
    resolution_meta["selection_reason"] = (
        data.get("selection_reason")
        or data.get("reason")
        or data.get("summary")
    )

    candidates = [
        data.get("selected_so_path"),
        data.get("so_path"),
        data.get("selected_target", {}).get("selected_so_path") if isinstance(data.get("selected_target"), dict) else None,
        data.get("selected_target", {}).get("so_path") if isinstance(data.get("selected_target"), dict) else None,
        data.get("selected_so_name"),
        data.get("so_name"),
        data.get("selected_target", {}).get("selected_so_name") if isinstance(data.get("selected_target"), dict) else None,
        data.get("selected_target", {}).get("so_name") if isinstance(data.get("selected_target"), dict) else None,
    ]

    root = Path(args.target_dir).expanduser().resolve() if args.target_dir else None

    for candidate in candidates:
        if not candidate:
            continue
        candidate_path = Path(str(candidate)).expanduser()
        if candidate_path.is_absolute() and candidate_path.is_file():
            return candidate_path.resolve(), resolution_meta
        if root:
            joined = (root / str(candidate)).resolve()
            if joined.is_file():
                return joined, resolution_meta
            by_name = find_so_by_name(root, candidate_path.name)
            if by_name:
                return by_name.resolve(), resolution_meta

    raise RuntimeError(
        "无法从 selected target JSON 解析 so 文件路径。"
        "请补充 --target-dir，或在 JSON 中提供 selected_so_path。"
    )


def _ghidra_binary_names() -> tuple[str, str]:
    """Return (ghidraRun, analyzeHeadless) names for the current platform."""
    if platform.system().lower() == "windows":
        return "ghidraRun.bat", "analyzeHeadless.bat"
    return "ghidraRun", "analyzeHeadless"


def normalize_ghidra_root(raw: str | None) -> Path:
    ghidra_raw = raw or os.environ.get("GHIDRA_INSTALL_DIR")
    run_name, headless_name = _ghidra_binary_names()

    if ghidra_raw:
        root = Path(ghidra_raw).expanduser().resolve()
        # macOS app bundle support
        if root.name == "MacOS" and root.parent.name == "Contents":
            return root
        if root.suffix == ".app":
            return root / "Contents" / "MacOS"
        if (root / run_name).exists():
            return root
        if (root / "support" / headless_name).exists():
            return root

    # PATH search
    path_root = _find_ghidra_on_path()
    if path_root:
        return path_root

    # Platform-specific standard paths
    system = platform.system().lower()
    if system == "darwin":
        for app in MAC_APP_CANDIDATES:
            candidate = Path(app)
            if candidate.exists():
                return candidate / "Contents" / "MacOS"
    elif system == "windows":
        win_root = _find_ghidra_windows_standard()
        if win_root:
            return win_root

    raise RuntimeError(
        "无法定位 Ghidra 安装目录。请通过 --ghidra-root 或 GHIDRA_INSTALL_DIR 提供路径。"
    )


def ghidra_binaries(ghidra_root: Path) -> tuple[Path, Path]:
    if platform.system().lower() == "windows":
        ghidra_run = ghidra_root / "ghidraRun.bat"
        analyze_headless = ghidra_root / "support" / "analyzeHeadless.bat"
    else:
        ghidra_run = ghidra_root / "ghidraRun"
        analyze_headless = ghidra_root / "support" / "analyzeHeadless"
    if not ghidra_run.exists():
        raise RuntimeError(f"找不到 ghidraRun: {ghidra_run}")
    if not analyze_headless.exists():
        raise RuntimeError(f"找不到 analyzeHeadless: {analyze_headless}")
    return ghidra_run, analyze_headless


def run_import(
    analyze_headless: Path,
    project_dir: Path,
    project_name: str,
    so_path: Path,
    program_name: str | None,
    overwrite: bool,
    noanalysis: bool,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        str(analyze_headless),
        str(project_dir),
        project_name,
        "-import",
        str(so_path),
    ]
    if program_name:
        cmd.extend(["-loader", "ElfLoader", "-loader-imagebase", "0x0"])
        # program_name itself is not directly configurable in all versions; record it in result instead
    if overwrite:
        cmd.append("-overwrite")
    if noanalysis:
        cmd.append("-noanalysis")
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def try_launch_gui(ghidra_run: Path, project_file: Path, activate: bool) -> dict:
    launch_meta = {
        "attempted": True,
        "method": None,
        "launched": False,
        "activated": False,
        "notes": [],
    }

    system = platform.system().lower()

    # On many local macOS installs, `.gpr` is not registered as a document type,
    # so `open project.gpr` often fails with kLSApplicationNotFoundErr.
    # Prefer the user's real-world launch path: ghidraRun.
    launch_cmds = [
        ([str(ghidra_run), str(project_file)], "ghidraRun_project_file"),
        ([str(ghidra_run)], "ghidraRun_plain"),
    ]

    for cmd, method in launch_cmds:
        try:
            subprocess.Popen(cmd)
            launch_meta["method"] = method
            launch_meta["launched"] = True
            break
        except Exception as exc:  # noqa: BLE001
            launch_meta["notes"].append(f"{method} failed: {exc}")

    if activate and launch_meta["launched"]:
        if system == "darwin":
            try:
                subprocess.run(
                    ["osascript", "-e", 'tell application "Ghidra" to activate'],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                launch_meta["activated"] = True
            except Exception as exc:  # noqa: BLE001
                launch_meta["notes"].append(f"macOS activate failed: {exc}")
        elif system == "windows":
            try:
                subprocess.Popen(
                    [
                        "powershell", "-Command",
                        "(New-Object -ComObject WScript.Shell).AppActivate('Ghidra')",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                launch_meta["activated"] = True
            except Exception as exc:  # noqa: BLE001
                launch_meta["notes"].append(f"Windows activate failed: {exc}")

    if system == "darwin" and not launch_meta["launched"]:
        launch_meta["notes"].append(
            "macOS LaunchServices association for .gpr was intentionally not used; ghidraRun should be preferred on this host"
        )

    return launch_meta


def write_result(output_dir: Path, payload: dict) -> Path:
    step3_dir = phase_dir(output_dir, "step3")
    step3_dir.mkdir(parents=True, exist_ok=True)
    result_file = step3_dir / DEFAULT_RESULT_FILE
    result_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return result_file


def main() -> int:
    args = parse_args()

    output_dir = Path(args.output_dir).expanduser().resolve()
    project_dir = Path(args.project_dir).expanduser().resolve()
    project_dir.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "scan_meta": {
            "tool": "ghidra_target_loader.py",
            "generated_at": utc_now(),
            "platform": platform.platform(),
        },
        "status": "failed",
        "target": {},
        "ghidra": {},
        "import_result": {},
        "gui_result": {},
        "notes": [],
    }

    try:
        so_path, resolution_meta = resolve_so_path(args)
        result["target"] = {
            "selected_so_path": str(so_path),
            "selected_so_name": so_path.name,
            "resolution": resolution_meta,
        }

        ghidra_root = normalize_ghidra_root(args.ghidra_root)
        ghidra_run, analyze_headless = ghidra_binaries(ghidra_root)
        project_file = project_dir / f"{args.project_name}.gpr"

        result["ghidra"] = {
            "ghidra_root": str(ghidra_root),
            "ghidra_run": str(ghidra_run),
            "analyze_headless": str(analyze_headless),
            "project_dir": str(project_dir),
            "project_name": args.project_name,
            "project_file": str(project_file),
        }

        completed = run_import(
            analyze_headless=analyze_headless,
            project_dir=project_dir,
            project_name=args.project_name,
            so_path=so_path,
            program_name=args.program_name,
            overwrite=args.overwrite,
            noanalysis=args.noanalysis,
        )

        result["import_result"] = {
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-4000:],
            "stderr_tail": completed.stderr[-4000:],
            "overwrite": args.overwrite,
            "noanalysis": args.noanalysis,
        }

        if completed.returncode != 0:
            result["status"] = "import_failed"
            result["notes"].append("analyzeHeadless import failed")
            write_result(output_dir, result)
            return 1

        if not args.no_launch_gui:
            gui_result = try_launch_gui(
                ghidra_run=ghidra_run,
                project_file=project_file,
                activate=not args.no_activate,
            )
            result["gui_result"] = gui_result
            if not gui_result.get("launched"):
                result["notes"].append("GUI launch attempted but not confirmed")

        result["status"] = "ok"
        result["notes"].append(
            "so imported into Ghidra project successfully; GUI program auto-focus still depends on local Ghidra behavior"
        )
        result_file = write_result(output_dir, result)
        print(f"[+] selected so: {so_path}")
        print(f"[+] project file: {project_file}")
        print(f"[+] result file: {result_file}")
        return 0

    except Exception as exc:  # noqa: BLE001
        result["notes"].append(str(exc))
        write_result(output_dir, result)
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Import a selected .so into an IDA Pro database and best-effort bring the GUI to front.

This is the IDA counterpart of ghidra_target_loader.py. It bridges the same gap:
1. Phase 1 / Phase 2 selecting a target native library
2. Phase 3 requiring that target be opened (and pre-analyzed) inside IDA

What it does:
- Resolve the target `.so` from an explicit path or a `selected_native_target.json`
- Headless-analyze the target with `idat` (creates a .i64 database and runs auto-analysis)
- Best-effort launch / foreground the IDA GUI on the generated database
- Write a structured loader result JSON for Phase 3 (and the ida_pro_mcp plugin) consumption

What it does not guarantee:
- It cannot guarantee the IDA GUI auto-focuses the right view
- GUI behavior depends on local IDA installation, OS integration, and current workspace state
- The ida_pro_mcp plugin must be installed in IDA for MCP-driven analysis after launch

IDA version notes:
- IDA 9.x unifies the binaries to `ida` (GUI) and `idat` (headless/text mode); the single
  binary handles both 32- and 64-bit targets.
- IDA 8.x and earlier use `ida64`/`idat64` (and `ida`/`idat` for 32-bit). Both are supported.
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
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_RESULT_FILE = "ida_loader_result.json"
MAC_APP_GLOBS = [
    "/Applications/IDA Professional *.app",
    "/Applications/IDA Pro *.app",
    "/Applications/IDA *.app",
    "/Applications/IDA*.app",
]
# Prefer the unified 9.x names first, fall back to the legacy 64-bit names.
GUI_BIN_NAMES = ["ida", "ida64"]
HEADLESS_BIN_NAMES = ["idat", "idat64"]
ABI_PRIORITY = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]


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
        help="Analysis output root; ida_loader_result.json is written to step3/ by default",
    )
    parser.add_argument(
        "--ida-root",
        help="IDA installation root or IDA*.app / Contents/MacOS path; falls back to IDA_DIR / IDADIR",
    )
    parser.add_argument(
        "--db-path",
        help="Output IDA database path (.i64); defaults to step3/<so_name>.i64",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite an existing database at --db-path",
    )
    parser.add_argument(
        "--noanalysis",
        action="store_true",
        help="Skip headless auto-analysis; just open the .so directly in the GUI",
    )
    parser.add_argument(
        "--analysis-timeout",
        type=int,
        default=1800,
        help="Max seconds to wait for headless auto-analysis (default 1800)",
    )
    parser.add_argument(
        "--no-launch-gui",
        action="store_true",
        help="Create the database but do not launch / activate the IDA GUI",
    )
    parser.add_argument(
        "--no-activate",
        action="store_true",
        help="Launch IDA but do not try to foreground it",
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


def abi_sort_key(path: Path) -> tuple[int, str]:
    path_str = str(path).replace("\\", "/")
    for index, abi in enumerate(ABI_PRIORITY):
        if f"/{abi}/" in path_str:
            return (index, path_str)
    return (len(ABI_PRIORITY), path_str)


def find_so_by_name(root: Path, so_name: str) -> Path | None:
    matches = [path for path in root.rglob(so_name) if path.is_file()]
    if not matches:
        return None
    matches.sort(key=abi_sort_key)
    return matches[0]


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

    selected_target = data.get("selected_target") if isinstance(data.get("selected_target"), dict) else {}
    candidates = [
        data.get("selected_so_path"),
        data.get("so_path"),
        selected_target.get("selected_so_path"),
        selected_target.get("so_path"),
        data.get("selected_so_name"),
        data.get("so_name"),
        selected_target.get("selected_so_name"),
        selected_target.get("so_name"),
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


def _exe(name: str) -> str:
    return f"{name}.exe" if platform.system().lower() == "windows" else name


def _first_existing_binary(root: Path, names: list[str]) -> Path | None:
    for name in names:
        candidate = root / _exe(name)
        if candidate.exists():
            return candidate
    return None


def _find_ida_on_path() -> Path | None:
    for name in GUI_BIN_NAMES + HEADLESS_BIN_NAMES:
        found = shutil.which(_exe(name))
        if found:
            return Path(found).resolve().parent
    return None


def _find_ida_mac_standard() -> Path | None:
    matches: list[str] = []
    for pattern in MAC_APP_GLOBS:
        matches.extend(glob.glob(pattern))
    # Newest version first (string sort puts higher version numbers last for typical "X.Y" naming)
    matches = sorted(set(matches), reverse=True)
    for app in matches:
        macos = Path(app) / "Contents" / "MacOS"
        if _first_existing_binary(macos, GUI_BIN_NAMES + HEADLESS_BIN_NAMES):
            return macos
    return None


def _find_ida_windows_standard() -> Path | None:
    patterns: list[str] = []
    for env_key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        val = os.environ.get(env_key)
        if val:
            patterns.append(os.path.join(val, "IDA Professional *"))
            patterns.append(os.path.join(val, "IDA Pro *"))
            patterns.append(os.path.join(val, "IDA *"))
    patterns.append(r"C:\Program Files\IDA*")
    patterns.append(r"C:\IDA*")
    for pattern in patterns:
        for match in sorted(glob.glob(pattern), reverse=True):
            root = Path(match)
            if _first_existing_binary(root, GUI_BIN_NAMES + HEADLESS_BIN_NAMES):
                return root
    return None


def normalize_ida_root(raw: str | None) -> Path:
    ida_raw = raw or os.environ.get("IDA_DIR") or os.environ.get("IDADIR")

    if ida_raw:
        root = Path(ida_raw).expanduser().resolve()
        # macOS app bundle support
        if root.name == "MacOS" and root.parent.name == "Contents":
            return root
        if root.suffix == ".app":
            return root / "Contents" / "MacOS"
        if _first_existing_binary(root, GUI_BIN_NAMES + HEADLESS_BIN_NAMES):
            return root
        # maybe they pointed at the .app without trailing slash resolution
        macos = root / "Contents" / "MacOS"
        if _first_existing_binary(macos, GUI_BIN_NAMES + HEADLESS_BIN_NAMES):
            return macos

    path_root = _find_ida_on_path()
    if path_root:
        return path_root

    system = platform.system().lower()
    if system == "darwin":
        mac_root = _find_ida_mac_standard()
        if mac_root:
            return mac_root
    elif system == "windows":
        win_root = _find_ida_windows_standard()
        if win_root:
            return win_root

    raise RuntimeError(
        "无法定位 IDA 安装目录。请通过 --ida-root 或 IDA_DIR / IDADIR 提供路径。"
    )


def ida_binaries(ida_root: Path) -> tuple[Path, Path]:
    gui = _first_existing_binary(ida_root, GUI_BIN_NAMES)
    headless = _first_existing_binary(ida_root, HEADLESS_BIN_NAMES)
    if not gui:
        raise RuntimeError(f"在 {ida_root} 找不到 IDA GUI 二进制 ({GUI_BIN_NAMES})")
    if not headless:
        raise RuntimeError(f"在 {ida_root} 找不到 IDA headless 二进制 ({HEADLESS_BIN_NAMES})")
    return gui, headless


def db_extension_variants(db_path: Path) -> list[Path]:
    """IDA writes .i64 for 64-bit targets and .idb for 32-bit ones; the bitness is
    decided from the input, not from the -o extension we request. Return both candidate
    paths (requested first) so existence checks tolerate either outcome."""
    stem_path = db_path.with_suffix("")
    candidates = [db_path]
    for ext in (".i64", ".idb"):
        alt = stem_path.with_suffix(ext)
        if alt not in candidates:
            candidates.append(alt)
    return candidates


def find_existing_db(db_path: Path) -> Path | None:
    for candidate in db_extension_variants(db_path):
        if candidate.exists():
            return candidate
    return None


# A minimal IDAPython script: wait for auto-analysis to finish, then save & quit.
_QUIT_SCRIPT = """import ida_auto, ida_pro
ida_auto.auto_wait()
ida_pro.qexit(0)
"""


def run_headless_analysis(
    headless_bin: Path,
    so_path: Path,
    db_path: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Create the IDA database headlessly and run full auto-analysis, then quit.

    Uses `-A` (autonomous: suppress dialogs), `-o<db>` to set the output database,
    and a tiny `-S` IDAPython script that blocks on auto_wait() before qexit.
    """
    script_file = Path(tempfile.gettempdir()) / "_ida_loader_quit.py"
    script_file.write_text(_QUIT_SCRIPT, encoding="utf-8")

    cmd = [
        str(headless_bin),
        "-A",
        f"-o{db_path}",
        f"-S{script_file}",
        str(so_path),
    ]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def try_launch_gui(gui_bin: Path, open_target: Path, activate: bool) -> dict:
    launch_meta = {
        "attempted": True,
        "method": None,
        "launched": False,
        "activated": False,
        "notes": [],
    }

    system = platform.system().lower()

    # On macOS prefer `open -a <App.app>`: it goes through LaunchServices so the
    # process registers as a proper GUI app (making `activate` reliable). Running the
    # Mach-O binary directly works too and is the cross-platform fallback.
    app_bundle: Path | None = None
    if system == "darwin":
        for parent in gui_bin.parents:
            if parent.suffix == ".app":
                app_bundle = parent
                break

    if app_bundle is not None:
        try:
            subprocess.run(
                ["open", "-a", str(app_bundle), str(open_target)],
                check=False,
                capture_output=True,
                text=True,
            )
            launch_meta["method"] = "macos_open_app"
            launch_meta["launched"] = True
        except Exception as exc:  # noqa: BLE001
            launch_meta["notes"].append(f"open -a failed: {exc}")

    if not launch_meta["launched"]:
        try:
            subprocess.Popen([str(gui_bin), str(open_target)])
            launch_meta["method"] = "ida_gui_open_target"
            launch_meta["launched"] = True
        except Exception as exc:  # noqa: BLE001
            launch_meta["notes"].append(f"ida gui launch failed: {exc}")

    if activate and launch_meta["launched"]:
        if system == "darwin":
            # IDA's app process name commonly appears as "ida" or "IDA"; try both.
            for app_name in ("ida", "IDA"):
                try:
                    proc = subprocess.run(
                        ["osascript", "-e", f'tell application "{app_name}" to activate'],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    if proc.returncode == 0:
                        launch_meta["activated"] = True
                        break
                except Exception as exc:  # noqa: BLE001
                    launch_meta["notes"].append(f"macOS activate ({app_name}) failed: {exc}")
        elif system == "windows":
            try:
                subprocess.Popen(
                    [
                        "powershell", "-Command",
                        "(New-Object -ComObject WScript.Shell).AppActivate('IDA')",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                launch_meta["activated"] = True
            except Exception as exc:  # noqa: BLE001
                launch_meta["notes"].append(f"Windows activate failed: {exc}")

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

    result: dict = {
        "scan_meta": {
            "tool": "ida_target_loader.py",
            "generated_at": utc_now(),
            "platform": platform.platform(),
        },
        "status": "failed",
        "target": {},
        "ida": {},
        "analysis_result": {},
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

        ida_root = normalize_ida_root(args.ida_root)
        gui_bin, headless_bin = ida_binaries(ida_root)

        if args.db_path:
            db_path = Path(args.db_path).expanduser().resolve()
        else:
            db_path = phase_dir(output_dir, "step3") / f"{so_path.stem}.i64"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        result["ida"] = {
            "ida_root": str(ida_root),
            "gui_bin": str(gui_bin),
            "headless_bin": str(headless_bin),
            "db_path": str(db_path),
        }

        # The GUI opens the database when one was created, otherwise the raw .so.
        open_target = so_path

        if not args.noanalysis:
            # 32-bit targets yield .idb instead of the requested .i64, so check both.
            existing_db = find_existing_db(db_path)
            if existing_db:
                if args.overwrite:
                    existing_db.unlink()
                else:
                    result["status"] = "db_exists"
                    result["notes"].append(
                        f"数据库已存在: {existing_db}。使用 --overwrite 覆盖，或 --noanalysis 直接打开 so。"
                    )
                    write_result(output_dir, result)
                    print(f"[-] database already exists: {existing_db}", file=sys.stderr)
                    return 1

            try:
                completed = run_headless_analysis(
                    headless_bin=headless_bin,
                    so_path=so_path,
                    db_path=db_path,
                    timeout=args.analysis_timeout,
                )
            except subprocess.TimeoutExpired:
                result["status"] = "analysis_timeout"
                result["notes"].append(
                    f"headless 分析超过 {args.analysis_timeout}s 超时；可调大 --analysis-timeout 或用 --noanalysis"
                )
                write_result(output_dir, result)
                print("[-] headless analysis timed out", file=sys.stderr)
                return 1

            created_db = find_existing_db(db_path)
            result["analysis_result"] = {
                "returncode": completed.returncode,
                "stdout_tail": completed.stdout[-4000:],
                "stderr_tail": completed.stderr[-4000:],
                "db_created": created_db is not None,
                "db_path_actual": str(created_db) if created_db else None,
            }

            if completed.returncode != 0 or not created_db:
                result["status"] = "analysis_failed"
                result["notes"].append("idat headless 分析失败或未生成数据库")
                write_result(output_dir, result)
                print("[-] headless analysis failed", file=sys.stderr)
                return 1

            # Adopt the actually-created database (may be .idb for 32-bit targets).
            db_path = created_db
            result["ida"]["db_path"] = str(db_path)
            open_target = db_path
        else:
            result["notes"].append("--noanalysis: 跳过 headless 建库，GUI 直接打开 so")

        if not args.no_launch_gui:
            gui_result = try_launch_gui(
                gui_bin=gui_bin,
                open_target=open_target,
                activate=not args.no_activate,
            )
            result["gui_result"] = gui_result
            if not gui_result.get("launched"):
                result["notes"].append("GUI launch attempted but not confirmed")

        result["status"] = "ok"
        result["notes"].append(
            "so 已载入 IDA；MCP 驱动分析需 IDA 内已安装 ida_pro_mcp 插件"
        )
        result_file = write_result(output_dir, result)
        print(f"[+] selected so: {so_path}")
        print(f"[+] database: {db_path}")
        print(f"[+] result file: {result_file}")
        return 0

    except Exception as exc:  # noqa: BLE001
        result["notes"].append(str(exc))
        write_result(output_dir, result)
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

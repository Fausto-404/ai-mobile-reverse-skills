#!/usr/bin/env python3
"""
自动化脱壳编排器

核心思路：
  无壳 → jadx 直接反编译（完全自动，秒级完成）
  有壳 → ADB + Frida 编排：安装 APK → 注入 dump 脚本 → monkey 启动 → 收集 DEX → 修复 → jadx

前置要求（有壳路径）：
  1. ADB 已配置，可见设备（真机或模拟器）
  2. 设备上已安装并运行 frida-server（对应架构版本）
  3. 设备已 root（或使用 Magisk/KernelSU）
  4. pip install frida-tools

用法：
  python auto_unpack.py --apk target.apk --output-dir ./analysis_out
  python auto_unpack.py --apk target.apk --output-dir ./analysis_out --device emulator-5554
  python auto_unpack.py --apk target.apk --output-dir ./analysis_out --skip-unpack  # 调试用
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import zipfile
import zlib
from pathlib import Path


# ─── 配置 ──────────────────────────────────────────────────────────────────────

SCRIPTS_DIR = Path(__file__).parent
FRIDA_DIR = SCRIPTS_DIR.parent / "frida"

DUMP_REMOTE_DIR = "/sdcard/dump"
WAIT_FOR_DUMP_SECONDS = 30       # 等待 DEX dump 的最长时间
POLL_INTERVAL = 2                 # 检查 dump 进度的间隔（秒）
MIN_DEX_SIZE = 0x70               # DEX header 最小长度
MAX_DEX_SIZE = 100 * 1024 * 1024  # 100MB 上限
DEX_MAGIC = b"dex\n"


# ─── 工具函数 ──────────────────────────────────────────────────────────────────

def run(cmd: list[str], check=True, capture=False, timeout=60) -> subprocess.CompletedProcess:
    """执行系统命令"""
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    else:
        result = subprocess.run(cmd, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{getattr(result, 'stderr', '')}")
    return result


def adb(*args, device: str | None = None, capture=True, check=True) -> str:
    """执行 ADB 命令"""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += list(args)
    result = run(cmd, capture=capture, check=check, timeout=60)
    return result.stdout.strip() if capture else ""


# ─── Phase 0.1: 壳检测 ────────────────────────────────────────────────────────

def detect_shell(apk_path: Path) -> dict:
    """调用 shell_detector.py 检测壳类型"""
    detector = SCRIPTS_DIR / "shell_detector.py"
    if not detector.exists():
        print("[warn] shell_detector.py not found, assuming no shell")
        return {"verdict": "unknown", "primary_shell": None, "recommended_dump_script": "dex_dumper_art.js"}

    result = run(
        [sys.executable, str(detector), "--apk", str(apk_path)],
        capture=True, check=False
    )

    # 从输出里提取 JSON（shell_detector 最后打印 JSON）
    output = result.stdout
    try:
        json_start = output.rfind("{")
        if json_start != -1:
            return json.loads(output[json_start:])
    except Exception:
        pass

    return {"verdict": "unknown", "primary_shell": None, "recommended_dump_script": "dex_dumper_art.js"}


# ─── Phase 0.2A: 无壳路径 ─────────────────────────────────────────────────────

def decompile_with_jadx(apk_path: Path, output_dir: Path) -> Path:
    """直接用 jadx 反编译，返回 target_dir"""
    target_dir = output_dir / "decompiled"
    target_dir.mkdir(parents=True, exist_ok=True)

    jadx = shutil.which("jadx")
    if not jadx:
        raise RuntimeError("jadx not found in PATH. Install: https://github.com/skylot/jadx")

    print(f"[unpack] running jadx: {apk_path} → {target_dir}")
    run([jadx, "--output-dir", str(target_dir), str(apk_path)], capture=False, timeout=300)
    print(f"[unpack] jadx done → {target_dir}")
    return target_dir


# ─── Phase 0.2B: 有壳路径 ─────────────────────────────────────────────────────

def get_device(preferred: str | None) -> str:
    """获取可用 ADB 设备"""
    output = adb("devices")
    lines = [l for l in output.splitlines() if "\t" in l and "offline" not in l]
    devices = [l.split("\t")[0] for l in lines]

    if not devices:
        raise RuntimeError("No ADB device found. Start emulator or connect device.")

    if preferred and preferred in devices:
        return preferred

    if len(devices) == 1:
        print(f"[unpack] using device: {devices[0]}")
        return devices[0]

    print(f"[unpack] multiple devices: {devices}")
    print(f"[unpack] using first: {devices[0]}")
    return devices[0]


def check_frida_server(device: str):
    """检查设备上是否有运行中的 frida-server"""
    try:
        result = adb("shell", "ps", "-e", device=device, capture=True, check=False)
        if "frida-server" in result:
            print("[unpack] frida-server is running")
            return True
        else:
            print("[warn] frida-server not detected. Make sure it's running on device.")
            print("[hint] push frida-server to /data/local/tmp/ and run: ./frida-server &")
            return False
    except Exception:
        return False


def install_apk(apk_path: Path, device: str) -> str:
    """安装 APK 并返回包名"""
    print(f"[unpack] installing {apk_path.name}...")
    adb("install", "-r", "-t", str(apk_path), device=device)

    # 从 APK 提取包名
    pkg = _get_package_name(apk_path)
    print(f"[unpack] installed: {pkg}")
    return pkg


def _get_package_name(apk_path: Path) -> str:
    """从 APK 提取包名"""
    try:
        with zipfile.ZipFile(apk_path) as apk:
            with apk.open("AndroidManifest.xml") as f:
                raw = f.read()
                import re
                match = re.search(rb"(?:com|org|net|io|cn|app)\.[a-zA-Z0-9._]+", raw[100:500])
                if match:
                    return match.group(0).decode("ascii")
    except Exception:
        pass
    return "unknown.package"


def prepare_dump_dir(device: str):
    """在设备上创建 dump 目录"""
    adb("shell", "rm", "-rf", DUMP_REMOTE_DIR, device=device, check=False)
    adb("shell", "mkdir", "-p", DUMP_REMOTE_DIR, device=device)


def inject_frida_dump(package: str, dump_script_name: str, device: str) -> subprocess.Popen:
    """
    用 Frida 注入 DEX dump 脚本，后台运行
    同时注入 bypass 脚本（处理反调试/root检测）和 dump 脚本
    """
    script_path = FRIDA_DIR / dump_script_name
    bypass_path = FRIDA_DIR / "android_phase1_bypass.js"

    if not script_path.exists():
        # fallback 到通用脚本
        script_path = FRIDA_DIR / "dex_dumper_art.js"

    if not script_path.exists():
        raise RuntimeError(f"Dump script not found: {script_path}")

    # 合并 bypass + dump 脚本
    combined_script = _merge_scripts(bypass_path, script_path)
    combined_path = script_path.parent / "_combined_dump.js"
    combined_path.write_text(combined_script)

    # 启动 frida，spawn 模式（在 APP 启动最早期注入）
    frida_cmd = [
        "frida", "-U",
        "--device", device if device else "usb",
        "-f", package,
        "-l", str(combined_path),
        "--no-pause",
        "--runtime=v8"
    ]

    print(f"[unpack] injecting frida: {package}")
    proc = subprocess.Popen(frida_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc


def _merge_scripts(bypass_path: Path, dump_path: Path) -> str:
    """合并 bypass 和 dump 脚本"""
    parts = []

    # bypass 脚本（填充默认配置）
    if bypass_path.exists():
        bypass_content = bypass_path.read_text()
        bypass_content = bypass_content.replace("__ENABLE_ROOT__", "true")
        bypass_content = bypass_content.replace("__ENABLE_EMULATOR__", "true")
        bypass_content = bypass_content.replace("__ENABLE_PROXY__", "false")
        bypass_content = bypass_content.replace("__ENABLE_SSL__", "false")
        bypass_content = bypass_content.replace("__ENABLE_DEBUG__", "false")
        parts.append("// === bypass ===\n" + bypass_content)

    # dump 脚本
    if dump_path.exists():
        parts.append("\n// === dex dumper ===\n" + dump_path.read_text())

    return "\n".join(parts)


def trigger_app_start(package: str, device: str):
    """用 monkey 触发 APP 启动（让壳解密 DEX）"""
    print(f"[unpack] starting app via monkey: {package}")
    adb("shell", "monkey", "-p", package, "--throttle", "500", "3",
        device=device, check=False)


def wait_for_dumps(device: str, expected_min: int = 1) -> list[str]:
    """
    轮询等待 DEX dump 完成
    返回远端 dump 文件列表
    """
    print(f"[unpack] waiting for DEX dumps (max {WAIT_FOR_DUMP_SECONDS}s)...")

    deadline = time.time() + WAIT_FOR_DUMP_SECONDS
    last_count = 0

    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)

        try:
            output = adb("shell", "ls", DUMP_REMOTE_DIR, device=device, check=False)
            files = [f for f in output.splitlines() if f.endswith(".dex")]
        except Exception:
            files = []

        if len(files) != last_count:
            print(f"[unpack] found {len(files)} DEX file(s)...")
            last_count = len(files)

        # 如果已经有文件且 5 秒内没有新增，认为 dump 完成
        if len(files) >= expected_min and len(files) == last_count:
            # 再等一秒确认
            time.sleep(2)
            output2 = adb("shell", "ls", DUMP_REMOTE_DIR, device=device, check=False)
            files2 = [f for f in output2.splitlines() if f.endswith(".dex")]
            if len(files2) == len(files):
                print(f"[unpack] dump stable: {len(files)} file(s)")
                return files2

    output = adb("shell", "ls", DUMP_REMOTE_DIR, device=device, check=False)
    return [f for f in output.splitlines() if f.endswith(".dex")]


def pull_dumps(device: str, local_dir: Path) -> list[Path]:
    """从设备拉取 dump 文件"""
    local_dir.mkdir(parents=True, exist_ok=True)
    adb("pull", DUMP_REMOTE_DIR, str(local_dir), device=device, check=False)

    dex_files = list((local_dir / "dump").glob("*.dex"))
    if not dex_files:
        dex_files = list(local_dir.glob("*.dex"))

    print(f"[unpack] pulled {len(dex_files)} DEX file(s)")
    return dex_files


# ─── Phase 0.3: DEX 修复 ──────────────────────────────────────────────────────

def fix_dex_files(dex_files: list[Path], output_dir: Path) -> list[Path]:
    """修复 DEX header（checksum + SHA1），过滤无效文件"""
    fixed = []
    fix_dir = output_dir / "fixed_dex"
    fix_dir.mkdir(parents=True, exist_ok=True)

    for dex in dex_files:
        data = dex.read_bytes()

        # 检查 magic
        if not data[:4] == DEX_MAGIC and not data[:3] == b"dex":
            print(f"[unpack] skip {dex.name}: invalid magic")
            continue

        if len(data) < MIN_DEX_SIZE or len(data) > MAX_DEX_SIZE:
            print(f"[unpack] skip {dex.name}: size out of range ({len(data)})")
            continue

        # 修复 file_size 字段（offset 32, uint32 little-endian）
        data = bytearray(data)
        struct.pack_into("<I", data, 32, len(data))

        # 重新计算 Adler-32 checksum（offset 8, uint32，覆盖 offset 12 之后的所有内容）
        checksum = zlib.adler32(bytes(data[12:]))
        struct.pack_into("<I", data, 8, checksum & 0xFFFFFFFF)

        out_path = fix_dir / dex.name
        out_path.write_bytes(bytes(data))
        fixed.append(out_path)
        print(f"[unpack] fixed: {dex.name} ({len(data)} bytes)")

    return fixed


# ─── Phase 0.4: 用 jadx 反编译 dump 出的 DEX ─────────────────────────────────

def decompile_dex_files(dex_files: list[Path], output_dir: Path) -> Path:
    """把所有 dump 出来的 DEX 用 jadx 反编译"""
    target_dir = output_dir / "decompiled"
    target_dir.mkdir(parents=True, exist_ok=True)

    jadx = shutil.which("jadx")
    if not jadx:
        raise RuntimeError("jadx not found in PATH")

    # jadx 可以接受多个 DEX 文件
    cmd = [jadx, "--output-dir", str(target_dir)] + [str(f) for f in dex_files]
    print(f"[unpack] decompiling {len(dex_files)} DEX file(s) with jadx...")
    run(cmd, capture=False, timeout=300)
    print(f"[unpack] decompile done → {target_dir}")
    return target_dir


# ─── 主流程 ───────────────────────────────────────────────────────────────────

def auto_unpack(apk_path: Path, output_dir: Path, device: str | None = None, skip_unpack: bool = False) -> Path:
    """
    主入口：检测壳 → 选择路径 → 反编译 → 返回 target_dir

    返回值：可以直接传给 Phase 1 的 target_dir
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: 检测壳 ──────────────────────────────────────────────────────
    print(f"\n[unpack] === Phase 0: 自动脱壳 ===")
    print(f"[unpack] APK: {apk_path}")

    shell_info = detect_shell(apk_path)
    verdict = shell_info.get("verdict", "unknown")
    primary_shell = shell_info.get("primary_shell")
    dump_script = shell_info.get("recommended_dump_script", "dex_dumper_art.js")

    print(f"[unpack] 壳检测结果: {verdict} / {primary_shell or '无壳'}")

    # 保存 shell 报告
    (output_dir / "shell_report.json").write_text(
        json.dumps(shell_info, ensure_ascii=False, indent=2)
    )

    # ── Step 2A: 无壳路径 ──────────────────────────────────────────────────
    if verdict == "clean" or skip_unpack:
        print("[unpack] 无壳，直接 jadx 反编译")
        return decompile_with_jadx(apk_path, output_dir)

    # ── Step 2B: 有壳路径 ──────────────────────────────────────────────────
    print(f"[unpack] 检测到壳: {primary_shell}，进入动态脱壳流程")
    print(f"[unpack] 使用脚本: {dump_script}")

    # 确认设备
    device = get_device(device)
    check_frida_server(device)

    # 安装 APK
    package = install_apk(apk_path, device)

    # 清理 dump 目录
    prepare_dump_dir(device)

    # 注入 Frida 脚本
    frida_proc = inject_frida_dump(package, dump_script, device)
    time.sleep(3)  # 等待注入完成

    # 触发 APP 启动（让壳解密 DEX）
    trigger_app_start(package, device)

    # 等待 dump 完成
    dump_files = wait_for_dumps(device)

    # 停止 frida
    frida_proc.terminate()

    if not dump_files:
        print("[warn] no DEX files dumped. Possible issues:")
        print("  - APP crashed before DEX was loaded")
        print("  - Frida hook didn't attach correctly")
        print("  - Shell uses a non-standard loading path")
        print("[warn] falling back to jadx direct decompile (may get stub DEX)")
        return decompile_with_jadx(apk_path, output_dir)

    # 拉取 dump 文件
    local_dump_dir = output_dir / "raw_dumps"
    dex_files = pull_dumps(device, local_dump_dir)

    # 修复 DEX header
    fixed_dex = fix_dex_files(dex_files, output_dir)

    if not fixed_dex:
        print("[warn] all DEX files invalid after fix, falling back to jadx")
        return decompile_with_jadx(apk_path, output_dir)

    # jadx 反编译
    return decompile_dex_files(fixed_dex, output_dir)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="自动化脱壳 + 反编译")
    parser.add_argument("--apk", required=True, help="APK 文件路径")
    parser.add_argument("--output-dir", required=True, help="输出目录（作为 Phase 1 的 target_dir）")
    parser.add_argument("--device", help="ADB 设备序列号（默认自动选择）")
    parser.add_argument("--skip-unpack", action="store_true", help="跳过脱壳，直接 jadx（用于调试）")
    args = parser.parse_args()

    apk_path = Path(args.apk)
    output_dir = Path(args.output_dir)

    try:
        target_dir = auto_unpack(apk_path, output_dir, args.device, args.skip_unpack)
        print(f"\n[unpack] === 完成 ===")
        print(f"[unpack] target_dir (传给 Phase 1): {target_dir}")

        # 写入一个 handoff 文件，让 Phase 1 能自动读取路径
        handoff = {
            "target_dir": str(target_dir),
            "apk_path": str(apk_path),
            "shell_info": json.loads((output_dir / "shell_report.json").read_text()),
            "analysis_mode": "local_source"
        }
        (output_dir / "phase0_handoff.json").write_text(
            json.dumps(handoff, ensure_ascii=False, indent=2)
        )
        print(f"[unpack] handoff written: {output_dir}/phase0_handoff.json")

    except Exception as e:
        print(f"[error] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
静态壳检测器 - 从 APK 文件识别加固类型，无需运行设备

原理：
  各家加固方案在 APK 内留有特征文件名、包名、字符串
  通过解析 APK 的 manifest 和文件列表即可识别

用法：
  python shell_detector.py --apk target.apk
  python shell_detector.py --apk target.apk --output shell_report.json
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


# ─── 壳特征库 ────────────────────────────────────────────────────────────────

SHELL_SIGNATURES: dict[str, dict] = {
    "360jiagu": {
        "name": "360加固保",
        "files": ["libjiagu.so", "libjiagu_a64.so", "libjiagu_x86.so", "libjiagu_x64.so"],
        "packages": ["com.qihoo.util", "com.qihoo.util.StubApp"],
        "strings": ["jiagu", "360jiagu"],
        "dump_script": "dex_dumper_360.js",
        "notes": "Hook DexFile.openDexFileNative 或 InMemoryDexClassLoader",
    },
    "tencent_legu": {
        "name": "腾讯乐固",
        "files": ["libshella-2.11.so", "libshellx-2.11.so", "libshella.so"],
        "packages": ["com.tencent.legu", "com.tencent.StubShell", "com.tencent.legu.StubApp"],
        "strings": ["legu", "tencent.legu"],
        "dump_script": "dex_dumper_art.js",
        "notes": "Hook InMemoryDexClassLoader，注意反Frida检测",
    },
    "bangcle": {
        "name": "梆梆加固",
        "files": ["libsecexe.so", "libSecShell.so", "libdexjni.so"],
        "packages": ["com.bangcle.comguard", "com.bangcle.comguard.StubApp"],
        "strings": ["bangcle", "comguard"],
        "dump_script": "dex_dumper_art.js",
        "notes": "Hook libdvm/libart 底层 OpenMemory",
    },
    "baidu": {
        "name": "百度加固",
        "files": ["libbaiduprotect.so", "libbaiduprotect_x86.so"],
        "packages": ["com.baidu.shield", "com.baidu.protect"],
        "strings": ["baiduprotect", "baidu.protect"],
        "dump_script": "dex_dumper_art.js",
        "notes": "通用 ART dump 即可",
    },
    "ijiami": {
        "name": "爱加密",
        "files": ["libexec.so", "libexecmain.so"],
        "packages": ["s.h.e.l.l", "com.ijiami.stub"],
        "strings": ["ijiami"],
        "dump_script": "dex_dumper_art.js",
        "notes": "注意 dex 分片，需要收集多个 dump 文件",
    },
    "kiwisec": {
        "name": "几维安全",
        "files": ["libkwscmm.so", "libkwscr.so", "libkwslinker.so"],
        "packages": ["com.kiwisec"],
        "strings": ["kiwisec"],
        "dump_script": "dex_dumper_art.js",
    },
    "qihoo_vmp": {
        "name": "360 VMP",
        "files": ["libprotectClass.so", "libjiagu_vmp.so"],
        "packages": [],
        "strings": ["vmp", "libprotectClass"],
        "dump_script": "dex_dumper_360.js",
        "notes": "VMP 部分方法体无法还原，只能拿到 stub DEX",
    },
    "ali_tongdun": {
        "name": "阿里聚安全/同盾",
        "files": ["libsgmain.so", "libSGMain.so", "libmobisec.so"],
        "packages": ["com.alibaba.wireless.security", "com.taobao.wireless.security"],
        "strings": ["sgmain", "mobisec", "tongdun"],
        "dump_script": "dex_dumper_art.js",
        "notes": "常见于淘宝系 APP，阿里自研，有较强反调试",
    },
    "netease_shield": {
        "name": "网易易盾",
        "files": ["libnesec.so"],
        "packages": ["com.netease.nis.nsprotect"],
        "strings": ["netease", "nesec"],
        "dump_script": "dex_dumper_art.js",
    },
}

# 轻度混淆（不是壳，但需要注意）
OBFUSCATION_INDICATORS = {
    "proguard": ["META-INF/proguard/", "proguard.cfg"],
    "r8": ["META-INF/com.android.tools/r8"],
    "dexguard": ["META-INF/CERT.RSA"],  # 不充分，只是暗示
}


# ─── 数据结构 ─────────────────────────────────────────────────────────────────

@dataclass
class ShellHit:
    signature_type: str  # "file" / "package" / "string"
    value: str
    confidence: float


@dataclass
class ShellResult:
    shell_type: str
    shell_name: str
    confidence: float          # 0.0 ~ 1.0
    hits: list[ShellHit] = field(default_factory=list)
    dump_script: str = ""
    notes: str = ""


@dataclass
class DetectionReport:
    apk_path: str
    package_name: str
    detected_shells: list[ShellResult] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)
    verdict: str = "clean"        # clean / packed / obfuscated / unknown
    primary_shell: str | None = None
    recommended_dump_script: str = ""
    analysis_ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── 检测逻辑 ─────────────────────────────────────────────────────────────────

def detect_shell(apk_path: str) -> DetectionReport:
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    report = DetectionReport(apk_path=str(path), package_name="unknown")

    with zipfile.ZipFile(path, "r") as apk:
        names = apk.namelist()
        report.package_name = _extract_package_name(apk)
        _check_shell_signatures(apk, names, report)
        _check_obfuscation(names, report)

    _finalize_verdict(report)
    return report


def _extract_package_name(apk: zipfile.ZipFile) -> str:
    """从 AndroidManifest.xml 中提取包名（二进制 XML 简单解析）"""
    try:
        with apk.open("AndroidManifest.xml") as f:
            raw = f.read()
            # 二进制 AXML 里包名以 UTF-16LE 存储
            # 简单扫描 package= 后面的字符串
            idx = raw.find(b"package")
            if idx != -1:
                chunk = raw[idx:idx + 200]
                match = re.search(rb"(?:com|org|net|io|cn|app)\.[a-zA-Z0-9._]+", chunk)
                if match:
                    return match.group(0).decode("ascii", errors="ignore")
    except Exception:
        pass
    return "unknown"


def _check_shell_signatures(apk: zipfile.ZipFile, names: list[str], report: DetectionReport):
    # 读取所有文件名（小写比较）
    names_lower = {n.lower(): n for n in names}

    # 读取 manifest 内容用于包名检测
    manifest_text = ""
    try:
        with apk.open("AndroidManifest.xml") as f:
            raw = f.read()
            manifest_text = raw.decode("latin-1")
    except Exception:
        pass

    for shell_id, sig in SHELL_SIGNATURES.items():
        hits: list[ShellHit] = []

        # 1. 文件特征
        for file_sig in sig.get("files", []):
            for name_lower, original_name in names_lower.items():
                if file_sig.lower() in name_lower:
                    hits.append(ShellHit("file", original_name, 0.9))

        # 2. 包名特征（在 manifest 二进制里找字符串）
        for pkg in sig.get("packages", []):
            if pkg.lower() in manifest_text.lower():
                hits.append(ShellHit("package", pkg, 0.95))

        # 3. 字符串特征（在 manifest 中）
        for s in sig.get("strings", []):
            if s.lower() in manifest_text.lower():
                hits.append(ShellHit("string", s, 0.6))

        if not hits:
            continue

        # 计算综合置信度
        max_conf = max(h.confidence for h in hits)
        # 多种类型命中则提升置信度
        types_hit = {h.signature_type for h in hits}
        if len(types_hit) >= 2:
            max_conf = min(1.0, max_conf + 0.05)

        result = ShellResult(
            shell_type=shell_id,
            shell_name=sig["name"],
            confidence=max_conf,
            hits=hits,
            dump_script=sig.get("dump_script", "dex_dumper_art.js"),
            notes=sig.get("notes", ""),
        )
        report.detected_shells.append(result)


def _check_obfuscation(names: list[str], report: DetectionReport):
    for obf_type, indicators in OBFUSCATION_INDICATORS.items():
        for indicator in indicators:
            if any(indicator in n for n in names):
                if obf_type not in report.obfuscation:
                    report.obfuscation.append(obf_type)


def _finalize_verdict(report: DetectionReport):
    if not report.detected_shells:
        report.verdict = "clean"
        report.primary_shell = None
        return

    # 按置信度排序，取最高
    report.detected_shells.sort(key=lambda r: r.confidence, reverse=True)
    best = report.detected_shells[0]

    report.primary_shell = best.shell_type
    report.recommended_dump_script = best.dump_script
    report.verdict = "packed"


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="静态 APK 壳检测器")
    parser.add_argument("--apk", required=True, help="APK 文件路径")
    parser.add_argument("--output", help="JSON 报告输出路径")
    args = parser.parse_args()

    report = detect_shell(args.apk)

    # 控制台输出
    print(f"\n=== APK 壳检测报告 ===")
    print(f"APK:     {report.apk_path}")
    print(f"包名:    {report.package_name}")
    print(f"结论:    {report.verdict.upper()}")

    if report.primary_shell:
        best = report.detected_shells[0]
        print(f"\n主要壳:  {best.shell_name} ({report.primary_shell})")
        print(f"置信度:  {best.confidence:.0%}")
        print(f"命中点:  {len(best.hits)} 个")
        for h in best.hits[:5]:
            print(f"  [{h.signature_type}] {h.value}")
        if best.notes:
            print(f"注意:    {best.notes}")
        print(f"\n推荐脚本: tools/frida/{report.recommended_dump_script}")
    else:
        print("无壳，可直接 jadx 反编译")

    if report.obfuscation:
        print(f"\n混淆:    {', '.join(report.obfuscation)}")

    # 输出 JSON
    data = asdict(report)
    if args.output:
        Path(args.output).write_text(json.dumps(data, ensure_ascii=False, indent=2))
        print(f"\n报告已写入: {args.output}")
    else:
        print(f"\n{json.dumps(data, ensure_ascii=False, indent=2)}")


if __name__ == "__main__":
    main()

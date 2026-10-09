#!/usr/bin/env python3
"""سِتر — مشغل فحص جنائي محلي موسّع للصور والملفات المشتبه بها.

يشغّل أدوات التحليل المثبتة محلياً إن وُجدت ويجمع نتائجها في تقرير JSON.
لا يرسل الملف إلى الشبكة، ولا يحدّث قواعد أو أدوات، ولا يجرب كلمات المرور.
لا يستخدم steghide إلا مع كلمة مرور يمرّرها المستخدم صراحةً.

أمثلة:
  python3 sitr_forensics.py image.png
  python3 sitr_forensics.py image.jpg --password 'known-passphrase' --out report.json
  python3 sitr_forensics.py image.png --yara-rules ./trusted-rules.yar
  python3 sitr_forensics.py image.png --text-limit 120 --full-strings

أدوات اختيارية مفيدة:
  exiftool   EXIF/IPTC/XMP/ICC ووسوم غير معروفة
  zsteg      تحليل PNG/BMP لمسارات LSB المعروفة
  stegdetect كشف احتمالي لبعض تقنيات JPEG (JSteg/OutGuess/JPHide)
  c2patool  فحص اختياري لبيانات C2PA / Content Credentials؛ يتطلب موافقة شبكية صريحة
  clamscan  فحص دفاعي للملف محلياً
  yara      فحص اختياري بقواعد موثوقة يحددها المستخدم
  steghide  معلومات فقط؛ extraction لا يتم تلقائياً
  binwalk   بصمات وحاويات مدمجة (دون استخراج)
  strings   سلاسل قابلة للعرض
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

MAX_CAPTURE = 1_500_000
MAX_RAW_SCAN = 16 * 1024 * 1024


def run(
    command: list[str],
    timeout: int = 90,
    status_by_returncode: dict[int, str] | None = None,
) -> dict[str, Any]:
    """يشغّل أداة محلية من دون shell ويحد طول المخرجات.

    لا تمرر هذه الدالة أي إدخال إلى الأداة، ولا تنفذ محارف shell من اسم الملف.
    """
    executable = command[0]
    if not shutil.which(executable):
        return {"status": "not_installed", "command": command}
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        statuses = status_by_returncode or {}
        status = statuses.get(
            completed.returncode,
            "ok" if completed.returncode == 0 else "tool_error",
        )
        stdout = completed.stdout[:MAX_CAPTURE]
        stderr = completed.stderr[:MAX_CAPTURE]
        return {
            "status": status,
            "returncode": completed.returncode,
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": len(completed.stdout) > MAX_CAPTURE or len(completed.stderr) > MAX_CAPTURE,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": command, "timeout_seconds": timeout}
    except OSError as error:
        return {"status": "runner_error", "command": command, "error": str(error)}


def available(names: Iterable[str]) -> str | None:
    """يعيد أول اسم تنفيذي موجود، لتغطية اختلاف تسميات أدوات C2PA."""
    return next((name for name in names if shutil.which(name)), None)


def shannon_entropy(blob: bytes, limit: int = 4 * 1024 * 1024) -> float:
    sample = blob[:limit]
    if not sample:
        return 0.0
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    size = len(sample)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


def raw_signatures(blob: bytes, offset_base: int = 0) -> list[dict[str, Any]]:
    signatures = {
        b"PK\x03\x04": "ZIP archive",
        b"\x1f\x8b\x08": "GZIP stream",
        b"Rar!\x1a\x07": "RAR archive",
        b"7z\xbc\xaf\x27\x1c": "7z archive",
        b"%PDF-": "PDF document",
        b"SQLite format 3\x00": "SQLite database",
        b"MZ": "Windows executable candidate (MZ)",
        b"\x7fELF": "ELF executable candidate",
        b"dex\n": "Android DEX candidate",
        b"\x00asm": "WebAssembly candidate",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "OLE document container",
        b"ID3": "MP3 audio candidate",
        b"WAVE": "WAVE identifier",
        b"jumb": "C2PA/JUMBF marker",
        b"JUMBF": "C2PA/JUMBF marker",
        b"c2pa": "C2PA claim marker",
        b"C2PA": "C2PA claim marker",
        b"SITR": "Sitr V2 marker",
        b"SANA": "Sitr V1 marker",
    }
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for marker, name in signatures.items():
        cursor = 0
        for _ in range(8):
            pos = blob.find(marker, cursor)
            if pos < 0:
                break
            absolute = offset_base + pos
            key = (name, absolute)
            if key not in seen:
                seen.add(key)
                found.append({"name": name, "offset": absolute})
            cursor = pos + len(marker)
    return found


def file_identity(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    # لا نحمّل ملفاً بحجم مئات الميغابايت إلى الذاكرة: نقرأ مقدمة ونهاية محدودتين فقط.
    with path.open("rb") as handle:
        head = handle.read(min(size, MAX_RAW_SCAN))
        tail = b""
        tail_offset = 0
        if size > MAX_RAW_SCAN:
            tail_offset = max(0, size - MAX_RAW_SCAN)
            handle.seek(tail_offset)
            tail = handle.read(MAX_RAW_SCAN)
    findings = raw_signatures(head)
    if tail:
        findings.extend(raw_signatures(tail, tail_offset))
    dedup = {(item["name"], item["offset"]): item for item in findings}
    entropy = shannon_entropy(head)
    return {
        "name": path.name,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "magic_hex": head[:24].hex(" "),
        "raw_entropy_bits_per_byte": round(entropy, 6),
        "entropy_sample_bytes": min(len(head), 4 * 1024 * 1024),
        "high_entropy_note": (
            "قد يكون الملف مضغوطاً أو مشفراً؛ الإنتروبيا ليست دليلاً على تشفير أو إخفاء."
            if entropy > 7.8
            else None
        ),
        "signatures": sorted(dedup.values(), key=lambda item: (item["offset"], item["name"])),
    }


def c2pa_module(path: Path, allow_network: bool) -> dict[str, Any]:
    """يتحقق من C2PA اختيارياً؛ c2patool قد يجلب manifest بعيداً افتراضياً."""
    if not allow_network:
        return {
            "status": "not_run",
            "reason": (
                "لم يُشغّل c2patool في الوضع الافتراضي غير المتصل؛ قد تجلب بعض إصداراته "
                "manifest بعيداً. مرّر --allow-c2pa-network بعد مراجعة الملف وسياسة الشبكة."
            ),
        }
    tool = available(("c2patool",))
    if not tool:
        return {
            "status": "not_installed",
            "command": ["c2patool", str(path)],
            "note": "ثبّت c2patool محلياً للتحقق التشفيري من Content Credentials.",
        }
    # المسار الموضعي يعرض ما يتيحه الإصدار المثبّت من manifest وحالة التحقق.
    return run([tool, str(path)], timeout=120)


def clamav_module(path: Path, skipped: bool) -> dict[str, Any]:
    if skipped:
        return {"status": "skipped", "reason": "طُلب تخطي فحص ClamAV."}
    # code 1 يعني اكتشافاً لدى clamscan وليس عطلاً في الأداة.
    return run(
        ["clamscan", "--no-summary", "--infected", str(path)],
        timeout=300,
        status_by_returncode={1: "detection"},
    )


def yara_module(path: Path, rules: Path | None) -> dict[str, Any]:
    if rules is None:
        return {
            "status": "not_run",
            "reason": "لم تُحدد قواعد YARA. مرّر --yara-rules لمسار قواعد موثوقة تتحكم بها.",
        }
    if not rules.is_file():
        return {"status": "skipped", "reason": f"ملف قواعد YARA غير موجود: {rules}"}
    tool = available(("yara", "yara64"))
    if not tool:
        return {"status": "not_installed", "command": ["yara", "--no-warnings", str(rules), str(path)]}
    return run([tool, "--no-warnings", str(rules), str(path)], timeout=180)


def main() -> int:
    parser = argparse.ArgumentParser(description="مشغل سِتر للفحص الجنائي المحلي الموسع")
    parser.add_argument("image", type=Path, help="الصورة أو الملف المراد فحصه")
    parser.add_argument(
        "--password",
        help="كلمة مرور معروفة فقط لاختبار steghide؛ لا توجد محاولة تخمين أو cracking",
    )
    parser.add_argument("--out", type=Path, default=Path("sitr-forensics-report.json"), help="مسار تقرير JSON")
    parser.add_argument("--full-strings", action="store_true", help="خفض حد strings من 120 إلى 24 حرفاً")
    parser.add_argument("--yara-rules", type=Path, help="مسار قواعد YARA موثوقة محلياً (اختياري)")
    parser.add_argument("--skip-clamav", action="store_true", help="تخطي ClamAV حتى لو كان مثبتاً")
    parser.add_argument(
        "--allow-c2pa-network",
        action="store_true",
        help="السماح لـ c2patool بجلب manifests بعيدة إن طلبها الملف؛ الافتراضي غير متصل",
    )
    args = parser.parse_args()

    path = args.image.expanduser().resolve()
    if not path.is_file():
        parser.error(f"الملف غير موجود: {path}")
    if path.stat().st_size > 750 * 1024 * 1024:
        parser.error("الملف أكبر من حد المشغل الآمن: 750 م.ب")

    rules = args.yara_rules.expanduser().resolve() if args.yara_rules else None
    minimum = "24" if args.full_strings else "120"
    tools = ("exiftool", "zsteg", "stegdetect", "c2patool", "clamscan", "yara", "yara64", "steghide", "binwalk", "strings")
    report: dict[str, Any] = {
        "tool": "Sitr Forensics Runner",
        "version": "2.2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "offline_only": not args.allow_c2pa_network,
        "c2pa_network_policy": (
            "allowed by explicit --allow-c2pa-network"
            if args.allow_c2pa_network
            else "blocked; c2patool not invoked"
        ),
        "safety_note": (
            "النتائج مؤشرية. لا يمكن فك تشفير أو إخفاء معتمد على مفتاح بدون المفتاح الصحيح. "
            "بصمات البرامج التنفيذية ليست حكماً بوجود برمجية ضارة؛ راجع ClamAV/YARA وسياق الملف."
        ),
        "file": file_identity(path),
        "tool_availability": {name: bool(shutil.which(name)) for name in tools},
        "modules": {},
    }

    # ExifTool: EXIF/IPTC/XMP/ICC ووسوم غير معروفة، مع إخراج JSON فقط.
    report["modules"]["exiftool"] = run(["exiftool", "-j", "-G1", "-a", "-u", str(path)])
    # يقرأ النصوص الظاهرة من الملف الخام. لا ينفذ المحتوى ولا يفتحه كأرشيف.
    report["modules"]["strings"] = run(["strings", "-a", "-n", minimum, str(path)])
    # Binwalk للمؤشرات والبصمات فقط: لا نستخدم -e أو استخراجاً آلياً.
    report["modules"]["binwalk"] = run(["binwalk", str(path)])
    report["modules"]["c2pa"] = c2pa_module(path, args.allow_c2pa_network)
    report["modules"]["clamav"] = clamav_module(path, args.skip_clamav)
    report["modules"]["yara"] = yara_module(path, rules)

    suffix = path.suffix.lower()
    if suffix in {".png", ".bmp"}:
        report["modules"]["zsteg"] = run(["zsteg", "-a", str(path)], timeout=180)
    else:
        report["modules"]["zsteg"] = {"status": "skipped", "reason": "zsteg يركز على PNG/BMP"}

    if suffix in {".jpg", ".jpeg"}:
        report["modules"]["stegdetect"] = run(["stegdetect", "-s", "1.0", str(path)], timeout=180)
    else:
        report["modules"]["stegdetect"] = {
            "status": "skipped",
            "reason": "stegdetect مخصص لتقدير بعض تقنيات JPEG فقط؛ النتيجة احتمالية وليست استخراجاً.",
        }

    if suffix in {".jpg", ".jpeg", ".bmp", ".wav", ".au"}:
        # لا تُنشأ ملفات استخراج تلقائياً؛ و-p يستخدم كلمة يملكها المستخدم فقط عند إدخالها.
        info_cmd = ["steghide", "info", "-p", args.password or "", str(path)]
        report["modules"]["steghide_info"] = run(info_cmd)
        report["modules"]["steghide_extract"] = {
            "status": "not_run",
            "reason": "لا ينشئ المشغل ملفات مخفية تلقائياً. استخرج يدوياً بعد مراجعة info وبكلمة مرور تملكها.",
        }
    else:
        report["modules"]["steghide_info"] = {"status": "skipped", "reason": "صيغة غير مدعومة عادةً من steghide"}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"تم إنشاء التقرير: {args.out.resolve()}")
    ready = [name for name, ok in report["tool_availability"].items() if ok]
    print("الأدوات المتاحة:", ", ".join(ready) or "لا توجد أدوات خارجية مثبتة")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

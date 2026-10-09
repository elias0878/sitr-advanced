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
  Aletheia  تقييم احتمالي لـ OutGuess/Steghide/nsF5/J-UNIWARD وRS/SPA/WS، بلا brute force
  StegExpose JAR  RS/Sample Pairs/Chi-square/Primary Sets fusion عند تمرير مسار JAR موثوق
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
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

MAX_CAPTURE = 1_500_000
MAX_RAW_SCAN = 16 * 1024 * 1024
RAW_SIGNATURES: dict[bytes, str] = {
    b"PK\x03\x04": "ZIP archive",
    b"\x1f\x8b\x08": "GZIP stream",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7z archive",
    b"%PDF-": "PDF document",
    b"SQLite format 3\x00": "SQLite database",
    b"\x89PNG\r\n\x1a\n": "PNG image candidate",
    b"\xff\xd8\xff": "JPEG image candidate",
    b"GIF8": "GIF image candidate",
    b"II*\x00": "TIFF image candidate",
    b"MM\x00*": "TIFF image candidate",
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
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for marker, name in RAW_SIGNATURES.items():
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


def scan_file_signatures(path: Path, size: int) -> list[dict[str, Any]]:
    """يمسح كامل الملف على دفعات مع تداخل قصير، من دون تحميله كله في الذاكرة."""
    block_size = 4 * 1024 * 1024
    overlap_size = max(len(marker) for marker in RAW_SIGNATURES) - 1
    found: dict[tuple[str, int], dict[str, Any]] = {}
    counts: dict[str, int] = {}
    offset = 0
    overlap = b""
    with path.open("rb") as handle:
        while block := handle.read(block_size):
            data = overlap + block
            data_offset = offset - len(overlap)
            for item in raw_signatures(data, data_offset):
                name = str(item["name"])
                key = (name, int(item["offset"]))
                if key not in found and counts.get(name, 0) < 8:
                    found[key] = item
                    counts[name] = counts.get(name, 0) + 1
            overlap = data[-overlap_size:]
            offset += len(block)
    return sorted(found.values(), key=lambda item: (item["offset"], item["name"]))


def file_identity(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    digest = hashlib.sha256()
    entropy_sample = bytearray()
    magic = b""
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            if not magic:
                magic = block[:24]
            if len(entropy_sample) < 4 * 1024 * 1024:
                entropy_sample.extend(block[: 4 * 1024 * 1024 - len(entropy_sample)])
            digest.update(block)
    entropy = shannon_entropy(bytes(entropy_sample))
    return {
        "name": path.name,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "magic_hex": magic.hex(" "),
        "raw_entropy_bits_per_byte": round(entropy, 6),
        "entropy_sample_bytes": len(entropy_sample),
        "signature_scan_scope": "full file, streamed in 4 MB blocks",
        "high_entropy_note": (
            "قد يكون الملف مضغوطاً أو مشفراً؛ الإنتروبيا ليست دليلاً على تشفير أو إخفاء."
            if entropy > 7.8
            else None
        ),
        "signatures": scan_file_signatures(path, size),
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


def aletheia_module(path: Path, suffix: str) -> dict[str, Any]:
    """يشغل كاشف Aletheia فقط؛ لا يستدعي أية أوامر brute-force الموجودة في الأداة."""
    tool = available(("aletheia.py", "aletheia"))
    if not tool:
        return {"status": "not_installed", "command": ["aletheia.py", "auto", "<directory>"]}
    if suffix not in {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff"}:
        return {"status": "skipped", "reason": "Aletheia هنا مقصور على مسارات الصور المدعومة"}
    # auto موثق للـ JPEG؛ نضع نسخة/رابطاً مؤقتاً في مجلد ليبقى الإدخال read-only.
    if suffix in {".jpg", ".jpeg"}:
        with tempfile.TemporaryDirectory(prefix="sitr-aletheia-") as directory:
            linked = Path(directory) / path.name
            try:
                os.symlink(path, linked)
            except OSError:
                shutil.copy2(path, linked)
            result = run([tool, "auto", directory], timeout=300)
            result["note"] = "Aletheia auto: احتمالات OutGuess/Steghide/nsF5/J-UNIWARD فقط؛ لا brute-force."
            return result
    checks = {name: run([tool, name, str(path)], timeout=240) for name in ("rs", "spa", "ws")}
    return {
        "status": "completed",
        "mode": "structural LSB statistics",
        "note": "Aletheia RS/SPA/WS هي مؤشرات إحصائية وليست استرداد حمولة.",
        "checks": checks,
    }


def stegexpose_module(path: Path, suffix: str, jar: Path | None) -> dict[str, Any]:
    """يشغل StegExpose اختيارياً في مجلد مؤقت، بلا استخراج ملفات أو تشغيل حمولة."""
    if jar is None:
        return {"status": "not_run", "reason": "مرر --stegexpose-jar لمسار JAR محلي موثوق لتفعيل RS/SPA/χ²/Primary Sets fusion."}
    if not jar.is_file():
        return {"status": "skipped", "reason": f"ملف StegExpose JAR غير موجود: {jar}"}
    if suffix not in {".png", ".bmp", ".jpg", ".jpeg"}:
        return {"status": "skipped", "reason": "صيغة غير مناسبة لفحص StegExpose"}
    if not shutil.which("java"):
        return {"status": "not_installed", "command": ["java", "-jar", str(jar), "<directory>"]}
    with tempfile.TemporaryDirectory(prefix="sitr-stegexpose-") as directory:
        linked = Path(directory) / path.name
        try:
            os.symlink(path, linked)
        except OSError:
            shutil.copy2(path, linked)
        result = run(["java", "-jar", str(jar), directory], timeout=300)
        result["note"] = "StegExpose fusion (RS/Sample Pairs/χ²/Primary Sets) مؤشر احتمالي فقط؛ لا payload recovery."
        return result


def structure_modules(path: Path, suffix: str, signatures: set[str]) -> dict[str, dict[str, Any]]:
    """فاحصات قراءة فقط للحاويات التي ظهرت بصماتها؛ لا تستخرج ملفات إلى القرص."""
    modules: dict[str, dict[str, Any]] = {}
    if suffix == ".png":
        modules["pngcheck"] = run(["pngcheck", "-v", str(path)])
    else:
        modules["pngcheck"] = {"status": "skipped", "reason": "ليس PNG حسب الامتداد"}
    if suffix in {".jpg", ".jpeg"}:
        modules["jpeginfo"] = run(["jpeginfo", "-c", str(path)])
    else:
        modules["jpeginfo"] = {"status": "skipped", "reason": "ليس JPEG حسب الامتداد"}
    if "PDF document" in signatures:
        modules["pdfinfo"] = run(["pdfinfo", str(path)])
    else:
        modules["pdfinfo"] = {"status": "skipped", "reason": "لا توجد بصمة PDF"}
    archive = bool({"ZIP archive", "RAR archive", "7z archive"} & signatures)
    if archive:
        modules["zipinfo"] = run(["zipinfo", "-l", str(path)])
        seven_zip = available(("7z", "7zz"))
        modules["7z_listing"] = run([seven_zip, "l", "-slt", str(path)], timeout=180) if seven_zip else {"status": "not_installed", "command": ["7z", "l", "-slt", str(path)]}
    else:
        modules["zipinfo"] = {"status": "skipped", "reason": "لا توجد بصمة أرشيف"}
        modules["7z_listing"] = {"status": "skipped", "reason": "لا توجد بصمة أرشيف"}
    if "OLE document container" in signatures:
        modules["oleid"] = run(["oleid", str(path)])
    else:
        modules["oleid"] = {"status": "skipped", "reason": "لا توجد بصمة OLE"}
    media = bool({"MP3 audio candidate", "WAVE identifier"} & signatures) or suffix in {".mp3", ".wav", ".webm", ".mp4", ".mov"}
    if media:
        modules["ffprobe"] = run(["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(path)])
    else:
        modules["ffprobe"] = {"status": "skipped", "reason": "لا توجد بصمة وسائط صوتية/فيديو"}
    return modules


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
    parser.add_argument("--stegexpose-jar", type=Path, help="مسار StegExpose JAR محلي موثوق (اختياري، قراءة فقط)")
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
    stegexpose_jar = args.stegexpose_jar.expanduser().resolve() if args.stegexpose_jar else None
    minimum = "24" if args.full_strings else "120"
    identity = file_identity(path)
    signature_names = {str(item["name"]) for item in identity["signatures"]}
    tools = ("exiftool", "zsteg", "stegdetect", "aletheia.py", "aletheia", "c2patool", "clamscan", "yara", "yara64", "steghide", "binwalk", "strings", "file", "pngcheck", "jpeginfo", "pdfinfo", "zipinfo", "7z", "7zz", "oleid", "ffprobe", "java")
    report: dict[str, Any] = {
        "tool": "Sitr Forensics Runner",
        "version": "2.5",
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
        "file": identity,
        "tool_availability": {name: bool(shutil.which(name)) for name in tools},
        "modules": {},
    }

    suffix = path.suffix.lower()
    # ExifTool: قراءة EXIF/IPTC/XMP/ICC والوسوم المضمنة بصورة أعمق، مع إخراج JSON فقط.
    report["modules"]["exiftool"] = run(["exiftool", "-j", "-G1", "-a", "-u", "-ee3", "-api", "RequestAll=3", str(path)], timeout=180)
    # سلاسل ASCII وUTF-16: قراءة فقط من الملف الخام، من دون تنفيذ أو استخراج تلقائي.
    report["modules"]["strings_ascii"] = run(["strings", "-a", "-n", minimum, str(path)])
    report["modules"]["strings_utf16le"] = run(["strings", "-a", "-e", "l", "-n", minimum, str(path)])
    report["modules"]["strings_utf16be"] = run(["strings", "-a", "-e", "b", "-n", minimum, str(path)])
    report["modules"]["file_identity"] = run(["file", "-b", "--mime-type", "--mime-encoding", str(path)])
    # Binwalk للمؤشرات والبصمات/الإنتروبيا فقط: لا نستخدم -e أو استخراجاً آلياً.
    report["modules"]["binwalk"] = run(["binwalk", "--signature", str(path)])
    report["modules"]["binwalk_entropy"] = run(["binwalk", "--entropy", "--nplot", str(path)], timeout=180)
    report["modules"].update(structure_modules(path, suffix, signature_names))
    report["modules"]["aletheia"] = aletheia_module(path, suffix)
    report["modules"]["stegexpose"] = stegexpose_module(path, suffix, stegexpose_jar)
    report["modules"]["c2pa"] = c2pa_module(path, args.allow_c2pa_network)
    report["modules"]["clamav"] = clamav_module(path, args.skip_clamav)
    report["modules"]["yara"] = yara_module(path, rules)

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

    report["evidence_summary"] = {
        "signature_candidates": len(identity["signatures"]),
        "signature_scan_scope": identity["signature_scan_scope"],
        "external_modules": {
            name: module.get("status", "nested")
            for name, module in report["modules"].items()
        },
        "interpretation": {
            "recovered": "محتوى فكّته حاوية/أداة بصورة قابلة للعرض",
            "carved_candidate": "بداية stream/ملف تحتاج parsing أو فحصاً مستقلاً",
            "structural_indicator": "دليل بنيوي مثل tail أو chunk غير معياري",
            "statistical_indicator": "مؤشر احتمالي لا يثبت وجود حمولة",
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"تم إنشاء التقرير: {args.out.resolve()}")
    ready = [name for name, ok in report["tool_availability"].items() if ok]
    print("الأدوات المتاحة:", ", ".join(ready) or "لا توجد أدوات خارجية مثبتة")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""سِتر — مشغل فحص جنائي محلي موسّع للصور.

يشغّل أدوات التحليل المثبتة محلياً إن وُجدت ويجمع النتائج في تقرير JSON.
لا يرسل ملفات إلى الشبكة، ولا يجرب كلمات مرور، ولا يستخرج حمولة محمية
إلا عند تمرير كلمة مرور يملكها المستخدم صراحةً.

أمثلة:
  python3 sitr_forensics.py image.png
  python3 sitr_forensics.py image.jpg --password 'known-passphrase' --out report.json
  python3 sitr_forensics.py image.png --text-limit 120 --full-strings

أدوات اختيارية مفيدة:
  exiftool   metadata متقدم
  zsteg      تحليل PNG/BMP ومسارات LSB المعروفة
  steghide   معلومات/استخراج JPEG أو BMP عند وجود كلمة مرور معروفة
  binwalk    بصمات وحاويات مدمجة
  strings    سلاسل قابلة للعرض
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_CAPTURE = 1_500_000


def run(command: list[str], timeout: int = 90) -> dict[str, Any]:
    """يشغّل أداة محلية من دون shell ويحد طول المخرجات."""
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
        stdout = completed.stdout[:MAX_CAPTURE]
        stderr = completed.stderr[:MAX_CAPTURE]
        return {
            "status": "ok" if completed.returncode == 0 else "tool_error",
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


def raw_signatures(blob: bytes) -> list[dict[str, Any]]:
    signatures = {
        b"PK\x03\x04": "ZIP archive",
        b"\x1f\x8b\x08": "GZIP stream",
        b"Rar!\x1a\x07": "RAR archive",
        b"7z\xbc\xaf\x27\x1c": "7z archive",
        b"%PDF-": "PDF document",
        b"SITR": "Sitr V2 marker",
        b"SANA": "Sitr V1 marker",
        b"SQLite format 3\x00": "SQLite database",
    }
    # افحص البداية وآخر 8MB؛ يكفي للحاويات المضافة بلا قراءة متكررة ضخمة.
    regions = [(0, min(len(blob), 8 * 1024 * 1024))]
    if len(blob) > 8 * 1024 * 1024:
        regions.append((max(0, len(blob) - 8 * 1024 * 1024), len(blob)))
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for marker, name in signatures.items():
        for start, end in regions:
            cursor = start
            for _ in range(8):
                pos = blob.find(marker, cursor, end)
                if pos < 0:
                    break
                key = (name, pos)
                if key not in seen:
                    seen.add(key)
                    found.append({"name": name, "offset": pos})
                cursor = pos + len(marker)
    return found


def file_identity(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    blob = path.read_bytes()
    return {
        "name": path.name,
        "bytes": len(blob),
        "sha256": digest.hexdigest(),
        "magic_hex": blob[:24].hex(" "),
        "signatures": raw_signatures(blob),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="مشغل سِتر للفحص الجنائي المحلي الموسع")
    parser.add_argument("image", type=Path, help="الصورة أو الملف المراد فحصه")
    parser.add_argument("--password", help="كلمة مرور معروفة فقط لاختبار steghide؛ لا توجد محاولة تخمين")
    parser.add_argument("--out", type=Path, default=Path("sitr-forensics-report.json"), help="مسار تقرير JSON")
    parser.add_argument("--full-strings", action="store_true", help="رفع حد strings من 120 إلى 24 حرفاً")
    args = parser.parse_args()

    path = args.image.expanduser().resolve()
    if not path.is_file():
        parser.error(f"الملف غير موجود: {path}")
    if path.stat().st_size > 750 * 1024 * 1024:
        parser.error("الملف أكبر من حد المشغل الآمن: 750 م.ب")

    minimum = "24" if args.full_strings else "120"
    report: dict[str, Any] = {
        "tool": "Sitr Forensics Runner",
        "version": "2.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "offline_only": True,
        "note": "النتائج مؤشرية. لا يمكن فك تشفير أو إخفاء معتمد على مفتاح بدون المفتاح الصحيح.",
        "file": file_identity(path),
        "tool_availability": {name: bool(shutil.which(name)) for name in ("exiftool", "zsteg", "steghide", "binwalk", "strings")},
        "modules": {},
    }

    # ExifTool يقرأ EXIF/IPTC/XMP/ICC ووسوماً غير معروفة مع المحافظة على صيغة JSON.
    report["modules"]["exiftool"] = run(["exiftool", "-j", "-G1", "-a", "-u", str(path)])
    # يقرأ النصوص الظاهرة من الملف الخام. لا ينفذ المحتوى ولا يفتحه كأرشيف.
    report["modules"]["strings"] = run(["strings", "-a", "-n", minimum, str(path)])
    # Binwalk للمؤشرات والبصمات فقط: لا نستخدم -e أو استخراجاً آلياً.
    report["modules"]["binwalk"] = run(["binwalk", str(path)])

    suffix = path.suffix.lower()
    if suffix in {".png", ".bmp"}:
        report["modules"]["zsteg"] = run(["zsteg", "-a", str(path)], timeout=180)
    else:
        report["modules"]["zsteg"] = {"status": "skipped", "reason": "zsteg يركز على PNG/BMP"}

    if suffix in {".jpg", ".jpeg", ".bmp", ".wav", ".au"}:
        info_cmd = ["steghide", "info", "-p", args.password or "", str(path)]
        report["modules"]["steghide_info"] = run(info_cmd)
        report["modules"]["steghide_extract"] = {
            "status": "not_run",
            "reason": "يجب تنفيذ الاستخراج يدوياً إلى مجلد تحدده أنت بعد مراجعة steghide_info؛ لا ينشئ المشغل ملفات مخفية تلقائياً.",
        }
    else:
        report["modules"]["steghide_info"] = {"status": "skipped", "reason": "صيغة غير مدعومة عادةً من steghide"}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"تم إنشاء التقرير: {args.out.resolve()}")
    print("الأدوات المتاحة:", ", ".join(name for name, ok in report["tool_availability"].items() if ok) or "لا توجد أدوات خارجية مثبتة")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

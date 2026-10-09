#!/usr/bin/env python3
"""محرك سِتر المحلي للتحليل الجنائي العميق.

يعالج الملف محلياً فقط ولا ينفذ أي حمولة ولا يحاول تخمين كلمات مرور.
هذا المحرك متعمد أن يكون محافظاً: نحت الملفات اختياري، وفك الضغط محدود
بالحجم، وكل نتيجة تحمل نوع الدليل بدلاً من ادعاء استرداد غير متحقق.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import math
import re
import struct
import zlib
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

STREAM_BLOCK = 1024 * 1024
MAX_ARTIFACTS = 80
MAX_CARVE_BYTES = 16 * 1024 * 1024
MAX_DECOMPRESSED = 1024 * 1024
MAX_PIXEL_BYTES = 192 * 1024
MAX_PIXELS = 12_000_000

# تؤخذ هذه البصمات كمرشحات نحت فقط؛ لا تعني أي بصمة أن الملف صالح أو ضار.
DEEP_SIGNATURES: dict[bytes, str] = {
    b"PK\x03\x04": "ZIP archive",
    b"PK\x05\x06": "ZIP end record",
    b"\x1f\x8b\x08": "GZIP stream",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7z archive",
    b"%PDF-": "PDF document",
    b"SQLite format 3\x00": "SQLite database",
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF8": "GIF image",
    b"II*\x00": "TIFF image",
    b"MM\x00*": "TIFF image",
    b"MZ": "Windows executable candidate",
    b"\x7fELF": "ELF executable candidate",
    b"dex\n": "Android DEX candidate",
    b"\x00asm": "WebAssembly candidate",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "OLE document container",
    b"ID3": "MP3 ID3 tag",
    b"WAVE": "WAVE identifier",
    b"jumb": "JUMBF marker",
    b"c2pa": "C2PA marker",
    b"SITR": "Sitr V2 marker",
    b"SANA": "Sitr V1 marker",
}


def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.1f} GB"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _safe_text(data: bytes, limit: int = 900) -> str:
    data = data[:limit]
    text = data.decode("utf-8", "replace").replace("\x00", "·")
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
    if text and printable / len(text) >= 0.72 and "�" not in text:
        return " ".join(text.split())[:limit]
    return "[binary] " + data[:72].hex(" ")


def _ascii_runs(data: bytes, base: int, minimum: int = 32, limit: int = 12) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, data):
        results.append({"offset": base + match.start(), "text": match.group()[:900].decode("ascii", "replace")})
        if len(results) >= limit:
            break
    return results


def _utf16_runs(data: bytes, base: int, little: bool, limit: int = 5) -> list[dict[str, Any]]:
    encoding = "utf-16le" if little else "utf-16be"
    try:
        text = data[:256 * 1024].decode(encoding, "replace")
    except UnicodeError:
        return []
    out: list[dict[str, Any]] = []
    for match in re.finditer(r"[\w\u0600-\u06ff][\w\u0600-\u06ff\s.,;:!?()\-]{15,500}", text):
        value = " ".join(match.group().split())
        if "�" not in value:
            out.append({"offset": base + match.start() * 2, "text": value[:900], "encoding": encoding})
        if len(out) >= limit:
            break
    return out


def _find_all(data: bytes, needle: bytes, base: int = 0, cap: int = 8) -> list[int]:
    positions: list[int] = []
    at = 0
    while len(positions) < cap:
        at = data.find(needle, at)
        if at < 0:
            break
        positions.append(base + at)
        at += max(1, len(needle))
    return positions


def scan_signatures(path: Path, per_type_cap: int = 8) -> list[dict[str, Any]]:
    """يمسح الملف كاملاً بدفق وتداخل حتى لا تفوت البصمات عند حدود الدفعات."""
    overlap_len = max(map(len, DEEP_SIGNATURES)) - 1
    overlap = b""
    offset = 0
    counts: Counter[str] = Counter()
    found: dict[tuple[str, int], dict[str, Any]] = {}
    with path.open("rb") as handle:
        while block := handle.read(STREAM_BLOCK):
            data = overlap + block
            base = offset - len(overlap)
            for magic, name in DEEP_SIGNATURES.items():
                if counts[name] >= per_type_cap:
                    continue
                for position in _find_all(data, magic, base, per_type_cap - counts[name]):
                    key = (name, position)
                    if key not in found:
                        found[key] = {"name": name, "offset": position}
                        counts[name] += 1
            overlap = data[-overlap_len:]
            offset += len(block)
    return sorted(found.values(), key=lambda item: (item["offset"], item["name"]))


def read_window(path: Path, offset: int, limit: int = MAX_CARVE_BYTES) -> bytes:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(limit)


def _png_end(data: bytes) -> int | None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    while pos + 12 <= len(data):
        size = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        end = pos + 12 + size
        if end > len(data):
            return None
        if kind == b"IEND":
            return end
        pos = end
    return None


def _jpeg_end(data: bytes) -> int | None:
    at = data.find(b"\xff\xd9", 2)
    return at + 2 if at >= 0 else None


def _gif_end(data: bytes) -> int | None:
    at = data.find(b"\x3b", 6)
    return at + 1 if at >= 0 else None


def _pdf_end(data: bytes) -> int | None:
    at = data.rfind(b"%%EOF")
    if at < 0:
        return None
    end = at + 5
    while end < len(data) and data[end] in b"\r\n \t":
        end += 1
    return end


def _zip_end(data: bytes) -> int | None:
    at = data.rfind(b"PK\x05\x06")
    if at < 0 or at + 22 > len(data):
        return None
    comment = int.from_bytes(data[at + 20 : at + 22], "little")
    end = at + 22 + comment
    return end if end <= len(data) else None


def artifact_boundary(kind: str, data: bytes) -> tuple[int | None, str]:
    if kind == "PNG image":
        return _png_end(data), "PNG IEND"
    if kind == "JPEG image":
        return _jpeg_end(data), "JPEG EOI"
    if kind == "GIF image":
        return _gif_end(data), "GIF trailer"
    if kind == "PDF document":
        return _pdf_end(data), "PDF EOF"
    if kind == "ZIP archive":
        return _zip_end(data), "ZIP EOCD"
    return None, "bounded preview"


def parse_pdf(data: bytes) -> dict[str, Any]:
    text = data[:2 * 1024 * 1024].decode("latin-1", "replace")
    metadata: dict[str, str] = {}
    for key in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"):
        match = re.search(rf"/{key}\s*(?:\(([^)]{{1,900}})\)|<([0-9A-Fa-f]{{2,1800}})>)", text)
        if match:
            metadata[key] = (match.group(1) or match.group(2) or "")[:900]
    return {
        "objects_visible": len(re.findall(r"\b\d+\s+\d+\s+obj\b", text)),
        "embedded_file_marker": bool(re.search(r"/EmbeddedFile\b", text)),
        "javascript_marker": bool(re.search(r"/(?:JavaScript|JS)\b", text)),
        "metadata": metadata,
    }


def parse_zip(data: bytes) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            rows = []
            encrypted = 0
            for info in archive.infolist()[:200]:
                encrypted += int(bool(info.flag_bits & 1))
                rows.append(
                    {
                        "name": info.filename,
                        "compressed": info.compress_size,
                        "uncompressed": info.file_size,
                        "method": info.compress_type,
                        "encrypted": bool(info.flag_bits & 1),
                        "crc32": f"{info.CRC:08x}",
                    }
                )
            return {"valid": True, "entries": rows, "entry_count": len(archive.infolist()), "encrypted_entries": encrypted}
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        return {"valid": False, "error": str(error)}


def parse_id3(data: bytes) -> dict[str, Any]:
    if len(data) < 10 or data[:3] != b"ID3":
        return {"valid": False}
    version = data[3]
    size = ((data[6] & 0x7F) << 21) | ((data[7] & 0x7F) << 14) | ((data[8] & 0x7F) << 7) | (data[9] & 0x7F)
    fields: dict[str, str] = {}
    labels = {"TIT2": "title", "TPE1": "artist", "TALB": "album", "TCON": "genre", "TDRC": "date", "TYER": "year", "COMM": "comment"}
    pos = 10
    end = min(len(data), 10 + size)
    for _ in range(100):
        if pos + 10 > end:
            break
        frame = data[pos : pos + 4].decode("ascii", "replace")
        if not re.fullmatch(r"[A-Z0-9]{4}", frame):
            break
        length = int.from_bytes(data[pos + 4 : pos + 8], "big")
        if not length or pos + 10 + length > end:
            break
        raw = data[pos + 10 : pos + 10 + length]
        if frame in labels and raw:
            encoding = raw[0]
            body = raw[1:]
            codec = "latin-1" if encoding == 0 else "utf-8" if encoding == 3 else "utf-16"
            fields[labels[frame]] = _safe_text(body.decode(codec, "replace").encode("utf-8", "replace"), 800)
        pos += 10 + length
    return {"valid": True, "version": version, "tag_bytes": size, "fields": fields}


def parse_wave(data: bytes) -> dict[str, Any]:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return {"valid": False}
    pos = 12
    info: dict[str, Any] = {"valid": True, "chunks": []}
    while pos + 8 <= len(data) and len(info["chunks"]) < 160:
        kind = data[pos : pos + 4].decode("ascii", "replace")
        size = int.from_bytes(data[pos + 4 : pos + 8], "little")
        start, end = pos + 8, pos + 8 + size
        if end > len(data):
            break
        row: dict[str, Any] = {"type": kind, "size": size}
        if kind == "fmt " and size >= 16:
            row["audio"] = {
                "format": int.from_bytes(data[start : start + 2], "little"),
                "channels": int.from_bytes(data[start + 2 : start + 4], "little"),
                "sample_rate": int.from_bytes(data[start + 4 : start + 8], "little"),
                "bits": int.from_bytes(data[start + 14 : start + 16], "little"),
            }
        elif kind == "LIST" and data[start : start + 4] == b"INFO":
            fields: dict[str, str] = {}
            cursor = start + 4
            while cursor + 8 <= end:
                key = data[cursor : cursor + 4].decode("ascii", "replace")
                amount = int.from_bytes(data[cursor + 4 : cursor + 8], "little")
                fields[key] = _safe_text(data[cursor + 8 : min(end, cursor + 8 + amount)], 500)
                cursor += 8 + amount + (amount & 1)
            row["info"] = fields
        info["chunks"].append(row)
        pos = end + (size & 1)
    return info


def parse_executable(data: bytes, kind: str) -> dict[str, Any]:
    if kind == "Windows executable candidate" and len(data) >= 0x40:
        pointer = int.from_bytes(data[0x3C:0x40], "little")
        if pointer + 24 <= len(data) and data[pointer : pointer + 4] == b"PE\0\0":
            return {"format": "PE", "machine": f"0x{int.from_bytes(data[pointer+4:pointer+6], 'little'):04x}", "sections": int.from_bytes(data[pointer + 6 : pointer + 8], "little")}
    if kind == "ELF executable candidate" and len(data) >= 20:
        return {"format": "ELF", "class": {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown"), "endianness": {1: "little", 2: "big"}.get(data[5], "unknown")}
    if kind == "Android DEX candidate" and len(data) >= 8:
        return {"format": "DEX", "version": data[4:7].decode("ascii", "replace")}
    if kind == "WebAssembly candidate" and len(data) >= 8:
        return {"format": "WASM", "version": int.from_bytes(data[4:8], "little")}
    return {"format": kind}


def _decompress_gzip(data: bytes) -> dict[str, Any]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            plain = stream.read(MAX_DECOMPRESSED + 1)
        truncated = len(plain) > MAX_DECOMPRESSED
        plain = plain[:MAX_DECOMPRESSED]
        return {"ok": True, "bytes": len(plain), "truncated": truncated, "preview": _safe_text(plain)}
    except (OSError, EOFError, zlib.error) as error:
        return {"ok": False, "error": str(error)}


def carve_artifacts(path: Path, signatures: list[dict[str, Any]], carve_dir: Path | None, max_bytes: int, primary_format: str | None = None) -> list[dict[str, Any]]:
    """ينحت حدوداً معروفة فقط؛ لا يفتح أو ينفذ أي ناتج."""
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    primary_magic = {"PNG": "PNG image", "JPEG": "JPEG image", "GIF": "GIF image", "TIFF": "TIFF image"}.get(primary_format or "")
    covered_zip_ranges: list[tuple[int, int]] = []
    for item in signatures:
        kind, offset = str(item["name"]), int(item["offset"])
        if kind in {"ZIP end record", "JUMBF marker", "C2PA marker", "Sitr V1 marker", "Sitr V2 marker"} or (offset == 0 and kind == primary_magic):
            continue
        if kind == "ZIP archive" and any(start <= offset < end for start, end in covered_zip_ranges):
            continue
        key = (kind, offset)
        if key in seen or len(results) >= MAX_ARTIFACTS:
            continue
        seen.add(key)
        window = read_window(path, offset, max_bytes)
        boundary, boundary_kind = artifact_boundary(kind, window)
        carved = window[:boundary] if boundary else window
        entry: dict[str, Any] = {
            "kind": kind,
            "offset": offset,
            "boundary": boundary_kind,
            "bytes_available": len(carved),
            "complete_boundary": boundary is not None,
            "sha256": hashlib.sha256(carved).hexdigest(),
            "preview": _safe_text(carved),
        }
        if kind == "ZIP archive":
            entry["zip"] = parse_zip(carved)
        elif kind == "PDF document":
            entry["pdf"] = parse_pdf(carved)
        elif kind == "MP3 ID3 tag":
            entry["id3"] = parse_id3(carved)
        elif kind == "WAVE identifier":
            entry["wave"] = parse_wave(read_window(path, max(0, offset - 8), max_bytes))
        elif kind == "GZIP stream":
            entry["gzip"] = _decompress_gzip(carved)
        elif "candidate" in kind:
            entry["executable"] = parse_executable(carved, kind)
        if kind == "ZIP archive" and boundary is not None:
            covered_zip_ranges.append((offset, offset + boundary))
        if carve_dir is not None:
            carve_dir.mkdir(parents=True, exist_ok=True)
            safe_kind = re.sub(r"[^A-Za-z0-9]+", "_", kind).strip("_").lower() or "artifact"
            output = carve_dir / f"{offset:012x}_{safe_kind}.bin"
            output.write_bytes(carved)
            entry["carved_path"] = str(output)
        results.append(entry)
    return results


def entropy_profile(path: Path, windows: int = 32, sample_size: int = 64 * 1024) -> dict[str, Any]:
    size = path.stat().st_size
    if not size:
        return {"windows": []}
    positions = sorted({min(max(0, int((size - sample_size) * i / max(1, windows - 1))), max(0, size - sample_size)) for i in range(windows)})
    values = []
    with path.open("rb") as handle:
        for offset in positions:
            handle.seek(offset)
            data = handle.read(sample_size)
            values.append({"offset": offset, "sample_bytes": len(data), "entropy": round(_entropy(data), 6)})
    entropy_values = [row["entropy"] for row in values]
    return {
        "window_bytes": sample_size,
        "windows": values,
        "min": min(entropy_values),
        "max": max(entropy_values),
        "mean": round(sum(entropy_values) / len(entropy_values), 6),
        "high_entropy_windows": [row for row in values if row["entropy"] > 7.8],
    }


def raw_text_carve(path: Path, limit: int = 48) -> dict[str, list[dict[str, Any]]]:
    ascii_out: list[dict[str, Any]] = []
    utf16_out: list[dict[str, Any]] = []
    overlap = b""
    offset = 0
    with path.open("rb") as handle:
        while block := handle.read(STREAM_BLOCK):
            data = overlap + block
            base = offset - len(overlap)
            if len(ascii_out) < limit:
                ascii_out.extend(_ascii_runs(data, base, limit=limit - len(ascii_out)))
            if len(utf16_out) < limit:
                utf16_out.extend(_utf16_runs(data, base, True, limit - len(utf16_out)))
                if len(utf16_out) < limit:
                    utf16_out.extend(_utf16_runs(data, base, False, limit - len(utf16_out)))
            overlap = data[-1024:]
            offset += len(block)
            if len(ascii_out) >= limit and len(utf16_out) >= limit:
                break
    return {"ascii": ascii_out[:limit], "utf16": utf16_out[:limit]}


def _rs_style(raw: bytes, width: int, height: int, stride: int) -> dict[str, Any]:
    def lum(x: int, y: int) -> int:
        at = (y * width + x) * 4
        return round(0.299 * raw[at] + 0.587 * raw[at + 1] + 0.114 * raw[at + 2])

    def discr(values: list[int]) -> int:
        return sum(abs(values[i] - values[i + 1]) for i in range(3))

    def plus(value: int) -> int:
        return value ^ 1

    def minus(value: int) -> int:
        if value == 0:
            return 1
        if value == 255:
            return 254
        return value + 1 if value & 1 else value - 1

    r_plus = s_plus = r_minus = s_minus = groups = 0
    for y in range(0, max(0, height - stride), stride * 2):
        for x in range(0, max(0, width - 3 * stride), stride * 4):
            values = [lum(x + i * stride, y) for i in range(4)]
            base = discr(values)
            p = discr([plus(value) for value in values])
            n = discr([minus(value) for value in values])
            if p > base:
                r_plus += 1
            elif p < base:
                s_plus += 1
            if n > base:
                r_minus += 1
            elif n < base:
                s_minus += 1
            groups += 1

    def balance(regular: int, singular: int) -> float:
        return round((regular - singular) / max(1, regular + singular), 6)

    return {
        "groups": groups,
        "regular_plus": r_plus,
        "singular_plus": s_plus,
        "regular_minus": r_minus,
        "singular_minus": s_minus,
        "balance_plus": balance(r_plus, s_plus),
        "balance_minus": balance(r_minus, s_minus),
        "interpretation": "RS-style statistic only; it is not a calibrated payload estimate or proof of steganography.",
    }


def _pixel_stream(raw: bytes, channels: tuple[int, ...], planes: tuple[int, ...], cap: int = MAX_PIXEL_BYTES) -> bytes:
    out = bytearray(cap)
    target_bits = cap * 8
    bit_at = 0
    for at in range(0, len(raw), 4):
        for channel in channels:
            value = raw[at + channel]
            for plane in planes:
                if bit_at >= target_bits:
                    return bytes(out)
                if value & (1 << plane):
                    out[bit_at >> 3] |= 1 << (7 - (bit_at & 7))
                bit_at += 1
    return bytes(out[: (bit_at + 7) // 8])


def _stream_candidates(stream: bytes) -> dict[str, Any]:
    signatures = []
    for magic, name in DEEP_SIGNATURES.items():
        for offset in _find_all(stream, magic, cap=3):
            signatures.append({"name": name, "offset": offset})
    strings = _ascii_runs(stream, 0, minimum=16, limit=4)
    strings.extend(_utf16_runs(stream, 0, True, limit=max(0, 6 - len(strings))))
    return {"signatures": signatures, "strings": strings[:6]}


def pixel_forensics(path: Path) -> dict[str, Any]:
    try:
        from PIL import Image, UnidentifiedImageError  # type: ignore
    except ImportError:
        return {"status": "not_available", "reason": "Pillow غير مثبت؛ ثبّت pillow لتشغيل تحليل البكسلات المحلي."}
    try:
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS * 2
        with Image.open(path) as image:
            width, height = image.size
            if width * height > MAX_PIXELS:
                return {"status": "skipped", "reason": f"{width * height:,} pixels exceeds safe local cap of {MAX_PIXELS:,}", "dimensions": [width, height]}
            rgba = image.convert("RGBA")
            raw = rgba.tobytes()
    except (UnidentifiedImageError, OSError, ValueError) as error:
        return {"status": "skipped", "reason": str(error)}

    pixels = width * height
    stride = max(1, math.ceil(pixels / 800_000))
    histograms = [[0] * 256 for _ in range(3)]
    lsb_ones = [0, 0, 0]
    sampled = 0
    pvd_values: list[int] = []
    transitions = 0
    pairs = 0
    complexity = [0, 0, 0, 0]
    for y in range(0, height, stride):
        for x in range(0, width, stride):
            at = (y * width + x) * 4
            for channel in range(3):
                value = raw[at + channel]
                histograms[channel][value] += 1
                lsb_ones[channel] += value & 1
            if x + stride < width:
                right = (y * width + min(width - 1, x + stride)) * 4
                a = round(0.299 * raw[at] + 0.587 * raw[at + 1] + 0.114 * raw[at + 2])
                b = round(0.299 * raw[right] + 0.587 * raw[right + 1] + 0.114 * raw[right + 2])
                pvd_values.append(abs(a - b))
                for bit in range(4):
                    complexity[bit] += int(((raw[at] >> bit) & 1) != ((raw[right] >> bit) & 1))
                transitions += int((raw[at] & 1) != (raw[right] & 1))
                pairs += 1
            sampled += 1

    channels = []
    for index, histogram in enumerate(histograms):
        chi = 0.0
        nonempty = 0
        for value in range(0, 256, 2):
            total = histogram[value] + histogram[value + 1]
            if total:
                expected = total / 2
                chi += ((histogram[value] - expected) ** 2 + (histogram[value + 1] - expected) ** 2) / expected
                nonempty += 1
        p = lsb_ones[index] / max(1, sampled)
        lsb_entropy = 0.0 if p in (0.0, 1.0) else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))
        channels.append({"channel": "RGB"[index], "lsb_one_fraction": round(p, 6), "lsb_entropy": round(lsb_entropy, 6), "chi_square": round(chi, 3), "chi_per_pair": round(chi / max(1, nonempty), 6)})

    profiles = [
        ("rgb-lsb", (0, 1, 2), (0,)), ("bgr-lsb", (2, 1, 0), (0,)), ("rgba-lsb", (0, 1, 2, 3), (0,)),
        ("r-lsb", (0,), (0,)), ("g-lsb", (1,), (0,)), ("b-lsb", (2,), (0,)),
        ("rgb-b1", (0, 1, 2), (1,)), ("rgb-b2", (0, 1, 2), (2,)), ("rgb-b3", (0, 1, 2), (3,)),
        ("rgb-b1b0", (0, 1, 2), (1, 0)), ("rgb-b2b1b0", (0, 1, 2), (2, 1, 0)),
    ]
    streams = []
    for name, channel_order, planes in profiles:
        candidate = _stream_candidates(_pixel_stream(raw, channel_order, planes))
        if candidate["signatures"] or candidate["strings"]:
            streams.append({"profile": name, **candidate})

    pvd_mean = sum(pvd_values) / max(1, len(pvd_values))
    pvd_var = sum((value - pvd_mean) ** 2 for value in pvd_values) / max(1, len(pvd_values))
    return {
        "status": "ok",
        "dimensions": [width, height],
        "sampled_pixels": sampled,
        "sample_stride": stride,
        "channels": channels,
        "pvd": {"mean": round(pvd_mean, 6), "stddev": round(math.sqrt(pvd_var), 6)},
        "lsb_transition_fraction": round(transitions / max(1, pairs), 6),
        "bpcs_r_complexity": [round(value / max(1, pairs), 6) for value in complexity],
        "rs_style": _rs_style(raw, width, height, stride),
        "payload_stream_candidates": streams,
        "interpretation": "Pixel metrics are statistical indicators. A matching magic/text stream may be extractable; a statistical value alone is not proof.",
    }


def basic_container(path: Path) -> dict[str, Any]:
    """خريطة حاوية خفيفة مستقلة عن ExifTool، لا تستبدل محللاً كاملاً لكل صيغة."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(32)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        chunks = []
        warnings = []
        pos = 8
        end_offset = None
        with path.open("rb") as handle:
            while pos + 12 <= size and len(chunks) < 10000:
                handle.seek(pos)
                header = handle.read(8)
                if len(header) != 8:
                    break
                length = int.from_bytes(header[:4], "big")
                kind = header[4:8].decode("latin-1", "replace")
                if length > size or pos + 12 + length > size:
                    warnings.append(f"truncated PNG chunk at {pos}")
                    break
                # تحقق CRC للـ chunks المعقولة فقط؛ لا نحمّل IDAT عملاقاً كاملاً إلى الذاكرة.
                if length <= 16 * 1024 * 1024:
                    data = handle.read(length)
                    expected = int.from_bytes(handle.read(4), "big")
                    actual = zlib.crc32(header[4:8] + data) & 0xFFFFFFFF
                    crc_valid: bool | None = expected == actual
                    if not crc_valid:
                        warnings.append(f"CRC mismatch in {kind} at {pos}")
                else:
                    handle.seek(length, 1)
                    handle.read(4)
                    crc_valid = None
                chunks.append({"offset": pos, "type": kind, "size": length, "crc_valid": crc_valid})
                pos += 12 + length
                if kind == "IEND":
                    end_offset = pos
                    break
        return {"format": "PNG", "chunks": chunks, "end_offset": end_offset, "tail_bytes": max(0, size - (end_offset or size)), "warnings": warnings}
    if head.startswith(b"\xff\xd8\xff"):
        segments = []
        pos = 2
        end_offset = None
        warnings = []
        with path.open("rb") as handle:
            while pos + 2 <= size and len(segments) < 10000:
                handle.seek(pos)
                marker_bytes = handle.read(2)
                if marker_bytes[0] != 0xFF:
                    pos += 1
                    continue
                marker = marker_bytes[1]
                while marker == 0xFF:
                    marker = handle.read(1)[0]
                if marker == 0xD9:
                    end_offset = pos + 2
                    break
                if marker in {0x00, 0x01, *range(0xD0, 0xD8)}:
                    pos += 2
                    continue
                raw_len = handle.read(2)
                if len(raw_len) != 2:
                    warnings.append(f"truncated marker at {pos}")
                    break
                length = int.from_bytes(raw_len, "big")
                if length < 2 or pos + 2 + length > size:
                    warnings.append(f"invalid marker length at {pos}")
                    break
                names = {0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT", 0xDD: "DRI", 0xFE: "COM"}
                label = names.get(marker, f"APP{marker-0xE0}" if 0xE0 <= marker <= 0xEF else f"FF{marker:02X}")
                segments.append({"offset": pos, "marker": label, "size": length - 2})
                pos += 2 + length
                if marker == 0xDA:
                    handle.seek(pos)
                    tail = handle.read()
                    eoi = tail.find(b"\xff\xd9")
                    if eoi >= 0:
                        end_offset = pos + eoi + 2
                    else:
                        warnings.append("EOI missing after SOS")
                    break
        return {"format": "JPEG", "segments": segments, "end_offset": end_offset, "tail_bytes": max(0, size - (end_offset or size)), "warnings": warnings}
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        declared = int.from_bytes(head[4:8], "little") + 8
        return {"format": "WebP", "declared_bytes": declared, "tail_bytes": max(0, size - min(size, declared)), "warnings": []}
    if head[:6] in {b"GIF87a", b"GIF89a"}:
        return {"format": "GIF", "warnings": []}
    if head[:2] == b"BM":
        return {"format": "BMP", "declared_bytes": int.from_bytes(head[2:6], "little"), "warnings": []}
    if head[:2] in {b"II", b"MM"} and head[2:4] in {b"*\x00", b"\x00*"}:
        return {"format": "TIFF", "warnings": []}
    return {"format": "unknown", "warnings": ["No supported primary container parser"]}


def analyze_deep(path: Path, carve_dir: Path | None = None, max_carve_bytes: int = MAX_CARVE_BYTES) -> dict[str, Any]:
    """يشغل جميع التحليلات الأصلية المتاحة محلياً ويعيد JSON-serializable evidence."""
    max_carve_bytes = max(64 * 1024, min(max_carve_bytes, 64 * 1024 * 1024))
    signatures = scan_signatures(path)
    container = basic_container(path)
    return {
        "engine": "Sitr native deep engine",
        "version": "1.0",
        "safety": {
            "network": "disabled",
            "payload_execution": "never",
            "password_guessing": "never",
            "carving": "only to an explicit --carve-dir; outputs are .bin and never executed",
            "decompression_preview_cap": MAX_DECOMPRESSED,
            "artifact_window_cap": max_carve_bytes,
        },
        "container": container,
        "entropy_profile": entropy_profile(path),
        "signatures": signatures,
        "artifacts": carve_artifacts(path, signatures, carve_dir, max_carve_bytes, container.get("format")),
        "raw_text": raw_text_carve(path),
        "pixel_forensics": pixel_forensics(path),
    }

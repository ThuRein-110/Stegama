from __future__ import annotations

import mimetypes
from pathlib import Path

from .helpers import hex_range, human_size


SIGNATURES = [
    {"type": "PNG image", "mime": "image/png", "extensions": [".png"], "magic": b"\x89PNG\r\n\x1a\n"},
    {"type": "JPEG image", "mime": "image/jpeg", "extensions": [".jpg", ".jpeg"], "magic": b"\xff\xd8\xff"},
    {"type": "GIF image", "mime": "image/gif", "extensions": [".gif"], "magic": b"GIF8"},
    {"type": "BMP image", "mime": "image/bmp", "extensions": [".bmp"], "magic": b"BM"},
    {"type": "ZIP archive", "mime": "application/zip", "extensions": [".zip", ".jar", ".docx", ".xlsx", ".pptx"], "magic": b"PK\x03\x04"},
    {"type": "PDF document", "mime": "application/pdf", "extensions": [".pdf"], "magic": b"%PDF"},
    {"type": "Windows executable", "mime": "application/x-msdownload", "extensions": [".exe", ".dll"], "magic": b"MZ"},
    {"type": "ELF executable", "mime": "application/x-elf", "extensions": [".elf", ".so"], "magic": b"\x7fELF"},
]


def analyze_binary(path: Path) -> dict:
    file_size = path.stat().st_size
    first_bytes = read_first_bytes(path, 4096)
    last_bytes = read_last_bytes(path, 128)
    extension = path.suffix.lower()
    signature = detect_signature(first_bytes, extension)

    patterns = detect_binary_patterns(path)
    mismatch = not signature["extension_matches"] and signature["detected_type"] != "Unknown binary"
    notes = list(signature["notes"])
    if mismatch:
        notes.append("Extension does not align with the detected magic bytes; review for masquerading.")
    if patterns:
        notes.append(f"{len(patterns)} embedded binary or operator-pattern marker(s) were observed.")

    return {
        "extension": extension or "(none)",
        "mime_type": signature["mime_from_extension"] or signature["detected_mime"],
        "signature": signature,
        "first_bytes": format_bytes(first_bytes[:128], 0),
        "last_bytes": format_bytes(last_bytes, max(0, file_size - len(last_bytes))),
        "binary_patterns": patterns,
        "notes": notes,
    }


def read_first_bytes(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def read_last_bytes(path: Path, size: int) -> bytes:
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, file_size - size))
        return handle.read(size)


def detect_signature(data: bytes, extension: str) -> dict:
    detected = None
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        detected = {"type": "WEBP image", "mime": "image/webp", "extensions": [".webp"]}
    elif len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        detected = {"type": "WAV audio", "mime": "audio/wav", "extensions": [".wav"]}
    else:
        for item in SIGNATURES:
            if data.startswith(item["magic"]):
                detected = item
                break

    if detected is None:
        if looks_text(data[:2048]):
            detected = {"type": "Plain text", "mime": "text/plain", "extensions": [".txt"]}
        else:
            detected = {"type": "Unknown binary", "mime": "application/octet-stream", "extensions": []}

    mime_from_extension = mimetypes.guess_type(f"sample{extension}")[0] if extension else None
    expected = detected.get("extensions", [])
    extension_matches = extension in expected if expected else detected["type"] == "Unknown binary"
    notes = []
    if not data:
        notes.append("File is empty; no magic bytes could be evaluated.")
    elif detected["type"] == "Unknown binary":
        notes.append("Magic bytes did not match the built-in signature set.")
    elif extension_matches:
        notes.append("File extension is consistent with the detected magic bytes.")

    return {
        "magic_hex": data[:16].hex(" "),
        "detected_type": detected["type"],
        "detected_mime": detected["mime"],
        "mime_from_extension": mime_from_extension,
        "expected_extensions": expected,
        "extension_matches": extension_matches,
        "notes": notes,
    }


def detect_binary_patterns(path: Path) -> list[dict]:
    markers = [
        {"label": "Embedded ZIP marker", "needle": b"PK\x03\x04", "severity": "High", "note": "Archive content may be embedded or appended."},
        {"label": "Windows PE marker", "needle": b"MZ", "severity": "High", "note": "Executable header-like bytes appear inside the artifact."},
        {"label": "ELF marker", "needle": b"\x7fELF", "severity": "High", "note": "Linux executable header-like bytes appear inside the artifact."},
        {"label": "PowerShell text", "needle": b"powershell", "severity": "Medium", "note": "Readable command-line tradecraft indicator appears in strings."},
        {"label": "Download command text", "needle": b"curl", "severity": "Medium", "note": "Network retrieval keyword appears in binary content."},
        {"label": "Download command text", "needle": b"wget", "severity": "Medium", "note": "Network retrieval keyword appears in binary content."},
        {"label": "Base64 marker text", "needle": b"base64", "severity": "Medium", "note": "Encoding keyword appears in readable content."},
    ]
    patterns = []
    seen = set()
    chunk_size = 1024 * 1024
    overlap_size = max(len(marker["needle"]) for marker in markers) - 1
    previous_tail = b""
    offset_base = 0

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            window = previous_tail + chunk
            lowered = window.lower()
            window_base = offset_base - len(previous_tail)
            for marker in markers:
                if marker["label"] in seen:
                    continue
                found_at = lowered.find(marker["needle"].lower())
                if found_at == -1:
                    continue
                offset = window_base + found_at
                seen.add(marker["label"])
                patterns.append({
                    "label": marker["label"],
                    "offset": offset,
                    "offset_hex": f"0x{offset:08X}",
                    "severity": marker["severity"],
                    "note": marker["note"],
                })
            previous_tail = window[-overlap_size:]
            offset_base += len(chunk)

    return patterns[:16]


def format_bytes(data: bytes, base_offset: int) -> dict:
    rows = []
    for index in range(0, len(data), 16):
        chunk = data[index:index + 16]
        ascii_preview = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        rows.append({
            "offset": f"0x{base_offset + index:08X}",
            "hex": chunk.hex(" "),
            "ascii": ascii_preview,
        })

    return {
        "offset_range": hex_range(base_offset, base_offset + max(0, len(data) - 1)),
        "size": human_size(len(data)),
        "rows": rows,
    }


def looks_text(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(byte in b"\r\n\t" or 32 <= byte <= 126 for byte in data)
    return printable / len(data) > 0.92

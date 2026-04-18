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
    data = path.read_bytes()
    extension = path.suffix.lower()
    signature = detect_signature(data, extension)
    first_bytes = data[:128]
    last_bytes = data[-128:] if data else b""

    patterns = detect_binary_patterns(data)
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
        "first_bytes": format_bytes(first_bytes, 0),
        "last_bytes": format_bytes(last_bytes, max(0, len(data) - len(last_bytes))),
        "binary_patterns": patterns,
        "notes": notes,
    }


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


def detect_binary_patterns(data: bytes) -> list[dict]:
    markers = [
        {"label": "Embedded ZIP marker", "needle": b"PK\x03\x04", "severity": "High", "note": "Archive content may be embedded or appended."},
        {"label": "Windows PE marker", "needle": b"MZ", "severity": "High", "note": "Executable header-like bytes appear inside the artifact."},
        {"label": "ELF marker", "needle": b"\x7fELF", "severity": "High", "note": "Linux executable header-like bytes appear inside the artifact."},
        {"label": "PowerShell text", "needle": b"powershell", "severity": "Medium", "note": "Readable command-line tradecraft indicator appears in strings."},
        {"label": "Download command text", "needle": b"curl", "severity": "Medium", "note": "Network retrieval keyword appears in binary content."},
        {"label": "Download command text", "needle": b"wget", "severity": "Medium", "note": "Network retrieval keyword appears in binary content."},
        {"label": "Base64 marker text", "needle": b"base64", "severity": "Medium", "note": "Encoding keyword appears in readable content."},
    ]
    lowered = data.lower()
    patterns = []
    seen = set()

    for marker in markers:
        offset = lowered.find(marker["needle"].lower())
        if offset == -1:
            continue
        key = (marker["label"], offset)
        if key in seen:
            continue
        seen.add(key)
        patterns.append({
            "label": marker["label"],
            "offset": offset,
            "offset_hex": f"0x{offset:08X}",
            "severity": marker["severity"],
            "note": marker["note"],
        })

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

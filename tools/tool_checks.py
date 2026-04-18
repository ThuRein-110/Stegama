from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


def run_command(cmd: list[str], timeout: int = 20) -> dict:
    executable = cmd[0]
    if shutil.which(executable) is None:
        return {
            "ok": False,
            "error": f"Tool not found: {executable}",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return {
            "ok": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"Timeout while running: {' '.join(cmd)}",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }



def run_file_cmd(path: Path) -> dict:
    return run_command(["file", "-b", str(path)])



def run_strings(path: Path) -> dict:
    result = run_command(["strings", "-a", "-n", "4", str(path)])
    if not result.get("ok"):
        lines = extract_printable_strings(path)
        suspicious_items = find_suspicious_items(lines)
        return {
            "all": lines[:300],
            "normal": find_normal_strings(lines, suspicious_items),
            "suspicious": [item["value"] for item in suspicious_items],
            "suspicious_items": suspicious_items,
            "stats": build_string_stats(lines, suspicious_items),
            "raw": result,
            "fallback": "python printable strings scan",
        }

    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    suspicious_items = find_suspicious_items(lines)
    return {
        "all": lines[:300],
        "normal": find_normal_strings(lines, suspicious_items),
        "suspicious": [item["value"] for item in suspicious_items],
        "suspicious_items": suspicious_items,
        "stats": build_string_stats(lines, suspicious_items),
        "raw": result,
    }


def extract_printable_strings(path: Path, min_length: int = 4) -> list[str]:
    data = path.read_bytes()
    chunks = re.findall(rb"[\x20-\x7e]{%d,}" % min_length, data)
    return [chunk.decode("utf-8", errors="replace") for chunk in chunks]


def find_suspicious_strings(lines: list[str]) -> list[str]:
    return [item["value"] for item in find_suspicious_items(lines)]


def find_suspicious_items(lines: list[str]) -> list[dict]:
    suspicious = []
    keywords = {
        "flag": "High",
        "picoctf": "High",
        "ctf": "Medium",
        "key": "Medium",
        "pass": "Medium",
        "secret": "High",
        "hidden": "Medium",
        "cmd": "Medium",
        "powershell": "High",
        "wget": "High",
        "curl": "High",
        "base64": "Medium",
        "token": "High",
        "login": "Medium",
        "payload": "High",
        "zip": "Medium",
    }
    seen = set()

    for line in lines[:300]:
        lowered = line.lower()
        matched = [keyword for keyword in keywords if keyword in lowered]
        looks_base64 = len(line) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", line) is not None
        if not matched and not looks_base64 and len(line) <= 80:
            continue

        severity = "Low"
        if looks_base64:
            matched.append("base64-like")
            severity = "Medium"
        for keyword in matched:
            severity = max_severity(severity, keywords.get(keyword, "Medium"))
        if len(line) > 120:
            severity = max_severity(severity, "Medium")

        key = (line, ",".join(matched))
        if key in seen:
            continue
        seen.add(key)
        suspicious.append({
            "value": line,
            "keywords": matched or ["long-readable-string"],
            "severity": severity,
            "note": describe_suspicious_string(matched, looks_base64, len(line)),
        })

    return suspicious[:80]


def find_normal_strings(lines: list[str], suspicious_items: list[dict]) -> list[str]:
    suspicious_values = {item["value"] for item in suspicious_items}
    normal = [line for line in lines[:300] if line not in suspicious_values]
    return normal[:120]


def build_string_stats(lines: list[str], suspicious_items: list[dict]) -> dict:
    return {
        "total_extracted": len(lines[:300]),
        "suspicious_count": len(suspicious_items),
        "normal_preview_count": max(0, min(len(lines), 300) - len(suspicious_items)),
        "high_severity_count": sum(1 for item in suspicious_items if item["severity"] == "High"),
        "medium_severity_count": sum(1 for item in suspicious_items if item["severity"] == "Medium"),
    }


def max_severity(left: str, right: str) -> str:
    order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def describe_suspicious_string(keywords: list[str], looks_base64: bool, length: int) -> str:
    if looks_base64:
        return "Readable string matches a base64-like character profile."
    if any(keyword in keywords for keyword in ("powershell", "wget", "curl", "cmd")):
        return "Command or downloader keyword appears in readable content."
    if any(keyword in keywords for keyword in ("flag", "picoctf", "secret", "token", "payload")):
        return "CTF or hidden-data keyword appears in readable content."
    if length > 120:
        return "Long readable string may carry embedded configuration or encoded data."
    return "Keyword appears in extracted printable strings."



def run_exiftool(path: Path) -> dict:
    result = run_command(["exiftool", "-j", str(path)])
    if not result.get("ok"):
        return {
            "parsed": extract_image_metadata(path),
            "raw": result,
            "fallback": "python image metadata scan",
        }
    try:
        parsed = json.loads(result["stdout"])
        return {"parsed": parsed[0] if parsed else {}, "raw": result}
    except json.JSONDecodeError:
        return {"parsed": {}, "raw": result}


def extract_image_metadata(path: Path) -> dict:
    try:
        from PIL import ExifTags, Image
    except ImportError:
        return {}

    try:
        with Image.open(path) as image:
            metadata = {}
            for key, value in image.info.items():
                metadata[str(key)] = _stringify_metadata_value(value)

            exif = image.getexif()
            if exif:
                for key, value in exif.items():
                    label = ExifTags.TAGS.get(key, str(key))
                    metadata[str(label)] = _stringify_metadata_value(value)

            return metadata
    except Exception:
        return {}


def _stringify_metadata_value(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)



def detect_trailing_data(path: Path) -> dict:
    data = path.read_bytes()
    suffix = path.suffix.lower()

    marker_index = None
    marker_name = None
    if suffix in {".jpg", ".jpeg"}:
        marker = b"\xff\xd9"
        idx = data.rfind(marker)
        if idx != -1 and idx + len(marker) < len(data):
            marker_index = idx + len(marker)
            marker_name = "JPEG EOI"
    elif suffix == ".png":
        marker = b"IEND\xaeB`\x82"
        idx = data.rfind(marker)
        if idx != -1 and idx + len(marker) < len(data):
            marker_index = idx + len(marker)
            marker_name = "PNG IEND"
    elif suffix == ".gif":
        marker = b";"
        idx = data.rfind(marker)
        if idx != -1 and idx + 1 < len(data):
            marker_index = idx + 1
            marker_name = "GIF trailer"

    if marker_index is None:
        return {
            "has_trailing_data": False,
            "marker": marker_name,
            "trailing_size": 0,
            "preview_hex": "",
        }

    trailing = data[marker_index:]
    return {
        "has_trailing_data": len(trailing) > 0,
        "marker": marker_name,
        "trailing_size": len(trailing),
        "preview_hex": trailing[:64].hex(),
    }

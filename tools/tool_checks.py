from __future__ import annotations

import json
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
        return {"all": [], "suspicious": [], "raw": result}

    lines = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    suspicious = []
    keywords = (
        "flag{", "ctf", "http", "base64", "password", "secret", "hidden", "payload", "key", "zip"
    )
    for line in lines[:300]:
        lowered = line.lower()
        if any(keyword in lowered for keyword in keywords) or len(line) > 60:
            suspicious.append(line)

    return {
        "all": lines[:300],
        "suspicious": suspicious[:50],
        "raw": result,
    }



def run_exiftool(path: Path) -> dict:
    result = run_command(["exiftool", "-j", str(path)])
    if not result.get("ok"):
        return {"parsed": {}, "raw": result}
    try:
        parsed = json.loads(result["stdout"])
        return {"parsed": parsed[0] if parsed else {}, "raw": result}
    except json.JSONDecodeError:
        return {"parsed": {}, "raw": result}



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

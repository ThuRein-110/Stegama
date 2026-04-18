from __future__ import annotations

from pathlib import Path

from .helpers import sha256_file
from .ctf_checks import extract_ctf_clues
from .image_checks import analyze_image
from .tool_checks import (
    detect_trailing_data,
    run_exiftool,
    run_file_cmd,
    run_strings,
)

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def analyze_file(file_path: Path) -> dict:
    suffix = file_path.suffix.lower()

    result = {
        "filename": file_path.name,
        "filepath": str(file_path),
        "size_bytes": file_path.stat().st_size,
        "sha256": sha256_file(file_path),
        "file_type": run_file_cmd(file_path),
        "metadata": run_exiftool(file_path),
        "strings": run_strings(file_path),
        "trailing_data": detect_trailing_data(file_path),
        "tool_status": {},
        "findings": [],
        "score": 0,
        "verdict": "Low suspicion",
    }

    if suffix in IMAGE_EXTS:
        image_result = analyze_image(file_path)
        result.update(image_result)

    score = 0
    findings: list[str] = []

    strings_block = result.get("strings", {})
    suspicious_strings = strings_block.get("suspicious", [])
    if suspicious_strings:
        score += min(25, 5 * len(suspicious_strings))
        findings.append(f"Suspicious printable strings found: {len(suspicious_strings)}")

    trailing = result.get("trailing_data", {})
    if trailing.get("has_trailing_data"):
        score += 35
        findings.append("Possible appended data after expected file end marker")

    zsteg_data = result.get("zsteg", {})
    if zsteg_data.get("interesting_hits"):
        score += 40
        findings.append(f"zsteg reported {len(zsteg_data['interesting_hits'])} interesting hit(s)")

    steg_text = " ".join(strings_block.get("all", [])[:80]).lower()
    keywords = ["flag{", "ctf", "pk\x03\x04", "base64", "hidden", "secret", "payload"]
    kw_found = [kw for kw in keywords if kw in steg_text]
    if kw_found:
        score += min(20, 5 * len(kw_found))
        findings.append(f"CTF-style keywords detected in strings: {', '.join(kw_found)}")

    if result.get("lsb", {}).get("note"):
        score += 10
        findings.append(result["lsb"]["note"])

    ctf_clues = extract_ctf_clues(result)
    result.update(ctf_clues)
    if result["decoded_clues"]:
        score += min(25, 10 * len(result["decoded_clues"]))
        findings.append(f"Base64-looking clue(s) decoded: {len(result['decoded_clues'])}")
    if result["flags"]:
        score += 50
        findings.append(f"Likely CTF flag found: {result['flags'][0]}")

    result["findings"] = findings
    result["score"] = min(100, score)

    if score >= 70:
        result["verdict"] = "High suspicion"
    elif score >= 35:
        result["verdict"] = "Medium suspicion"
    else:
        result["verdict"] = "Low suspicion"

    return result

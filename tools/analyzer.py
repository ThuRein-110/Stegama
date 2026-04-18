from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .binary_checks import analyze_binary
from .ctf_checks import extract_ctf_clues
from .entropy_checks import analyze_entropy
from .helpers import file_hashes, human_size
from .image_checks import analyze_image
from .tool_checks import detect_trailing_data, run_exiftool, run_file_cmd, run_strings

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def analyze_file(file_path: Path, original_name: str | None = None, scan_mode: str = "quick") -> dict:
    display_name = original_name or file_path.name
    suffix = Path(display_name).suffix.lower() or file_path.suffix.lower()
    size_bytes = file_path.stat().st_size

    file_type = run_file_cmd(file_path)
    metadata = run_exiftool(file_path)
    strings = run_strings(file_path)
    trailing_data = detect_trailing_data(file_path)
    binary = analyze_binary(file_path)
    entropy = analyze_entropy(file_path)
    hashes = file_hashes(file_path)

    result = {
        "product": "Stegama",
        "scan_mode": normalize_scan_mode(scan_mode),
        "filename": display_name,
        "extension": suffix or "(none)",
        "size_bytes": size_bytes,
        "size_human": human_size(size_bytes),
        "hashes": hashes,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "file_type": file_type,
        "metadata": metadata,
        "strings": strings,
        "trailing_data": trailing_data,
        "binary": binary,
        "entropy": entropy,
        "tool_status": tool_status(file_type, metadata, strings),
        "findings": [],
        "score": 0,
        "verdict": "Clean-looking",
    }

    if suffix in IMAGE_EXTS or binary["signature"]["detected_mime"].startswith("image/"):
        result.update(analyze_image(file_path))

    result.update(extract_ctf_clues(result))
    result["stego_indicators"] = build_stego_indicators(result)
    result["metadata_notes"] = analyze_metadata_notes(result)
    result["adversarial_assessment"] = build_adversarial_assessment(result)
    result["findings"] = build_findings(result)
    result["score"] = calculate_score(result["findings"], result)
    result["verdict"] = verdict_for_score(result["score"])
    result["overview"] = build_overview(result)
    result["analyst_summary"] = build_analyst_summary(result)

    return result


def normalize_scan_mode(mode: str | None) -> dict:
    modes = {
        "quick": ("Quick Scan", "Fast first-look triage for obvious strings, metadata, hashes, and signatures."),
        "deep": ("Deep Scan", "Expanded suspicious-section and entropy-oriented artifact review."),
        "image": ("Image Stego Scan", "Image-focused review for metadata, tails, LSB hints, and channel anomalies."),
        "artifact": ("Suspicious Artifact Triage", "Defensive DFIR pass for masquerading, payload hints, and analyst prioritization."),
    }
    key = (mode or "quick").lower()
    label, description = modes.get(key, modes["quick"])
    return {"key": key if key in modes else "quick", "label": label, "description": description}


def tool_status(file_type: dict, metadata: dict, strings: dict) -> list[dict]:
    return [
        status_item("file", file_type, "External file type detection"),
        status_item("strings", strings.get("raw", {}), strings.get("fallback", "Printable string extraction")),
        status_item("exiftool", metadata.get("raw", {}), metadata.get("fallback", "Metadata extraction")),
    ]


def status_item(name: str, raw: dict, label: str) -> dict:
    unavailable = raw.get("returncode") is None and raw.get("error")
    return {
        "name": name,
        "label": label,
        "status": "Unavailable" if unavailable else "Available",
        "message": raw.get("error") or raw.get("stderr") or "Ready",
    }


def build_findings(result: dict) -> list[dict]:
    findings = []
    signature = result["binary"]["signature"]
    strings_stats = result["strings"].get("stats", {})

    if not signature["extension_matches"] and signature["detected_type"] != "Unknown binary":
        findings.append(finding(
            "Signature and extension mismatch",
            "Critical",
            "Hex / Binary",
            "The file extension does not match the detected magic bytes.",
            f"{result['extension']} submitted as {signature['detected_type']}",
        ))

    if result["trailing_data"].get("has_trailing_data"):
        findings.append(finding(
            "Appended data after valid file marker",
            "High",
            "Steganography",
            "Bytes exist after an expected image end marker, which is a common hiding location.",
            f"{result['trailing_data']['trailing_size']} trailing byte(s) after {result['trailing_data']['marker']}",
        ))

    for section in result["entropy"].get("suspicious_sections", [])[:5]:
        findings.append(finding(
            section["reason"],
            section["severity"],
            "Suspicious Sections",
            section["analyst_note"],
            section["offset_range"],
        ))

    if strings_stats.get("suspicious_count", 0):
        severity = "High" if strings_stats.get("high_severity_count", 0) else "Medium"
        findings.append(finding(
            "Suspicious readable strings",
            severity,
            "Strings",
            "Printable strings include CTF, credential-like, command, downloader, or encoding keywords.",
            f"{strings_stats['suspicious_count']} suspicious string(s)",
        ))

    if result.get("decoded_clues"):
        findings.append(finding(
            "Encoded clue decoded",
            "High",
            "CTF",
            "Base64-like content decoded into a readable clue or possible flag material.",
            f"{len(result['decoded_clues'])} decoded clue(s)",
        ))

    if result.get("flags"):
        findings.append(finding(
            "Likely CTF flag recovered",
            "Critical",
            "CTF",
            "The artifact contains a flag-like token after direct or decoded inspection.",
            result["flags"][0],
        ))

    for note in result.get("metadata_notes", []):
        findings.append(finding(
            note["title"],
            note["severity"],
            "Metadata",
            note["note"],
            note.get("evidence", "metadata"),
        ))

    for indicator in result.get("stego_indicators", []):
        if indicator["severity"] in {"Medium", "High", "Critical"}:
            findings.append(finding(
                indicator["name"],
                indicator["severity"],
                "Stego Indicators",
                indicator["explanation"],
                indicator["status"],
            ))

    if result["binary"].get("binary_patterns"):
        findings.append(finding(
            "Embedded binary or operator-pattern markers",
            "High",
            "Hex / Binary",
            "Marker bytes or command-oriented text appeared inside the artifact.",
            f"{len(result['binary']['binary_patterns'])} marker(s)",
        ))

    if not findings:
        findings.append(finding(
            "No strong suspicious indicators",
            "Informational",
            "Overview",
            "Built-in first-look checks did not find high-priority evidence.",
            "Continue with normal evidence handling if the source context is suspicious.",
        ))

    return findings[:24]


def finding(title: str, severity: str, category: str, explanation: str, evidence: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "explanation": explanation,
        "evidence": evidence,
    }


def calculate_score(findings: list[dict], result: dict) -> int:
    weights = {"Informational": 0, "Low": 8, "Medium": 18, "High": 32, "Critical": 45}
    score = sum(weights.get(item["severity"], 0) for item in findings)
    if result["entropy"].get("overall_entropy", 0) >= 7.6:
        score += 8
    if result["scan_mode"]["key"] in {"deep", "artifact"} and result["entropy"].get("suspicious_sections"):
        score += 5
    return min(100, score)


def verdict_for_score(score: int) -> str:
    if score >= 85:
        return "Critical Review Needed"
    if score >= 60:
        return "High Suspicion"
    if score >= 35:
        return "Medium Suspicion"
    if score >= 10:
        return "Low Suspicion"
    return "Clean-looking"


def build_overview(result: dict) -> dict:
    signature = result["binary"]["signature"]
    return {
        "file_name": result["filename"],
        "extension": result["extension"],
        "detected_real_file_type": result["file_type"].get("stdout") or signature["detected_type"],
        "mime_type": result["binary"]["mime_type"],
        "file_size": result["size_human"],
        "hashes": result["hashes"],
        "scan_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "overall_suspicion_score": result["score"],
        "verdict": result["verdict"],
    }


def build_stego_indicators(result: dict) -> list[dict]:
    indicators = []
    lsb = result.get("lsb", {})
    image_profile = result.get("image_profile", {})
    trailing = result.get("trailing_data", {})
    zsteg = result.get("zsteg", {})

    if lsb:
        indicators.append({
            "name": "Possible LSB anomalies",
            "status": f"ones ratio {lsb.get('ones_ratio', 0)}",
            "severity": lsb.get("severity", "Low"),
            "explanation": lsb.get("note", "LSB preview generated for analyst review."),
        })
        indicators.append({
            "name": "Image bit-plane hint",
            "status": "ASCII preview available" if lsb.get("ascii_preview") else "No readable preview",
            "severity": "Medium" if any(ch.isalnum() for ch in lsb.get("ascii_preview", "")) else "Low",
            "explanation": "Readable characters in an LSB preview can be a weak signal that bit-plane review is worthwhile.",
        })
    else:
        indicators.append({
            "name": "Possible LSB anomalies",
            "status": "Not applicable",
            "severity": "Informational",
            "explanation": "No image LSB scan was available for this file type.",
        })

    if image_profile:
        indicators.append({
            "name": "Channel anomalies",
            "status": f"mean {image_profile.get('channel_mean', [])}",
            "severity": image_profile.get("severity", "Low"),
            "explanation": image_profile.get("color_distribution_note", "Image color distribution reviewed."),
        })

    indicators.append({
        "name": "Appended content after image marker",
        "status": "Present" if trailing.get("has_trailing_data") else "Not observed",
        "severity": "High" if trailing.get("has_trailing_data") else "Low",
        "explanation": "Data after a valid image end marker can indicate a hidden payload or archive appended to a carrier file.",
    })

    if zsteg:
        hits = zsteg.get("interesting_hits", [])
        indicators.append({
            "name": "zsteg signal",
            "status": f"{len(hits)} interesting hit(s)" if hits else "No interesting hits or tool unavailable",
            "severity": "High" if hits else "Informational",
            "explanation": "zsteg output is treated as triage evidence and should be reviewed manually when present.",
        })

    indicators.append({
        "name": "Suspicious color distribution note",
        "status": image_profile.get("color_distribution_note", "No image profile available."),
        "severity": image_profile.get("severity", "Informational"),
        "explanation": "Large channel imbalance or unusually flat variation can help prioritize visual stego review.",
    })
    return indicators


def analyze_metadata_notes(result: dict) -> list[dict]:
    metadata = result.get("metadata", {}).get("parsed", {})
    notes = []
    image_like = result.get("dimensions") or result["binary"]["signature"]["detected_mime"].startswith("image/")
    if image_like and not metadata:
        notes.append({
            "title": "Metadata appears stripped or unavailable",
            "severity": "Low",
            "note": "The image has little or no embedded metadata. This can be normal, but it is also consistent with privacy stripping.",
            "evidence": "empty metadata",
        })

    lowered_values = " ".join(str(value).lower() for value in metadata.values())
    if any(tool in lowered_values for tool in ("exiftool", "imagemagick", "gimp", "photoshop", "canva")):
        notes.append({
            "title": "Creation or editing software identified",
            "severity": "Informational",
            "note": "Software tags are useful for provenance review and can explain benign metadata transformations.",
            "evidence": "software metadata",
        })
    if any(token in lowered_values for token in ("base64", "secret", "flag", "picoctf", "hidden")):
        notes.append({
            "title": "Suspicious metadata content",
            "severity": "High",
            "note": "Metadata contains CTF or hidden-data keywords that should be reviewed before deeper extraction.",
            "evidence": "keyword in metadata",
        })
    return notes


def build_adversarial_assessment(result: dict) -> list[str]:
    hypotheses = []
    if result["trailing_data"].get("has_trailing_data"):
        hypotheses.append("File may be padded to disguise appended content after a valid file terminator.")
    if result["strings"].get("stats", {}).get("suspicious_count", 0):
        hypotheses.append("Embedded readable strings could indicate operator error, hidden instructions, or CTF clue placement.")
    if any(section["reason"] == "Suspicious file tail" for section in result["entropy"].get("suspicious_sections", [])):
        hypotheses.append("Entropy spike near file tail may suggest compressed, encrypted, or encoded payload material.")
    if any(note["title"].startswith("Metadata appears stripped") for note in result.get("metadata_notes", [])):
        hypotheses.append("Metadata appears intentionally minimized, which can be consistent with privacy tooling or anti-forensic behavior.")
    if not result["binary"]["signature"]["extension_matches"]:
        hypotheses.append("Extension and signature mismatch could indicate file masquerading or mislabeled evidence.")
    if result.get("flags"):
        hypotheses.append("Flag-like content was recovered, which is typical of CTF artifacts and should be preserved in the report.")
    if not hypotheses:
        hypotheses.append("No strong adversarial hypothesis was produced by first-look heuristics; preserve the file and correlate with source context.")
    return hypotheses


def build_analyst_summary(result: dict) -> dict:
    top_findings = [
        f"{item['severity']}: {item['title']} ({item['category']})"
        for item in result["findings"]
        if item["severity"] != "Informational"
    ][:8]
    if not top_findings:
        top_findings = ["No high-priority forensic indicators were found by the current analyzer set."]

    recommendations = [
        "Review suspicious offsets before attempting extraction.",
        "Inspect tail bytes and compare them against expected file format boundaries.",
        "Preserve your original local file and generated report as evidence.",
        "Compare MD5, SHA1, and SHA256 with known-good or challenge-provided values.",
    ]
    if result["trailing_data"].get("has_trailing_data"):
        recommendations.append("Extract appended tail content in an offline forensic workspace if authorized.")
    if result["entropy"].get("suspicious_sections"):
        recommendations.append("Prioritize high-entropy and abrupt-transition sections for manual hex review.")
    if result["binary"].get("binary_patterns"):
        recommendations.append("Treat embedded executable/archive markers as leads for controlled offline analysis.")

    paragraph = (
        f"Stegama analyzed {result['filename']} in {result['scan_mode']['label']} mode and assigned "
        f"a {result['score']}/100 suspicion score with verdict '{result['verdict']}'. "
        "The report prioritizes observable forensic evidence such as file identity, readable strings, "
        "metadata, entropy transitions, steganography indicators, and suspicious offsets for defensive review."
    )

    return {
        "bullets": top_findings[:8],
        "paragraph": paragraph,
        "recommended_next_actions": recommendations[:8],
    }

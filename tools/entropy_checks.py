from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from .helpers import hex_range, human_size


def analyze_entropy(path: Path, window_size: int = 4096) -> dict:
    file_size = path.stat().st_size
    if file_size == 0:
        return {
            "overall_entropy": 0,
            "window_size": window_size,
            "windows_analyzed": 0,
            "suspicious_sections": [],
            "notes": ["Empty file; entropy analysis was not applicable."],
        }

    effective_window = min(window_size, max(512, file_size))
    windows = []
    overall_counts = Counter()
    start = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(effective_window)
            if not chunk:
                break
            overall_counts.update(chunk)
            windows.append({
                "start": start,
                "end": start + len(chunk) - 1,
                "length": len(chunk),
                "entropy": round(shannon_entropy(chunk), 3),
                "unique_ratio": round(len(set(chunk)) / max(1, len(chunk)), 4),
            })
            start += len(chunk)

    sections = []
    sections.extend(flag_high_entropy_regions(windows, file_size))
    sections.extend(flag_repeated_regions(windows))
    sections.extend(flag_entropy_changes(windows))
    sections.extend(flag_suspicious_tail(windows, file_size))
    sections = dedupe_sections(sections)

    for index, section in enumerate(sections, start=1):
        section["id"] = f"SEC-{index:03d}"

    notes = []
    if sections:
        notes.append(f"{len(sections)} suspicious section(s) prioritized for analyst review.")
    else:
        notes.append("No high-priority entropy sections were identified by the built-in heuristic.")

    return {
        "overall_entropy": round(entropy_from_counts(overall_counts, file_size), 3),
        "window_size": effective_window,
        "windows_analyzed": len(windows),
        "suspicious_sections": sections[:18],
        "notes": notes,
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def entropy_from_counts(counts: Counter, length: int) -> float:
    if length <= 0:
        return 0.0
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def flag_high_entropy_regions(windows: list[dict], file_size: int) -> list[dict]:
    sections = []
    active = None
    for window in windows:
        if window["entropy"] >= 7.35 and window["length"] >= 512:
            if active is None:
                active = dict(window)
            else:
                active["end"] = window["end"]
                active["length"] += window["length"]
                active["entropy"] = max(active["entropy"], window["entropy"])
        elif active is not None:
            sections.append(make_section(active, file_size, "High entropy region", "Compressed, encrypted, or encoded payload-like byte distribution.", "High"))
            active = None
    if active is not None:
        sections.append(make_section(active, file_size, "High entropy region", "Compressed, encrypted, or encoded payload-like byte distribution.", "High"))
    return sections


def flag_repeated_regions(windows: list[dict]) -> list[dict]:
    sections = []
    for window in windows:
        if window["length"] >= 512 and window["entropy"] <= 0.8 and window["unique_ratio"] <= 0.02:
            sections.append(make_section(window, None, "Low entropy repeated block", "Large repeated byte block can indicate padding, alignment tricks, or decoy filler.", "Medium"))
    return sections


def flag_entropy_changes(windows: list[dict]) -> list[dict]:
    sections = []
    for previous, current in zip(windows, windows[1:]):
        delta = abs(current["entropy"] - previous["entropy"])
        if delta >= 2.4:
            merged = {
                "start": previous["start"],
                "end": current["end"],
                "length": previous["length"] + current["length"],
                "entropy": max(previous["entropy"], current["entropy"]),
            }
            sections.append(make_section(merged, None, "Abrupt entropy transition", "Sharp local entropy change may mark an embedded chunk boundary or file tail payload.", "Medium"))
    return sections[:8]


def flag_suspicious_tail(windows: list[dict], file_size: int) -> list[dict]:
    if not windows:
        return []
    tail = windows[-1]
    if file_size > 2048 and tail["entropy"] >= 7.15:
        return [make_section(tail, file_size, "Suspicious file tail", "High entropy near the end of file can indicate appended compressed or encoded data.", "High")]
    return []


def make_section(window: dict, file_size: int | None, reason: str, note: str, severity: str) -> dict:
    start = window["start"]
    end = window["end"]
    entropy = round(window["entropy"], 3)
    confidence = "High" if entropy >= 7.6 or reason == "Suspicious file tail" else "Medium"
    if file_size is not None and end >= file_size - 2048 and severity == "High":
        note = f"{note} Region is close to EOF, making it a strong tail-review candidate."

    return {
        "id": "",
        "start_offset": start,
        "end_offset": end,
        "offset_range": hex_range(start, end),
        "length": window["length"],
        "size": human_size(window["length"]),
        "entropy": entropy,
        "reason": reason,
        "severity": severity,
        "confidence": confidence,
        "analyst_note": note,
    }


def dedupe_sections(sections: list[dict]) -> list[dict]:
    deduped = []
    seen = set()
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for section in sorted(sections, key=lambda item: (severity_order.get(item["severity"], 9), item["start_offset"])):
        key = (section["start_offset"], section["end_offset"], section["reason"])
        if key not in seen:
            seen.add(key)
            deduped.append(section)
    return deduped

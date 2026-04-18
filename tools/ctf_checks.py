from __future__ import annotations

import base64
import binascii
import re
from typing import Any


FLAG_RE = re.compile(r"\b(?:picoCTF|flag|ctf)\{[^}\r\n]{1,160}\}", re.IGNORECASE)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")


def extract_ctf_clues(result: dict) -> dict:
    sources = []

    metadata = result.get("metadata", {}).get("parsed", {})
    for key, value in _walk_metadata(metadata):
        sources.append({"source": f"metadata.{key}", "text": value})

    strings_block = result.get("strings", {})
    for value in strings_block.get("suspicious", []) + strings_block.get("all", [])[:120]:
        sources.append({"source": "strings", "text": value})

    lsb_preview = result.get("lsb", {}).get("ascii_preview")
    if lsb_preview:
        sources.append({"source": "lsb.ascii_preview", "text": lsb_preview})

    decoded_clues = _decode_base64_candidates(sources)
    flags = _find_flags(sources, decoded_clues)

    return {
        "flags": flags,
        "decoded_clues": decoded_clues,
    }


def _walk_metadata(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_metadata(child, child_prefix)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_prefix = f"{prefix}[{index}]"
            yield from _walk_metadata(child, child_prefix)
    elif value is not None:
        text = str(value).strip()
        if text:
            yield prefix or "value", text


def _decode_base64_candidates(sources: list[dict]) -> list[dict]:
    seen = set()
    decoded = []

    for item in sources:
        for match in BASE64_RE.finditer(item["text"]):
            candidate = match.group(0)
            normalized = candidate + ("=" * (-len(candidate) % 4))
            if normalized in seen:
                continue
            seen.add(normalized)

            try:
                raw = base64.b64decode(normalized, validate=True)
            except (binascii.Error, ValueError):
                continue

            if not raw or any(byte == 0 for byte in raw[:16]):
                continue

            text = raw.decode("utf-8", errors="replace").strip()
            if not _looks_useful(text):
                continue

            decoded.append({
                "source": item["source"],
                "encoded": candidate,
                "decoded": text,
            })

    return decoded[:30]


def _find_flags(sources: list[dict], decoded_clues: list[dict]) -> list[str]:
    flags = []
    seen = set()

    for item in sources:
        for match in FLAG_RE.finditer(item["text"]):
            flag = match.group(0)
            if flag.lower() not in seen:
                seen.add(flag.lower())
                flags.append(flag)

    for item in decoded_clues:
        for match in FLAG_RE.finditer(item["decoded"]):
            flag = match.group(0)
            if flag.lower() not in seen:
                seen.add(flag.lower())
                flags.append(flag)

    return flags[:20]


def _looks_useful(text: str) -> bool:
    if len(text) < 4:
        return False

    printable = sum(ch.isprintable() and ch not in "\x0b\x0c" for ch in text)
    if printable / max(1, len(text)) < 0.85:
        return False

    lowered = text.lower()
    useful_tokens = ("ctf", "flag", "pico", "secret", "hidden", "password", "{", "}")
    return any(token in lowered for token in useful_tokens)

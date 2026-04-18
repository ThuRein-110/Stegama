from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def file_hashes(path: Path) -> dict:
    return {
        "md5": hash_file(path, "md5"),
        "sha1": hash_file(path, "sha1"),
        "sha256": hash_file(path, "sha256"),
    }


def sha256_file(path: Path) -> str:
    return hash_file(path, "sha256")


def human_size(size_bytes: int) -> str:
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024

    return f"{size_bytes} B"


def hex_range(start: int, end: int) -> str:
    return f"0x{start:08X}-0x{end:08X}"

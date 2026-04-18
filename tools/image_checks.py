from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageStat

from .tool_checks import run_command

MAX_PIXEL_ANALYSIS_PIXELS = 8_000_000
PROFILE_SAMPLE_SIZE = (768, 768)


def analyze_image(path: Path) -> dict:
    result: dict = {
        "dimensions": None,
        "mode": None,
        "lsb": {},
        "zsteg": {"available": False, "interesting_hits": [], "raw": {}},
    }

    try:
        with Image.open(path) as img:
            result["dimensions"] = {"width": img.width, "height": img.height}
            result["mode"] = img.mode
            result["image_profile"] = image_profile(img)
            pixel_count = img.width * img.height
            if pixel_count > MAX_PIXEL_ANALYSIS_PIXELS:
                result["lsb"] = {
                    "note": (
                        "Pixel-level LSB scan skipped because the image is large enough to risk "
                        "exhausting the web worker. Use an offline workstation for full bit-plane review."
                    ),
                    "ascii_preview": "",
                    "ones_ratio": 0,
                    "severity": "Informational",
                    "skipped": True,
                    "pixel_count": pixel_count,
                }
            else:
                result["lsb"] = basic_lsb_scan(img)
    except Exception as exc:
        result["image_error"] = str(exc)

    if path.suffix.lower() in {".png", ".bmp"}:
        zsteg_raw = run_command(["zsteg", "-a", str(path)], timeout=20)
        result["zsteg"]["available"] = zsteg_raw.get("returncode") is not None or zsteg_raw.get("ok")
        result["zsteg"]["raw"] = zsteg_raw
        if zsteg_raw.get("stdout"):
            hits = []
            for line in zsteg_raw["stdout"].splitlines():
                lowered = line.lower()
                if any(token in lowered for token in ["text:", "file:", "openstego", "camouflage", "zlib"]):
                    hits.append(line.strip())
            result["zsteg"]["interesting_hits"] = hits[:50]

    return result



def basic_lsb_scan(img: Image.Image) -> dict:
    rgb = img.convert("RGB")
    pixels = []
    for index, pixel in enumerate(rgb.getdata()):
        if index >= 50000:
            break
        pixels.append(pixel)
    if not pixels:
        return {"note": "No pixels read", "ascii_preview": "", "ones_ratio": 0}

    bits = []
    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    if not bits:
        return {"note": "No LSB data extracted", "ascii_preview": "", "ones_ratio": 0}

    chars = []
    for i in range(0, min(len(bits), 8 * 256), 8):
        byte = 0
        byte_bits = bits[i:i + 8]
        if len(byte_bits) < 8:
            break
        for bit in byte_bits:
            byte = (byte << 1) | bit
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        else:
            chars.append(".")

    ones_ratio = sum(bits) / len(bits)
    note = "LSB preview generated"
    if 0.45 <= ones_ratio <= 0.55:
        note = "LSB distribution looks balanced; hidden content is possible but not proven"

    stat = ImageStat.Stat(rgb)
    severity = "Low"
    if 0.49 <= ones_ratio <= 0.51:
        severity = "Medium"
    elif ones_ratio < 0.35 or ones_ratio > 0.65:
        severity = "Medium"

    return {
        "note": note,
        "ascii_preview": "".join(chars[:256]),
        "ones_ratio": round(ones_ratio, 4),
        "channel_mean": [round(v, 2) for v in stat.mean],
        "channel_stddev": [round(v, 2) for v in stat.stddev],
        "severity": severity,
    }


def image_profile(img: Image.Image) -> dict:
    sample = img.copy()
    sample.thumbnail(PROFILE_SAMPLE_SIZE)
    rgb = sample.convert("RGB")
    stat = ImageStat.Stat(rgb)
    means = [round(value, 2) for value in stat.mean]
    stddev = [round(value, 2) for value in stat.stddev]
    spread = max(means) - min(means)
    note = "Color channels are within an expected broad distribution for first-look triage."
    severity = "Low"
    if spread > 75:
        note = "One color channel differs strongly from the others; review bit planes or channel-specific content."
        severity = "Medium"
    if max(stddev) < 8:
        note = "Very low channel variation may indicate a flat carrier, padding, or generated image content."
        severity = "Medium"

    return {
        "channel_mean": means,
        "channel_stddev": stddev,
        "color_distribution_note": note,
        "severity": severity,
    }

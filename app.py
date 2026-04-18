from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from collections import deque
from pathlib import Path

from flask import Flask, current_app, flash, g, jsonify, redirect, render_template, request, send_from_directory, url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from tools.analyzer import analyze_file

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
SITE_URL = "https://stegama.onrender.com"
REPORT_NAME_RE = re.compile(r"^[a-f0-9]{32}_[A-Za-z0-9_.-]+\.json$")
SCAN_MODES = {"quick", "deep", "image", "artifact"}
PRIVATE_ENDPOINTS = {"analyze", "api_analyze", "download_report"}
SEO_PAGES = [
    {
        "slug": "guide",
        "path": "/guide",
        "eyebrow": "Steganography detection guide",
        "title": "How to Detect Hidden Data in Images",
        "meta_title": "How to Detect Hidden Data in Images - Stegama Guide",
        "description": (
            "Learn a practical steganography workflow for checking images and files for hidden data, "
            "metadata clues, appended payloads, entropy changes, and CTF flags."
        ),
        "keywords": (
            "detect hidden data in images, image hidden data checker, steganography detection tool online, "
            "online forensic file analyzer, stegama"
        ),
        "lede": (
            "A strong first pass looks for file identity problems, metadata hints, suspicious strings, "
            "trailing bytes, and entropy shifts before moving into specialized stego tooling."
        ),
        "sections": [
            {
                "heading": "Start with file identity",
                "body": (
                    "Confirm that the extension, MIME type, magic bytes, and real file signature agree. "
                    "A PNG that begins like a ZIP, executable, or archive deserves closer review."
                ),
                "bullets": [
                    "Compare the displayed extension with the detected binary signature.",
                    "Check the first bytes and last bytes for embedded archive or executable markers.",
                    "Record hashes before sharing samples or asking teammates to reproduce findings.",
                ],
            },
            {
                "heading": "Review metadata and readable strings",
                "body": (
                    "Metadata, comments, and printable strings often reveal passwords, tool names, CTF flag "
                    "formats, base64 fragments, or suspicious operator notes."
                ),
                "bullets": [
                    "Look for EXIF comments, software names, timestamps, and unusual creator fields.",
                    "Search strings for flag patterns, archive names, URLs, commands, and encoded text.",
                    "Treat readable clues as pivots, not final proof, until they match binary evidence.",
                ],
            },
            {
                "heading": "Inspect appended data and entropy",
                "body": (
                    "Hidden payloads are often appended after a valid image end marker or packed into high "
                    "entropy regions that stand out from the rest of the carrier file."
                ),
                "bullets": [
                    "Check for bytes after JPEG, PNG, GIF, and archive end markers.",
                    "Compare entropy windows to find compressed, encrypted, or packed regions.",
                    "Use image-focused scans when LSB, channel, or color-plane anomalies are suspected.",
                ],
            },
        ],
    },
    {
        "slug": "learn-steganography",
        "path": "/learn-steganography",
        "eyebrow": "Learn steganography",
        "title": "Understanding LSB Steganography",
        "meta_title": "Understanding LSB Steganography - Stegama",
        "description": (
            "Understand least significant bit steganography, why PNG and BMP files are common carriers, "
            "and how analysts spot hidden data during CTF and forensic investigations."
        ),
        "keywords": (
            "LSB steganography, learn steganography, PNG steganography, BMP stego analysis, "
            "beginner stego analysis website"
        ),
        "lede": (
            "Least significant bit steganography hides information by changing tiny pixel-value details. "
            "Those changes are hard to see visually, but they can leave statistical and channel-level clues."
        ),
        "sections": [
            {
                "heading": "What LSB hiding changes",
                "body": (
                    "Digital pixels store color values as numbers. LSB techniques alter the smallest bit in "
                    "one or more channels so the image still looks normal while carrying a hidden message."
                ),
                "bullets": [
                    "PNG and BMP are common in CTFs because lossless formats preserve exact pixel values.",
                    "JPEG compression can destroy simple LSB payloads, so JPEG stego usually needs other methods.",
                    "Suspicious channel noise can appear in red, green, blue, or alpha planes.",
                ],
            },
            {
                "heading": "How analysts detect it",
                "body": (
                    "Detection starts with quick visual and statistical checks, then moves into bit-plane "
                    "views, channel extraction, known tool signatures, and decoded payload review."
                ),
                "bullets": [
                    "Run a carrier-focused scan to look for LSB previews and channel irregularities.",
                    "Compare file size, pixel dimensions, metadata, and entropy against normal images.",
                    "Validate recovered messages with hashes, offsets, and repeatable extraction steps.",
                ],
            },
            {
                "heading": "Why Stegama helps beginners",
                "body": (
                    "Stegama groups the first-pass evidence into readable findings so new CTF players can "
                    "see what to investigate next instead of jumping between unrelated command outputs."
                ),
                "bullets": [
                    "Use Image Stego Scan for PNG, BMP, GIF, WEBP, and JPEG review.",
                    "Use Deep Scan when entropy or appended data looks suspicious.",
                    "Export JSON reports to keep investigation notes consistent across teammates.",
                ],
            },
        ],
    },
    {
        "slug": "ctf-stego-tips",
        "path": "/ctf-stego-tips",
        "eyebrow": "CTF stego tips",
        "title": "Best First Checks for CTF Steganography",
        "meta_title": "CTF Stego Analyzer Tips - Free Online Steganography Checks",
        "description": (
            "Use this CTF steganography checklist to find flags in images and files with hidden strings, "
            "metadata, appended archives, base64 clues, and suspicious entropy."
        ),
        "keywords": (
            "CTF stego analyzer free, ctf steganography tool online free, detect hidden data in png online ctf, "
            "stego CTF tips, hidden data detector"
        ),
        "lede": (
            "Most beginner and intermediate stego challenges reward disciplined first checks: file type, "
            "metadata, strings, appended bytes, archive clues, and simple encodings."
        ),
        "sections": [
            {
                "heading": "Run the fast checks first",
                "body": (
                    "Before trying passwords or heavy extraction, collect the obvious evidence. Many flags "
                    "are visible in metadata, printable strings, or bytes appended after a valid image."
                ),
                "bullets": [
                    "Check magic bytes and extension mismatch for disguised archives.",
                    "Search strings for CTF flag formats, base64-looking values, and challenge hints.",
                    "Inspect trailing data after PNG IEND, JPEG EOI, and GIF trailer markers.",
                ],
            },
            {
                "heading": "Choose the right scan mode",
                "body": (
                    "Different CTF artifacts need different levels of attention. Stegama keeps the workflow "
                    "fast by separating quick triage, deep review, image stego, and suspicious artifact checks."
                ),
                "bullets": [
                    "Quick Scan is best for first-pass hashes, identity, metadata, and strings.",
                    "Image Stego Scan is best for channel and LSB-oriented image challenges.",
                    "Deep Scan is best when entropy, payload packing, or appended data is likely.",
                ],
            },
            {
                "heading": "Turn findings into next actions",
                "body": (
                    "A good CTF report does not stop at a suspicious clue. It names what was found, why it "
                    "matters, and the next extraction or decoding step to try."
                ),
                "bullets": [
                    "Use offsets to extract suspicious sections with a hex editor or command-line tool.",
                    "Decode base64, hex, rot, and archive hints only after confirming the evidence location.",
                    "Save repeatable notes so teammates can reproduce the path from artifact to flag.",
                ],
            },
        ],
    },
]
SEO_PAGES_BY_SLUG = {page["slug"]: page for page in SEO_PAGES}
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "bmp", "gif", "webp", "wav", "au", "txt", "bin", "zip",
    "pdf", "docx", "xlsx", "pptx", "jar", "exe", "dll", "elf", "so"
}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB, sized for Render's 512 MB instances
RATE_LIMIT_MAX_ANALYSES = int(os.environ.get("STEGAMA_RATE_LIMIT_MAX_ANALYSES", "12"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("STEGAMA_RATE_LIMIT_WINDOW_SECONDS", str(15 * 60)))
ARTIFACT_RETENTION_SECONDS = int(float(os.environ.get("STEGAMA_RETENTION_HOURS", "24")) * 60 * 60)
ARTIFACT_CLEANUP_INTERVAL_SECONDS = 10 * 60
CSRF_MAX_AGE_SECONDS = 2 * 60 * 60

_analysis_attempts: dict[str, deque[float]] = {}
_last_artifact_cleanup = 0.0


def create_app() -> Flask:
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.update(
        SECRET_KEY=configured_secret_key(),
        UPLOAD_FOLDER=str(UPLOAD_DIR),
        REPORT_FOLDER=str(REPORT_DIR),
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", default=False),
    )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    @app.before_request
    def prepare_security_context():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.after_request
    def add_security_headers(response):
        nonce = getattr(g, "csp_nonce", "")
        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        if request.is_secure:
            csp = f"{csp}; upgrade-insecure-requests"

        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
        )
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        if request.endpoint in PRIVATE_ENDPOINTS:
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Robots-Tag"] = "noindex, noarchive, nosnippet"

        return response

    @app.context_processor
    def inject_security_helpers():
        return {
            "csrf_token": csrf_token,
            "csp_nonce": lambda: getattr(g, "csp_nonce", ""),
        }

    @app.route("/", methods=["GET"])
    @app.route("/analysis", methods=["GET"])
    def index():
        return render_template("index.html", site_url=SITE_URL, seo_pages=SEO_PAGES)

    @app.route("/guide", methods=["GET"])
    def guide():
        return render_seo_page("guide")

    @app.route("/learn-steganography", methods=["GET"])
    def learn_steganography():
        return render_seo_page("learn-steganography")

    @app.route("/ctf-stego-tips", methods=["GET"])
    def ctf_stego_tips():
        return render_seo_page("ctf-stego-tips")

    @app.route("/robots.txt", methods=["GET"])
    def robots_txt():
        return send_from_directory(BASE_DIR, "robots.txt", mimetype="text/plain")

    @app.route("/sitemap.xml", methods=["GET"])
    def sitemap_xml():
        return send_from_directory(BASE_DIR, "sitemap.xml", mimetype="application/xml")

    @app.route("/google53e27be8688dc71c.html", methods=["GET"])
    def google_site_verification():
        return send_from_directory(BASE_DIR, "google53e27be8688dc71c.html", mimetype="text/html")

    @app.route("/healthz", methods=["GET"])
    def healthz():
        return jsonify({"status": "ok", "service": "stegama"})

    @app.route("/analyze", methods=["GET", "POST"])
    def analyze():
        if request.method == "GET":
            return redirect(url_for("index"))

        maybe_cleanup_old_artifacts()

        limited = reject_if_rate_limited(json_response=False)
        if limited:
            return limited

        if not validate_csrf_token():
            flash("Security check failed. Please refresh the page and upload the file again.", "error")
            return redirect(url_for("index"))

        uploaded, filename, error_message = uploaded_file_from_request()
        if error_message:
            flash(error_message, "error")
            return redirect(url_for("index"))

        try:
            result, report_filename = analyze_uploaded_file(uploaded, filename, request.form.get("scan_mode"))
        except Exception:
            reference = secrets.token_hex(6)
            app.logger.exception("Stegama analysis failed for %s", filename)
            return render_template(
                "error.html",
                title="Analysis could not complete",
                message=(
                    "Stegama safely stopped this scan instead of exposing internal error details. "
                    f"Reference: {reference}."
                ),
                reference=reference,
            ), 500

        return render_template("result.html", result=result, report_filename=report_filename)

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        maybe_cleanup_old_artifacts()

        limited = reject_if_rate_limited(json_response=True)
        if limited:
            return limited

        uploaded, filename, error_message = uploaded_file_from_request()
        if error_message:
            return jsonify({"error": "invalid_upload", "message": error_message}), 400

        try:
            result, report_filename = analyze_uploaded_file(uploaded, filename, request.form.get("scan_mode"))
        except Exception:
            reference = secrets.token_hex(6)
            app.logger.exception("Stegama API analysis failed for %s", filename)
            return jsonify({
                "error": "analysis_failed",
                "message": "Stegama safely stopped this scan.",
                "reference": reference,
            }), 500

        result["report_download"] = url_for("download_report", filename=report_filename)
        return jsonify(result)

    @app.route("/reports/<filename>", methods=["GET"])
    def download_report(filename: str):
        if not is_safe_report_filename(filename):
            return render_template(
                "error.html",
                title="Report not found",
                message="The requested report link is invalid or has expired.",
                reference=None,
            ), 404
        return send_from_directory(REPORT_DIR, filename, as_attachment=True, mimetype="application/json")

    @app.errorhandler(413)
    def file_too_large(_error):
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "file_too_large",
                "message": "Artifact exceeds the 20 MB upload limit.",
            }), 413
        flash("Artifact exceeds the 20 MB upload limit for this Render instance.", "error")
        return redirect(url_for("index"))

    return app


def configured_secret_key() -> str:
    key = os.environ.get("SECRET_KEY")
    if key and len(key) >= 32:
        return key
    if key:
        logging.getLogger(__name__).warning("SECRET_KEY is set but shorter than 32 characters; using an ephemeral key.")
    else:
        logging.getLogger(__name__).warning("SECRET_KEY is not set; using an ephemeral key for this process.")
    return secrets.token_hex(32)


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def csrf_token() -> str:
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="stegama-upload-csrf")
    return serializer.dumps({"nonce": secrets.token_urlsafe(16), "purpose": "artifact-upload"})


def validate_csrf_token() -> bool:
    supplied = request.form.get("csrf_token", "")
    if not supplied:
        return False
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="stegama-upload-csrf")
    try:
        payload = serializer.loads(supplied, max_age=CSRF_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return False
    return payload.get("purpose") == "artifact-upload"


def reject_if_rate_limited(json_response: bool):
    allowed, retry_after = record_analysis_attempt()
    if allowed:
        return None

    if json_response:
        response = jsonify({
            "error": "rate_limited",
            "message": "Too many analysis requests. Please wait before scanning another artifact.",
            "retry_after_seconds": retry_after,
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    flash("Too many analysis requests. Please wait a few minutes before scanning another artifact.", "error")
    response = redirect(url_for("index"))
    response.headers["Retry-After"] = str(retry_after)
    return response


def record_analysis_attempt() -> tuple[bool, int]:
    now = time.monotonic()
    key = client_ip()
    attempts = _analysis_attempts.setdefault(key, deque())
    while attempts and now - attempts[0] > RATE_LIMIT_WINDOW_SECONDS:
        attempts.popleft()

    if len(attempts) >= RATE_LIMIT_MAX_ANALYSES:
        retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - attempts[0])))
        return False, retry_after

    attempts.append(now)
    return True, 0


def client_ip() -> str:
    return request.remote_addr or "unknown"


def uploaded_file_from_request():
    if request.content_length and request.content_length > MAX_CONTENT_LENGTH:
        return None, "", "Artifact exceeds the 20 MB upload limit for this Render instance."
    if "file" not in request.files:
        return None, "", "No file part found in request."

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return None, "", "Please choose a file."

    filename = secure_filename(uploaded.filename)
    if not filename or not allowed_file(filename):
        return None, "", "Unsupported file type for this starter version."

    return uploaded, filename, None


def analyze_uploaded_file(uploaded, filename: str, scan_mode: str | None) -> tuple[dict, str]:
    token = secrets.token_hex(16)
    saved_name = f"{token}_{filename}"
    save_path = safe_child_path(UPLOAD_DIR, saved_name)
    report_filename = f"{save_path.stem}.json"
    report_path = safe_child_path(REPORT_DIR, report_filename)

    try:
        uploaded.save(save_path)
        result = analyze_file(save_path, original_name=filename, scan_mode=normalize_scan_mode_key(scan_mode))
        report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        safe_unlink(save_path, UPLOAD_DIR)
        return result, report_filename
    except Exception:
        safe_unlink(save_path, UPLOAD_DIR)
        safe_unlink(report_path, REPORT_DIR)
        raise


def normalize_scan_mode_key(mode: str | None) -> str:
    key = (mode or "quick").lower()
    return key if key in SCAN_MODES else "quick"


def safe_child_path(directory: Path, filename: str) -> Path:
    directory_resolved = directory.resolve()
    path = (directory / filename).resolve()
    if path.parent != directory_resolved:
        raise ValueError("Unsafe artifact path rejected.")
    return path


def is_safe_report_filename(filename: str) -> bool:
    if secure_filename(filename) != filename:
        return False
    if not REPORT_NAME_RE.fullmatch(filename):
        return False
    return safe_child_path(REPORT_DIR, filename).is_file()


def maybe_cleanup_old_artifacts() -> None:
    global _last_artifact_cleanup
    now = time.monotonic()
    if now - _last_artifact_cleanup < ARTIFACT_CLEANUP_INTERVAL_SECONDS:
        return
    _last_artifact_cleanup = now
    cleanup_old_artifacts()


def cleanup_old_artifacts() -> None:
    cutoff = time.time() - ARTIFACT_RETENTION_SECONDS
    for directory in (UPLOAD_DIR, REPORT_DIR):
        if not directory.exists():
            continue
        for path in directory.iterdir():
            if not path.is_file():
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    safe_unlink(path, directory)
            except OSError:
                logging.getLogger(__name__).exception("Could not clean old artifact: %s", path.name)


def safe_unlink(path: Path, directory: Path) -> None:
    try:
        resolved = path.resolve()
        if resolved.parent != directory.resolve():
            raise ValueError("Refusing to delete outside artifact directory.")
        if resolved.exists() and resolved.is_file():
            resolved.unlink()
    except FileNotFoundError:
        return


def render_seo_page(slug: str):
    page = SEO_PAGES_BY_SLUG[slug]
    return render_template(
        "content_page.html",
        page=page,
        site_url=SITE_URL,
        seo_pages=SEO_PAGES,
        canonical_url=f"{SITE_URL}{page['path']}",
    )



def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

from tools.analyzer import analyze_file

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
SITE_URL = "https://stegama.onrender.com"
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


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
    app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
    app.config["REPORT_FOLDER"] = str(REPORT_DIR)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

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

        if "file" not in request.files:
            flash("No file part found in request.", "error")
            return redirect(url_for("index"))

        uploaded = request.files["file"]
        if uploaded.filename == "":
            flash("Please choose a file.", "error")
            return redirect(url_for("index"))

        filename = secure_filename(uploaded.filename)
        if not allowed_file(filename):
            flash("Unsupported file type for this starter version.", "error")
            return redirect(url_for("index"))

        token = secrets.token_hex(8)
        saved_name = f"{token}_{filename}"
        save_path = UPLOAD_DIR / saved_name
        uploaded.save(save_path)

        scan_mode = request.form.get("scan_mode", "quick")
        try:
            result = analyze_file(save_path, original_name=filename, scan_mode=scan_mode)
            report_path = REPORT_DIR / f"{save_path.stem}.json"
            report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            app.logger.exception("Stegama analysis failed for %s", filename)
            return render_template(
                "error.html",
                title="Analysis could not complete",
                message="Stegama safely stopped this scan instead of returning a broken gateway response.",
                detail=str(exc),
            ), 500

        return render_template("result.html", result=result, report_filename=report_path.name)

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        if "file" not in request.files:
            return jsonify({"error": "missing file field"}), 400

        uploaded = request.files["file"]
        if uploaded.filename == "":
            return jsonify({"error": "empty filename"}), 400

        filename = secure_filename(uploaded.filename)
        if not allowed_file(filename):
            return jsonify({"error": "unsupported file type"}), 400

        token = secrets.token_hex(8)
        saved_name = f"{token}_{filename}"
        save_path = UPLOAD_DIR / saved_name
        uploaded.save(save_path)

        scan_mode = request.form.get("scan_mode", "quick")
        try:
            result = analyze_file(save_path, original_name=filename, scan_mode=scan_mode)
            report_path = REPORT_DIR / f"{save_path.stem}.json"
            report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            app.logger.exception("Stegama API analysis failed for %s", filename)
            return jsonify({
                "error": "analysis_failed",
                "message": "Stegama safely stopped this scan.",
                "detail": str(exc),
            }), 500

        result["report_download"] = url_for("download_report", filename=report_path.name)
        return jsonify(result)

    @app.route("/reports/<path:filename>", methods=["GET"])
    def download_report(filename: str):
        return send_from_directory(REPORT_DIR, filename, as_attachment=True)

    @app.errorhandler(413)
    def file_too_large(_error):
        flash("Artifact exceeds the 20 MB upload limit for this Render instance.", "error")
        return redirect(url_for("index"))

    return app


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

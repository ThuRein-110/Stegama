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
ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "bmp", "gif", "webp", "wav", "au", "txt", "bin", "zip"
}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
    app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
    app.config["REPORT_FOLDER"] = str(REPORT_DIR)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    @app.route("/", methods=["GET"])
    def index():
        return render_template("index.html")

    @app.route("/analyze", methods=["POST"])
    def analyze():
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

        result = analyze_file(save_path)
        report_path = REPORT_DIR / f"{save_path.stem}.json"
        report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

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

        result = analyze_file(save_path)
        report_path = REPORT_DIR / f"{save_path.stem}.json"
        report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        result["report_download"] = url_for("download_report", filename=report_path.name)
        return jsonify(result)

    @app.route("/reports/<path:filename>", methods=["GET"])
    def download_report(filename: str):
        return send_from_directory(REPORT_DIR, filename, as_attachment=True)

    return app



def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
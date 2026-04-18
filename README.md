# Stegama

Stegama is a defensive web application for steganography detection, suspicious file triage, and CTF-style forensic analysis. It is designed as a hybrid of a CTF investigation toolkit, a SOC artifact triage dashboard, and a DFIR first-look report console.

## Scope

Stegama performs static, defensive analysis only. It does not execute uploaded artifacts, deliver exploits, automate credential attacks, brute force targets, or provide offensive workflows.

## Security and Privacy Defaults

- Uploaded files are analyzed statically and deleted after the JSON report is generated.
- Generated reports use 128-bit random filenames, are marked `noindex`, and are sent with `Cache-Control: no-store`.
- Old reports are cleaned automatically; the default retention window is 24 hours and can be changed with `STEGAMA_RETENTION_HOURS`.
- Browser uploads use a signed CSRF token, and analysis endpoints have a small in-memory per-IP rate limit.
- Security headers include CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, Permissions Policy, and HSTS on HTTPS.
- Server file paths and Python exception details are not returned in reports, API responses, or error pages.

Set a strong `SECRET_KEY` in production so signed tokens and Flask sessions survive restarts. Use at least 32 random characters.

## Core Capabilities

- Drag-and-drop artifact upload with scan mode selection
- 20 MB upload limit sized for Render's 512 MB instances
- MD5, SHA1, and SHA256 hashing
- Magic byte and extension mismatch review
- MIME and first/last byte previews
- Memory-safe printable string extraction with suspicious keyword severity
- CTF flag and base64-style clue detection
- Metadata extraction with graceful fallback when `exiftool` is unavailable
- Image-focused LSB, channel, tail, and zsteg-assisted triage with large-image safety skips
- Streaming entropy analysis with suspicious offset section prioritization
- Defensive adversarial assessment and analyst next actions

## Project Structure

```txt
steg-detect-web/
|-- app.py
|-- Procfile
|-- render.yaml
|-- requirements.txt
|-- README.md
|-- docs/
|   `-- sample_analysis_response.json
|-- reports/
|-- uploads/
|-- static/
|   |-- css/
|   |   `-- style.css
|   `-- js/
|       `-- app.js
|-- templates/
|   |-- error.html
|   |-- index.html
|   `-- result.html
`-- tools/
    |-- analyzer.py
    |-- binary_checks.py
    |-- ctf_checks.py
    |-- entropy_checks.py
    |-- helpers.py
    |-- image_checks.py
    `-- tool_checks.py
```

## Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:10000`.

## Render Deployment

Use a Render Web Service, not a Static Site.

Build command:

```bash
pip install -r requirements.txt
```

Start command:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 120 --max-requests 80 --max-requests-jitter 20
```

Health check endpoint:

```txt
/healthz
```

`render.yaml` and `Procfile` are included for deployment-friendly defaults.

## Optional External Tools

Stegama works without these tools and shows unavailable states gracefully:

- `file`
- `exiftool`
- `zsteg`

Python fallback analyzers provide metadata, printable strings, binary previews, entropy sections, and CTF clue detection where possible. The app avoids capturing large external command output to stay within small Render memory limits.

# StegDetect CTF Web

A starter Flask web app for **CTF-style steganography triage**.

## Features

- Upload a file from the browser
- Run `file` to detect the real file type
- Run `strings` to extract printable content
- Run `exiftool -j` to parse metadata
- Detect simple appended/trailing data in PNG/JPG/GIF
- Generate a basic RGB LSB preview for images
- Run `zsteg -a` for PNG/BMP if installed
- Save a JSON report for each scan

## Project structure

```txt
steg-detect-web/
├── app.py
├── requirements.txt
├── README.md
├── reports/
├── uploads/
├── static/
│   ├── css/style.css
│   └── js/app.js
├── templates/
│   ├── index.html
│   └── result.html
└── tools/
    ├── analyzer.py
    ├── helpers.py
    ├── image_checks.py
    └── tool_checks.py
```

## Install

Create a virtual environment and install Flask with pip. Flask's docs show installation with `pip install Flask`. citeturn941174search0turn941174search6

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install base CLI tools:

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install file binutils libimage-exiftool-perl ruby-full
sudo gem install zsteg
```

ExifTool is a command-line application for reading metadata from many file types, and it can be run directly after installation. citeturn941174search7turn941174search16

zsteg is designed to detect hidden data in PNG and BMP files, and its README documents installation with `gem install zsteg`. citeturn941174search2turn941174search5

## Run

```bash
python app.py
```

Open:

```txt
http://127.0.0.1:5000
```

## API

`POST /api/analyze` with multipart form field `file`

Example:

```bash
curl -F "file=@challenge.png" http://127.0.0.1:5000/api/analyze
```

## Notes

- This starter app is for **detection / triage**, not full extraction.
- It is useful for CTF workflows where you want a fast first-pass dashboard.
- Add optional modules later for steghide, binwalk, foremost, or custom extractors.

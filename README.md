# Security Log Analysis & Threat Detection

A local Flask-based defensive security log analysis system.

## Features
- Upload `.log`, `.txt`, `.json`, or `.jsonl` security logs.
- Paste log entries directly into the dashboard.
- Rule-based detection for repeated failed authentication/brute-force activity, suspicious events, failed authentication, and unusual successful login times.
- SQLite alert storage, severity classification, search/filtering, and 50 alerts per page.
- Existing SOC-style dashboard preserved.

## Run
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Example JSON
```json
[{"timestamp":"2026-08-16 12:30:00","username":"admin","ip_address":"192.168.1.10","event":"failed_login"}]
```

The project analyzes logs supplied by the user. It does not connect to AWS/Azure or generate network traffic.

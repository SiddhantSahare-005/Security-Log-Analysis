import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for

from db import (
    init_db,
    get_alerts,
    get_alert_stats,
    clear_alerts,
)
from detector import analyze_log_source


# Load .env for local development.
# On Vercel, DATABASE_URL comes from Environment Variables.
load_dotenv()


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent

# Vercel has a temporary writable /tmp directory.
# Locally, uploaded files are stored in logs/uploads/.
if os.getenv("VERCEL"):
    UPLOAD_DIR = Path("/tmp/security_log_uploads")
else:
    UPLOAD_DIR = BASE_DIR / "logs" / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Maximum uploaded log size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


# Initialize PostgreSQL table/indexes.
init_db()


@app.route("/")
def dashboard():

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except (ValueError, TypeError):
        page = 1

    per_page = 50

    stats = get_alert_stats()

    alerts, total_pages = get_alerts(
        page=page,
        per_page=per_page
    )

    if page > total_pages:
        page = total_pages

        alerts, total_pages = get_alerts(
            page=page,
            per_page=per_page
        )

    return render_template(
        "dashboard.html",
        alerts=alerts,
        stats=stats,
        page=page,
        total_pages=total_pages,
        input_message=request.args.get("message", ""),
    )


@app.route("/upload", methods=["POST"])
def upload_logs():

    uploaded = request.files.get("log_file")
    pasted = request.form.get("log_text", "").strip()

    if not uploaded and not pasted:
        return redirect(
            url_for(
                "dashboard",
                message="No log file or log data was provided."
            )
        )

    try:

        # -----------------------------
        # Uploaded file
        # -----------------------------

        if uploaded and uploaded.filename:

            filename = Path(uploaded.filename).name
            extension = Path(filename).suffix.lower()

            allowed_extensions = {
                ".log",
                ".txt",
                ".json",
                ".jsonl",
            }

            if extension not in allowed_extensions:
                return redirect(
                    url_for(
                        "dashboard",
                        message=(
                            "Unsupported file type. "
                            "Use LOG, TXT, JSON, or JSONL."
                        ),
                    )
                )

            timestamp = __import__(
                "datetime"
            ).datetime.now().strftime(
                "%Y%m%d_%H%M%S_%f"
            )

            safe_name = (
                f"upload_{timestamp}{extension}"
            )

            destination = UPLOAD_DIR / safe_name

            uploaded.save(destination)

            result = analyze_log_source(destination)

            message = (
                f"Analyzed {result['logs']} log entries "
                f"and generated {result['alerts']} "
                f"new security alerts."
            )

        # -----------------------------
        # Pasted log data
        # -----------------------------

        else:

            timestamp = __import__(
                "datetime"
            ).datetime.now().strftime(
                "%Y%m%d_%H%M%S_%f"
            )

            destination = (
                UPLOAD_DIR /
                f"pasted_{timestamp}.log"
            )

            destination.write_text(
                pasted,
                encoding="utf-8"
            )

            result = analyze_log_source(destination)

            message = (
                f"Analyzed {result['logs']} pasted "
                f"log entries and generated "
                f"{result['alerts']} new security alerts."
            )

    except Exception as exc:

        message = f"Log analysis failed: {exc}"

    return redirect(
        url_for(
            "dashboard",
            message=message
        )
    )


@app.route("/scan")
def scan():

    try:

        files = sorted(
            [
                p
                for p in UPLOAD_DIR.iterdir()
                if (
                    p.is_file()
                    and p.suffix.lower()
                    in {
                        ".log",
                        ".txt",
                        ".json",
                        ".jsonl",
                    }
                )
            ],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

    except OSError:
        files = []

    if not files:
        return redirect(
            url_for(
                "dashboard",
                message=(
                    "Upload or paste logs first, "
                    "then run the security scan."
                ),
            )
        )

    try:

        result = analyze_log_source(files[0])

        message = (
            f"Security scan completed. "
            f"Analyzed {result['logs']} entries "
            f"and generated {result['alerts']} "
            f"new alerts."
        )

    except Exception as exc:

        message = f"Security scan failed: {exc}"

    return redirect(
        url_for(
            "dashboard",
            message=message
        )
    )


@app.route("/clear")
def clear():

    try:

        clear_alerts()
        message = "All security alerts cleared."

    except Exception as exc:

        message = f"Unable to clear alerts: {exc}"

    return redirect(
        url_for(
            "dashboard",
            message=message
        )
    )


@app.errorhandler(413)
def request_too_large(_error):

    return redirect(
        url_for(
            "dashboard",
            message=(
                "Uploaded log file is too large. "
                "Maximum size is 5 MB."
            ),
        )
    )


@app.errorhandler(404)
def page_not_found(_error):

    return redirect(
        url_for("dashboard")
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
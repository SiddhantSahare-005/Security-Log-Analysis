from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for
from db import init_db, get_alerts, get_alert_stats, clear_alerts
from detector import analyze_log_source

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / 'logs' / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

@app.route('/')
def dashboard():
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except ValueError:
        page = 1
    alerts, total_pages = get_alerts(page=page, per_page=50)
    return render_template('dashboard.html', alerts=alerts, stats=get_alert_stats(),
                           page=page, total_pages=total_pages,
                           input_message=request.args.get('message', ''))

@app.route('/upload', methods=['POST'])
def upload_logs():
    uploaded = request.files.get('log_file')
    pasted = request.form.get('log_text', '').strip()
    if not uploaded and not pasted:
        return redirect(url_for('dashboard', message='No log file or log data was provided.'))
    try:
        if uploaded and uploaded.filename:
            filename = Path(uploaded.filename).name
            if Path(filename).suffix.lower() not in {'.log', '.txt', '.json', '.jsonl'}:
                return redirect(url_for('dashboard', message='Unsupported file type. Use LOG, TXT, JSON, or JSONL.'))
            destination = UPLOAD_DIR / f'uploaded_{filename}'
            uploaded.save(destination)
        else:
            from datetime import datetime
            destination = UPLOAD_DIR / f'pasted_{datetime.now():%Y%m%d_%H%M%S}.log'
            destination.write_text(pasted, encoding='utf-8')
        result = analyze_log_source(destination)
        message = f"Analyzed {result['logs']} log entries and generated {result['alerts']} new security alerts."
    except Exception as exc:
        message = f'Log analysis failed: {exc}'
    return redirect(url_for('dashboard', message=message))

@app.route('/scan')
def scan():
    files = sorted([p for p in UPLOAD_DIR.iterdir() if p.is_file() and p.suffix.lower() in {'.log','.txt','.json','.jsonl'}],
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return redirect(url_for('dashboard', message='Upload or paste logs first, then run the security scan.'))
    try:
        result = analyze_log_source(files[0])
        message = f"Security scan completed. Analyzed {result['logs']} entries and generated {result['alerts']} new alerts."
    except Exception as exc:
        message = f'Security scan failed: {exc}'
    return redirect(url_for('dashboard', message=message))

@app.route('/clear')
def clear():
    clear_alerts()
    return redirect(url_for('dashboard', message='All security alerts cleared.'))

@app.errorhandler(413)
def too_large(_error):
    return redirect(url_for('dashboard', message='Uploaded log file is too large. Maximum size is 5 MB.'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

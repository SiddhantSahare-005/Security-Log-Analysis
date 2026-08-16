import math
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / 'security_logs.db'

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            source_hash TEXT UNIQUE
        )''')
        conn.commit()

def insert_alert(alert):
    with get_connection() as conn:
        cur = conn.execute('''INSERT OR IGNORE INTO alerts
            (timestamp, username, ip_address, attack_type, severity, description, source_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (alert['timestamp'], alert.get('username','Unknown'), alert.get('ip_address','Unknown'),
             alert['attack_type'], alert['severity'], alert['description'], alert['source_hash']))
        conn.commit()
        return cur.rowcount == 1

def get_alert_stats():
    with get_connection() as conn:
        return {
            'total': conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],
            'high': conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0],
            'medium': conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0],
            'low': conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0],
        }

def get_alerts(page=1, per_page=50):
    page = max(page, 1)
    offset = (page - 1) * per_page
    with get_connection() as conn:
        total = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        rows = conn.execute('''SELECT id, timestamp, username, ip_address, attack_type, severity, description
                               FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?''', (per_page, offset)).fetchall()
    return rows, max(1, math.ceil(total / per_page))

def clear_alerts():
    with get_connection() as conn:
        conn.execute('DELETE FROM alerts')
        conn.commit()

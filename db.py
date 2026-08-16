import math
import sqlite3
from pathlib import Path

# Vercel provides /tmp as writable temporary storage.
# Locally, keep the database in the project directory.
if "VERCEL" in __import__("os").environ:
    DB_PATH = Path("/tmp/security_logs.db")
else:
    DB_PATH = Path(__file__).resolve().parent / "security_logs.db"


def get_connection():
    connection = sqlite3.connect(str(DB_PATH))
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_hash TEXT UNIQUE
            )
            """
        )
        conn.commit()


def insert_alert(alert):
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO alerts
            (
                timestamp,
                username,
                ip_address,
                attack_type,
                severity,
                description,
                source_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["timestamp"],
                alert.get("username", "Unknown"),
                alert.get("ip_address", "Unknown"),
                alert["attack_type"],
                alert["severity"],
                alert["description"],
                alert["source_hash"],
            ),
        )

        conn.commit()
        return cursor.rowcount == 1


def get_alert_stats():
    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        high = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'"
        ).fetchone()[0]

        medium = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'MEDIUM'"
        ).fetchone()[0]

        low = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'LOW'"
        ).fetchone()[0]

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
    }


def get_alerts(page=1, per_page=50):
    page = max(page, 1)
    offset = (page - 1) * per_page

    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        rows = conn.execute(
            """
            SELECT
                id,
                timestamp,
                username,
                ip_address,
                attack_type,
                severity,
                description
            FROM alerts
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (per_page, offset),
        ).fetchall()

    total_pages = max(1, math.ceil(total / per_page))

    return rows, total_pages


def clear_alerts():
    with get_connection() as conn:
        conn.execute("DELETE FROM alerts")
        conn.commit()

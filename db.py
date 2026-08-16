import os
import math
from pathlib import Path
from contextlib import contextmanager

from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE)

DATABASE_URL = os.getenv("DATABASE_URL")


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """Create a PostgreSQL connection."""

    if not DATABASE_URL:
        raise RuntimeError(
            f"DATABASE_URL was not found.\n"
            f"Expected .env file at:\n{ENV_FILE}\n\n"
            f"Make sure your .env contains:\n"
            f"DATABASE_URL=your_neon_connection_string"
        )

    try:
        return psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row
        )

    except Exception as exc:
        raise RuntimeError(
            f"Could not connect to PostgreSQL: {exc}"
        ) from exc


@contextmanager
def connection():
    """Open a database connection and handle commit/rollback."""

    conn = get_connection()

    try:
        yield conn
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_db():
    """Create the alerts table and required indexes."""

    with connection() as conn:

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,

                timestamp TIMESTAMP NOT NULL,

                username VARCHAR(255),

                ip_address VARCHAR(100),

                attack_type VARCHAR(255) NOT NULL,

                severity VARCHAR(20) NOT NULL,

                description TEXT NOT NULL,

                source_hash VARCHAR(255) UNIQUE
            )
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp DESC)
            """
        )

        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity)
            """
        )


# ============================================================
# INSERT ALERT
# ============================================================

def insert_alert(alert):
    """Insert a security alert and prevent duplicates."""

    with connection() as conn:

        cursor = conn.execute(
            """
            INSERT INTO alerts
            (
                timestamp,
                username,
                ip_address,
                attack_type,
                severity,
                description,
                source_hash
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )

            ON CONFLICT (source_hash)
            DO NOTHING

            RETURNING id
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

        row = cursor.fetchone()

        return row is not None


# ============================================================
# GET ALERT STATISTICS
# ============================================================

def get_alert_stats():
    """Return total, high, medium and low alert counts."""

    with connection() as conn:

        total = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            """
        ).fetchone()["count"]

        high = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            WHERE severity = 'HIGH'
            """
        ).fetchone()["count"]

        medium = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            WHERE severity = 'MEDIUM'
            """
        ).fetchone()["count"]

        low = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            WHERE severity = 'LOW'
            """
        ).fetchone()["count"]

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
    }


# ============================================================
# GET ALERTS WITH PAGINATION
# ============================================================

def get_alerts(page=1, per_page=50):
    """
    Retrieve alerts with pagination.

    Default:
    50 alerts per page.
    """

    page = max(int(page), 1)

    offset = (page - 1) * per_page

    with connection() as conn:

        total = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM alerts
            """
        ).fetchone()["count"]

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

            ORDER BY
                timestamp DESC,
                id DESC

            LIMIT %s
            OFFSET %s
            """,
            (
                per_page,
                offset,
            ),
        ).fetchall()

    total_pages = max(
        1,
        math.ceil(total / per_page)
    )

    return rows, total_pages


# ============================================================
# CLEAR ALERTS
# ============================================================

def clear_alerts():
    """Delete all stored security alerts."""

    with connection() as conn:

        conn.execute(
            """
            DELETE FROM alerts
            """
        )


# ============================================================
# CONNECTION TEST
# ============================================================

def test_connection():
    """Test the PostgreSQL connection."""

    with connection() as conn:

        result = conn.execute(
            "SELECT NOW() AS current_time"
        ).fetchone()

    return result["current_time"]


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print("Checking PostgreSQL configuration...")

    print(
        f"Project directory: {BASE_DIR}"
    )

    print(
        f".env exists: {ENV_FILE.exists()}"
    )

    print(
        f"DATABASE_URL found: {bool(DATABASE_URL)}"
    )

    if not DATABASE_URL:

        print()
        print("ERROR: DATABASE_URL is missing.")
        print()
        print(
            "Create a .env file containing:"
        )
        print()
        print(
            "DATABASE_URL=your_neon_connection_string"
        )

        raise SystemExit(1)

    try:

        init_db()

        current_time = test_connection()

        print()
        print("PostgreSQL connection successful!")
        print(
            f"Database server time: {current_time}"
        )
        print("Alerts table is ready.")

    except Exception as exc:

        print()
        print("PostgreSQL connection failed:")
        print(exc)

        raise SystemExit(1)

import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "instance" / "vigilis.sqlite3"


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            score_total INTEGER NOT NULL,
            score_rating TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(result: dict) -> int:
    conn = _connect()
    cursor = conn.execute(
        """
        INSERT INTO scans (hostname, scanned_at, score_total, score_rating, result_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            result["hostname"],
            result["scanned_at"],
            result["score"]["total"],
            result["score"]["rating"],
            json.dumps(result),
        ),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_scan(scan_id: int) -> dict | None:
    conn = _connect()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    result = json.loads(row["result_json"])
    result["id"] = row["id"]
    return result


def list_scans(limit: int = 50) -> list:
    conn = _connect()
    rows = conn.execute(
        "SELECT id, hostname, scanned_at, score_total, score_rating FROM scans "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def list_scans_for_host(hostname: str, limit: int = 20) -> list:
    conn = _connect()
    rows = conn.execute(
        "SELECT id, hostname, scanned_at, score_total, score_rating FROM scans "
        "WHERE hostname = ? ORDER BY id DESC LIMIT ?",
        (hostname, limit),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]

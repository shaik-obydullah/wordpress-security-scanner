"""SQLite schema + data models for scan storage."""

import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

DB_DIR = Path(os.getenv("WPSCANNER_DB_DIR", "."))
DB_PATH = DB_DIR / "wpscanner.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    duration REAL,
    score INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def init_db() -> None:
    """Create tables if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA)


def get_connection() -> sqlite3.Connection:
    init_db()
    return sqlite3.connect(DB_PATH)


def save_scan(target: str, profile: str, timestamp: str, duration: float, score: int, findings: List[Dict]) -> int:
    """Persist a scan and its findings; returns the new scan id."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, profile, timestamp, duration, score) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, profile, timestamp, duration, score),
        )
        scan_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings "
            "(scan_id, category, severity, title, description, evidence, remediation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    f["category"],
                    f["severity"],
                    f["title"],
                    f.get("description", ""),
                    f.get("evidence", ""),
                    f.get("remediation", ""),
                )
                for f in findings
            ],
        )
        return scan_id


def get_scans(limit: int = 100) -> List[Dict]:
    """Return the most recent scans (id, target, timestamp, score, findings count)."""
    init_db()
    rows = []
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT s.id, s.target, s.timestamp, s.score, "
            "(SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS n "
            "FROM scans s ORDER BY s.id DESC LIMIT ?",
            (limit,),
        )
        for rid, target, timestamp, score, n in cur.fetchall():
            rows.append(
                {
                    "id": rid,
                    "target": target,
                    "timestamp": timestamp,
                    "score": score,
                    "finding_count": n,
                }
            )
    return rows


def get_findings(scan_id: int) -> List[Dict]:
    """Return all findings for a scan id."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT category, severity, title, description, evidence, remediation "
            "FROM findings WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        )
        return [
            {
                "category": cat,
                "severity": sev,
                "title": title,
                "description": desc,
                "evidence": ev,
                "remediation": rem,
            }
            for cat, sev, title, desc, ev, rem in cur.fetchall()
        ]


def get_setting(key: str, default: str = "") -> str:
    """Read a setting value."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default


def set_setting(key: str, value: str) -> None:
    """Write a setting value."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
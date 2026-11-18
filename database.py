"""
SQLite storage for OSINT scans.

Two tables:
  targets — one row per domain ever scanned
  scans   — one row per scan, with the full result as JSON plus a few
            extracted counts so the dashboard can chart trends over time
            without re-parsing the JSON on every request.
"""

import os
import json
import sqlite3
import datetime

DB_PATH = os.environ.get("OSINT_DB", os.path.join(os.path.dirname(__file__), "osint.db"))


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain     TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id    INTEGER NOT NULL,
                scanned_at   TEXT NOT NULL,
                results_json TEXT NOT NULL,
                subdomains   INTEGER DEFAULT 0,
                open_ports   INTEGER DEFAULT 0,
                emails       INTEGER DEFAULT 0,
                dns_records  INTEGER DEFAULT 0,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            );
            """
        )


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_or_create_target(domain):
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO targets (domain, created_at) VALUES (?, ?)",
            (domain, _now()),
        )
        return cur.lastrowid


def save_scan(scan):
    """Persist a scan dict (from collectors.run_scan) and return its scan id."""
    target_id = get_or_create_target(scan["domain"])
    s = scan.get("summary", {})
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (target_id, scanned_at, results_json, subdomains, open_ports, emails, dns_records)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                target_id,
                scan.get("scanned_at", _now()),
                json.dumps(scan),
                s.get("subdomains", 0),
                s.get("open_ports", 0),
                s.get("emails", 0),
                s.get("dns_records", 0),
            ),
        )
        return cur.lastrowid


def list_targets():
    """Return every target with its latest scan's counts, for the dashboard."""
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT t.id, t.domain, t.created_at,
                   COUNT(s.id) AS scan_count,
                   MAX(s.scanned_at) AS last_scan,
                   (SELECT subdomains FROM scans WHERE target_id = t.id
                      ORDER BY id DESC LIMIT 1) AS subdomains,
                   (SELECT open_ports FROM scans WHERE target_id = t.id
                      ORDER BY id DESC LIMIT 1) AS open_ports,
                   (SELECT emails FROM scans WHERE target_id = t.id
                      ORDER BY id DESC LIMIT 1) AS emails
            FROM targets t
            LEFT JOIN scans s ON s.target_id = t.id
            GROUP BY t.id
            ORDER BY last_scan DESC
            """
        ).fetchall()


def get_target(target_id):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()


def get_scans_for_target(target_id):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE target_id = ? ORDER BY id ASC", (target_id,)
        ).fetchall()


def get_latest_scan(target_id):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT 1",
            (target_id,),
        ).fetchone()
    return row


def scan_results(row):
    """Decode the stored JSON for a scan row."""
    return json.loads(row["results_json"])

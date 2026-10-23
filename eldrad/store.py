"""SQLite storage for capture sessions and probe records, with CSV export."""
from __future__ import annotations

import csv
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .frames import Probe
from .privacy import MacAnonymizer

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id      TEXT PRIMARY KEY,
    label   TEXT,
    started REAL,
    lat     REAL,
    lon     REAL,
    source  TEXT            -- 'live:<iface>' or 'pcap:<file name>'
);
CREATE TABLE IF NOT EXISTS probes (
    id         INTEGER PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id),
    ts         REAL,
    device     TEXT,         -- salted per-session MAC token
    mac_raw    TEXT,         -- NULL unless --store-raw-mac
    oui        TEXT,         -- vendor prefix, globally administered MACs only
    randomized INTEGER,
    ssid       TEXT,         -- '' = broadcast probe
    rssi       INTEGER,
    channel    INTEGER,
    lat        REAL,
    lon        REAL
);
CREATE INDEX IF NOT EXISTS probes_session ON probes(session_id);
"""

CSV_FIELDS = ["session_id", "label", "time_utc", "device", "mac_raw", "oui", "randomized",
              "ssid", "rssi", "channel", "lat", "lon"]


class ProbeStore:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def start_session(self, label: str, lat: float | None, lon: float | None, source: str) -> str:
        session_id = uuid.uuid4().hex[:12]
        self.conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
                          (session_id, label, time.time(), lat, lon, source))
        self.conn.commit()
        return session_id

    def add(self, session_id: str, probe: Probe, anon: MacAnonymizer,
            lat: float | None, lon: float | None) -> None:
        self.conn.execute(
            "INSERT INTO probes (session_id, ts, device, mac_raw, oui, randomized, ssid, rssi,"
            " channel, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, probe.ts, anon.token(probe.mac), anon.raw(probe.mac), anon.oui(probe.mac),
             int(probe.randomized), probe.ssid, probe.rssi, probe.channel, lat, lon))

    def commit(self) -> None:
        self.conn.commit()

    def rows(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT p.*, s.label FROM probes p JOIN sessions s ON s.id = p.session_id ORDER BY p.ts")
        return [dict(r) for r in cur]

    def export_csv(self, path: str | Path) -> int:
        rows = self.rows()
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                r["time_utc"] = datetime.fromtimestamp(r["ts"], timezone.utc).isoformat(timespec="seconds")
                writer.writerow(r)
        return len(rows)

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

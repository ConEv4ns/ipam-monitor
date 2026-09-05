import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).parent / "ipam.db"
TRUST_STATUSES = {"trusted", "unknown", "untrusted"}

DEFAULT_SETTINGS = {
    "network_range": "192.168.1.0/24",
    "scan_timeout": "3"
}


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def current_time():
    return datetime.now(timezone.utc).isoformat()


def initialise_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT NOT NULL,
                name TEXT,
                device_type TEXT,
                notes TEXT,
                trust_status TEXT NOT NULL DEFAULT 'unknown',
                online INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                devices_found INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running'
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            )
        """)

        # Add defaults without replacing saved settings
        for setting_key, setting_value in DEFAULT_SETTINGS.items():
            connection.execute("""
                INSERT OR IGNORE INTO settings (
                    setting_key,
                    setting_value
                )
                VALUES (?, ?)
            """, (
                setting_key,
                setting_value
            ))


def save_scan(devices):
    timestamp = current_time()

    with get_connection() as connection:
        # Reset status before processing replies
        connection.execute("UPDATE devices SET online = 0")

        for device in devices:
            connection.execute("""
                INSERT INTO devices (
                    ip_address,
                    mac_address,
                    online,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    mac_address = excluded.mac_address,
                    online = 1,
                    last_seen = excluded.last_seen
            """, (
                device["ip"],
                device["mac"],
                timestamp,
                timestamp
            ))

        # Store the completed scan
        connection.execute("""
            INSERT INTO scans (
                started_at,
                completed_at,
                devices_found,
                status
            )
            VALUES (?, ?, ?, 'completed')
        """, (
            timestamp,
            timestamp,
            len(devices)
        ))


def save_failed_scan(started_at):
    completed_at = current_time()

    with get_connection() as connection:
        connection.execute("""
            INSERT INTO scans (
                started_at,
                completed_at,
                devices_found,
                status
            )
            VALUES (?, ?, 0, 'failed')
        """, (
            started_at,
            completed_at
        ))


def get_devices():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                ip_address,
                mac_address,
                name,
                device_type,
                notes,
                trust_status,
                online,
                first_seen,
                last_seen
            FROM devices
            ORDER BY ip_address
        """).fetchall()

    return [dict(row) for row in rows]


def get_device(device_id):
    with get_connection() as connection:
        row = connection.execute("""
            SELECT
                id,
                ip_address,
                mac_address,
                name,
                device_type,
                notes,
                trust_status,
                online,
                first_seen,
                last_seen
            FROM devices
            WHERE id = ?
        """, (device_id,)).fetchone()

    return dict(row) if row else None


def update_device(device_id, name, device_type, notes, trust_status):
    name = name.strip()
    device_type = device_type.strip()
    notes = notes.strip()
    trust_status = trust_status.strip().lower()

    # Validate editable fields
    if len(name) > 80:
        raise ValueError(
            "Device name must be 80 characters or fewer."
        )

    if len(device_type) > 50:
        raise ValueError(
            "Device type must be 50 characters or fewer."
        )

    if len(notes) > 500:
        raise ValueError(
            "Notes must be 500 characters or fewer."
        )

    if trust_status not in TRUST_STATUSES:
        raise ValueError("Invalid trust status.")

    with get_connection() as connection:
        cursor = connection.execute("""
            UPDATE devices
            SET
                name = ?,
                device_type = ?,
                notes = ?,
                trust_status = ?
            WHERE id = ?
        """, (
            name or None,
            device_type or None,
            notes or None,
            trust_status,
            device_id
        ))

    return cursor.rowcount == 1


def get_scan_history(limit=50):
    # Keep history requests within a safe range
    limit = max(1, min(limit, 200))

    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                started_at,
                completed_at,
                devices_found,
                status
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_settings():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                setting_key,
                setting_value
            FROM settings
        """).fetchall()

    settings = {
        row["setting_key"]: row["setting_value"]
        for row in rows
    }

    return {
        "network_range": settings.get(
            "network_range",
            DEFAULT_SETTINGS["network_range"]
        ),
        "scan_timeout": int(
            settings.get(
                "scan_timeout",
                DEFAULT_SETTINGS["scan_timeout"]
            )
        )
    }


def update_settings(network_range, scan_timeout):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO settings (
                setting_key,
                setting_value
            )
            VALUES ('network_range', ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value
        """, (network_range,))

        connection.execute("""
            INSERT INTO settings (
                setting_key,
                setting_value
            )
            VALUES ('scan_timeout', ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value
        """, (str(scan_timeout),))

    return get_settings()


if __name__ == "__main__":
    initialise_database()
    print(f"Database ready at {DATABASE_PATH}")
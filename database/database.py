from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator


DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "storage" / "cryptoshield.db"
PBKDF2_ITERATIONS = 600_000
DEFAULT_ACCOUNTS = {
    "alice": "AliceSecret123!",
    "bob": "BobSecret456!",
    "eve": "EveAttacker789!",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_user(user_id: str) -> str:
    normalized = user_id.strip().lower()
    if not normalized or len(normalized) > 40 or not normalized.replace("_", "").replace("-", "").isalnum():
        raise ValueError("Identity must contain 1-40 letters, numbers, underscores, or hyphens.")
    return normalized


class AuditDatabase:
    def __init__(self, db_path: str | os.PathLike[str] = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            user_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
            }
            if user_columns and not {"user_id", "password_salt", "password_hash"}.issubset(user_columns):
                conn.execute("ALTER TABLE users RENAME TO users_legacy")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS packets (
                    message_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    packet_timestamp TEXT NOT NULL,
                    packet_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_packets_recipient ON packets(recipient_id, stored_at DESC);
                CREATE INDEX IF NOT EXISTS idx_packets_sender ON packets(sender_id, stored_at DESC);
                CREATE TABLE IF NOT EXISTS seen_messages (
                    message_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    packet_timestamp TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tofu_pins (
                    user_id TEXT NOT NULL,
                    contact_id TEXT NOT NULL,
                    pinned_sign_fp TEXT NOT NULL,
                    pinned_enc_fp TEXT NOT NULL,
                    pinned_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    PRIMARY KEY (user_id, contact_id)
                );
                CREATE TABLE IF NOT EXISTS key_records (
                    fingerprint TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revoked_at TEXT,
                    revocation_reason TEXT,
                    public_key_pem TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_key_records_owner ON key_records(user_id, key_type, status);
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_failures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    attempted_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auth_failures_user ON auth_failures(user_id, attempted_at);
                CREATE TABLE IF NOT EXISTS one_time_prekeys (
                    prekey_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    encrypted_private_key BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE'
                );
                """
            )
            for username, password in DEFAULT_ACCOUNTS.items():
                exists = conn.execute(
                    "SELECT 1 FROM users WHERE user_id = ?", (username,)
                ).fetchone()
                if exists is None:
                    salt = secrets.token_bytes(16)
                    password_hash = hashlib.pbkdf2_hmac(
                        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
                    )
                    conn.execute(
                        "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                        (username, salt, password_hash, PBKDF2_ITERATIONS, utc_now()),
                    )

    def register_user(self, user_id: str, password: str) -> None:
        user_id = normalize_user(user_id)
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters.")
        salt = secrets.token_bytes(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        try:
            with self.connect() as conn:
                conn.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                    (user_id, salt, password_hash, PBKDF2_ITERATIONS, utc_now()),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That identity already exists.") from exc

    def user_exists(self, user_id: str) -> bool:
        with self.connect() as conn:
            return conn.execute(
                "SELECT 1 FROM users WHERE user_id = ?", (normalize_user(user_id),)
            ).fetchone() is not None

    def user_ids(self) -> list[str]:
        with self.connect() as conn:
            return [row["user_id"] for row in conn.execute("SELECT user_id FROM users ORDER BY user_id")]

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT user_id, iterations, created_at FROM users WHERE user_id = ?",
                (normalize_user(user_id),),
            ).fetchone()
            return dict(row) if row else None

    def authenticate(self, user_id: str, password: str) -> bool:
        user_id = normalize_user(user_id)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT password_salt, password_hash, iterations FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b"\0" * 16, PBKDF2_ITERATIONS)
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), row["password_salt"], row["iterations"]
        )
        return hmac.compare_digest(candidate, row["password_hash"])

    def record_auth_failure(self, user_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO auth_failures(user_id, attempted_at) VALUES (?, ?)",
                (normalize_user(user_id), utc_now()),
            )

    def clear_auth_failures(self, user_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM auth_failures WHERE user_id = ?", (normalize_user(user_id),))

    def auth_failure_count(self, user_id: str, since: str) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM auth_failures WHERE user_id = ? AND attempted_at >= ?",
                (normalize_user(user_id), since),
            ).fetchone()
            return int(row["n"])

    def recent_auth_failures(self, user_id: str, since: str) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT attempted_at FROM auth_failures
                   WHERE user_id=? AND attempted_at>=? ORDER BY attempted_at DESC""",
                (normalize_user(user_id), since),
            ).fetchall()
        return [row["attempted_at"] for row in rows]

    def save_packet(self, packet: dict[str, Any]) -> None:
        import json

        with self.connect() as conn:
            conn.execute(
                """INSERT INTO packets(message_id, sender_id, recipient_id, packet_timestamp, packet_json, stored_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    packet["message_id"],
                    normalize_user(packet["sender_id"]),
                    normalize_user(packet["recipient_id"]),
                    packet["timestamp"],
                    json.dumps(packet, separators=(",", ":"), sort_keys=True),
                    utc_now(),
                ),
            )

    def list_packets(self, user_id: str, direction: str = "inbox") -> list[dict[str, Any]]:
        import json

        user_id = normalize_user(user_id)
        column = "recipient_id" if direction == "inbox" else "sender_id"
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT packet_json FROM packets WHERE {column} = ? ORDER BY stored_at DESC",
                (user_id,),
            ).fetchall()
        return [json.loads(row["packet_json"]) for row in rows]

    def get_packet(self, message_id: str) -> dict[str, Any] | None:
        import json

        with self.connect() as conn:
            row = conn.execute(
                "SELECT packet_json FROM packets WHERE message_id = ?", (message_id,)
            ).fetchone()
        return json.loads(row["packet_json"]) if row else None

    def mark_message_seen(
        self, message_id: str, sender_id: str, recipient_id: str, packet_timestamp: str
    ) -> bool:
        try:
            with self.connect() as conn:
                conn.execute(
                    "INSERT INTO seen_messages VALUES (?, ?, ?, ?, ?)",
                    (
                        message_id,
                        normalize_user(sender_id),
                        normalize_user(recipient_id),
                        packet_timestamp,
                        utc_now(),
                    ),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def message_seen(self, message_id: str) -> bool:
        with self.connect() as conn:
            return conn.execute(
                "SELECT 1 FROM seen_messages WHERE message_id = ?", (message_id,)
            ).fetchone() is not None

    def pin_contact(self, user_id: str, contact_id: str, sign_fp: str, enc_fp: str) -> tuple[bool, str]:
        user_id, contact_id = normalize_user(user_id), normalize_user(contact_id)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT pinned_sign_fp, pinned_enc_fp, status FROM tofu_pins WHERE user_id = ? AND contact_id = ?",
                (user_id, contact_id),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO tofu_pins VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
                    (user_id, contact_id, sign_fp, enc_fp, utc_now()),
                )
                return True, "First contact: fingerprints pinned."
            if row["status"] != "ACTIVE":
                return False, "Contact pin is disabled; manual verification is required."
            if not hmac.compare_digest(row["pinned_sign_fp"], sign_fp) or not hmac.compare_digest(
                row["pinned_enc_fp"], enc_fp
            ):
                return False, "TOFU fingerprint mismatch: possible key substitution blocked."
            return True, "Pinned fingerprints match."

    def update_tofu_pin(self, user_id: str, contact_id: str, sign_fp: str, enc_fp: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO tofu_pins(user_id,contact_id,pinned_sign_fp,pinned_enc_fp,pinned_at,status)
                   VALUES (?, ?, ?, ?, ?, 'ACTIVE')
                   ON CONFLICT(user_id,contact_id) DO UPDATE SET
                     pinned_sign_fp=excluded.pinned_sign_fp,
                     pinned_enc_fp=excluded.pinned_enc_fp,
                     pinned_at=excluded.pinned_at,
                     status='ACTIVE'""",
                (normalize_user(user_id), normalize_user(contact_id), sign_fp, enc_fp, utc_now()),
            )

    def add_key_record(
        self, fingerprint: str, user_id: str, key_type: str, algorithm: str, public_key_pem: str
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO key_records
                   (fingerprint, user_id, key_type, algorithm, created_at, status, revoked_at, revocation_reason, public_key_pem)
                   VALUES (?, ?, ?, ?, ?, 'ACTIVE', NULL, NULL, ?)""",
                (fingerprint, normalize_user(user_id), key_type, algorithm, utc_now(), public_key_pem),
            )

    def list_key_records(self, user_id: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if user_id is None:
                rows = conn.execute("SELECT * FROM key_records ORDER BY created_at DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM key_records WHERE user_id = ? ORDER BY created_at DESC",
                    (normalize_user(user_id),),
                ).fetchall()
        return [dict(row) for row in rows]

    def get_key_record(self, fingerprint: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM key_records WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        return dict(row) if row else None

    def revoke_key(self, fingerprint: str, reason: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute(
                """UPDATE key_records SET status='REVOKED', revoked_at=?, revocation_reason=?
                   WHERE fingerprint=? AND status='ACTIVE'""",
                (utc_now(), reason[:500], fingerprint),
            )
            return cursor.rowcount == 1

    def add_prekey(
        self, prekey_id: str, user_id: str, public_key_pem: str, encrypted_private_key: bytes
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO one_time_prekeys VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
                (prekey_id, normalize_user(user_id), public_key_pem, encrypted_private_key, utc_now()),
            )

    def consume_prekey(self, prekey_id: str, user_id: str) -> bytes | None:
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """SELECT encrypted_private_key FROM one_time_prekeys
                   WHERE prekey_id=? AND user_id=? AND status IN ('ACTIVE','RESERVED')""",
                (prekey_id, normalize_user(user_id)),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE one_time_prekeys SET status='CONSUMED', encrypted_private_key=? WHERE prekey_id=?",
                (b"", prekey_id),
            )
            return bytes(row["encrypted_private_key"])

    def get_active_prekeys(self, user_id: str) -> list[dict[str, str]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT prekey_id, public_key_pem FROM one_time_prekeys
                   WHERE user_id=? AND status='ACTIVE' ORDER BY created_at""",
                (normalize_user(user_id),),
            ).fetchall()
        return [dict(row) for row in rows]

    def claim_prekey(self, prekey_id: str, user_id: str) -> bool:
            with self.connect() as conn:
                cursor = conn.execute(
                    """UPDATE one_time_prekeys SET status='RESERVED'
                       WHERE prekey_id=? AND user_id=? AND status='ACTIVE'""",
                    (prekey_id, normalize_user(user_id)),
                )
                return cursor.rowcount == 1

    def release_prekey(self, prekey_id: str, user_id: str) -> bool:
            with self.connect() as conn:
                cursor = conn.execute(
                    """UPDATE one_time_prekeys SET status='ACTIVE'
                       WHERE prekey_id=? AND user_id=? AND status='RESERVED'""",
                    (prekey_id, normalize_user(user_id)),
                )
                return cursor.rowcount == 1

    def log_event(
        self, event_type: str, severity: str, user_id: str, details: str
    ) -> int:
        timestamp = utc_now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute(
                "SELECT current_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = previous["current_hash"] if previous else "0" * 64
            canonical = "|".join(
                (prev_hash, timestamp, event_type, severity.upper(), normalize_user(user_id), details)
            )
            current_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            cursor = conn.execute(
                """INSERT INTO audit_chain(timestamp,event_type,severity,user_id,details,prev_hash,current_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, event_type, severity.upper(), normalize_user(user_id), details, prev_hash, current_hash),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("Audit event was not assigned a database row ID.")
            return cursor.lastrowid

    def verify_chain(self) -> tuple[bool, int | None, int, list[dict[str, Any]]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_chain ORDER BY id").fetchall()
        records = [dict(row) for row in rows]
        previous = "0" * 64
        for record in records:
            canonical = "|".join(
                (
                    previous,
                    record["timestamp"],
                    record["event_type"],
                    record["severity"],
                    record["user_id"],
                    record["details"],
                )
            )
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if record["prev_hash"] != previous or not hmac.compare_digest(
                record["current_hash"], expected
            ):
                return False, int(record["id"]), len(records), records
            previous = record["current_hash"]
        return True, None, len(records), records

    def get_recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id,timestamp,event_type,severity,user_id,details FROM audit_chain ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            packets = int(conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0])
            users = int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
            alerts = int(
                conn.execute("SELECT COUNT(*) FROM audit_chain WHERE severity IN ('HIGH','CRITICAL')").fetchone()[0]
            )
        return {
            "total_messages": packets,
            "alerts": alerts,
            "active_users": users,
            "events": self.get_recent_events(8),
        }

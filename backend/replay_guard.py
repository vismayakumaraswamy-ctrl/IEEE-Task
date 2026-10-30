from __future__ import annotations

from datetime import datetime, timedelta, timezone

from database.database import AuditDatabase


class ReplayAttackException(ValueError):
    pass


class ReplayGuard:
    def __init__(
        self, database: AuditDatabase, window_seconds: int = 120, clock_drift_seconds: int = 15
    ) -> None:
        if window_seconds < 1 or clock_drift_seconds < 0:
            raise ValueError("Replay window must be positive and clock drift cannot be negative.")
        self.database = database
        self.window_seconds = window_seconds
        self.clock_drift_seconds = clock_drift_seconds

    def validate(self, packet: dict[str, object]) -> None:
        try:
            packet_time = datetime.fromisoformat(str(packet["timestamp"]).replace("Z", "+00:00"))
            if packet_time.tzinfo is None:
                raise ValueError("Timestamp must include a timezone.")
            message_id = str(packet["message_id"])
            sender_id = str(packet["sender_id"])
            recipient_id = str(packet["recipient_id"])
            if not message_id:
                raise ValueError("Message ID is missing.")
        except (KeyError, TypeError, ValueError) as exc:
            raise ReplayAttackException(f"Invalid packet timestamp or identity: {exc}") from exc

        now = datetime.now(timezone.utc)
        if packet_time < now - timedelta(seconds=self.window_seconds):
            raise ReplayAttackException("Packet is older than the accepted replay window.")
        if packet_time > now + timedelta(seconds=self.clock_drift_seconds):
            raise ReplayAttackException("Packet timestamp exceeds allowed clock-drift tolerance.")
        if self.database.message_seen(message_id):
            raise ReplayAttackException("Duplicate message ID: replay rejected.")
        if not sender_id.strip() or not recipient_id.strip():
            raise ReplayAttackException("Packet sender or recipient is missing.")

    def accept(self, packet: dict[str, object]) -> None:
        self.validate(packet)
        inserted = self.database.mark_message_seen(
            str(packet["message_id"]),
            str(packet["sender_id"]),
            str(packet["recipient_id"]),
            str(packet["timestamp"]),
        )
        if not inserted:
            raise ReplayAttackException("Duplicate message ID: replay rejected.")

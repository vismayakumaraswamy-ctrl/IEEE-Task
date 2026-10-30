from __future__ import annotations

from typing import Any

from database.database import AuditDatabase


class AuditChain:
    def __init__(self, database: AuditDatabase) -> None:
        self.database = database

    def log(self, event_type: str, severity: str, user_id: str, details: str) -> int:
        return self.database.log_event(event_type, severity, user_id, details)

    def verify_chain(self) -> tuple[bool, int | None, int, list[dict[str, Any]]]:
        return self.database.verify_chain()

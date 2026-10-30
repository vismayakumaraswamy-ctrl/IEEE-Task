from __future__ import annotations

from datetime import datetime, timedelta, timezone

from database.database import AuditDatabase


class BruteForceGuard:
    def __init__(
        self,
        database: AuditDatabase,
        max_failures: int = 5,
        observation_seconds: int = 300,
        cooldown_seconds: int = 180,
    ) -> None:
        self.database = database
        self.max_failures = max_failures
        self.observation_seconds = observation_seconds
        self.cooldown_seconds = cooldown_seconds

    def remaining_lock_seconds(self, user_id: str) -> int:
        since = (datetime.now(timezone.utc) - timedelta(seconds=self.observation_seconds)).isoformat()
        failures = self.database.recent_auth_failures(user_id, since)
        if len(failures) < self.max_failures:
            return 0
        last_attempt = datetime.fromisoformat(failures[0])
        expires = last_attempt + timedelta(seconds=self.cooldown_seconds)
        return max(0, int((expires - datetime.now(timezone.utc)).total_seconds()))

    def authenticate(self, user_id: str, password: str) -> bool:
        remaining = self.remaining_lock_seconds(user_id)
        if remaining:
            raise PermissionError(f"Account temporarily locked. Try again in {remaining} seconds.")
        if self.database.authenticate(user_id, password):
            self.database.clear_auth_failures(user_id)
            self.database.log_event("LOGIN_SUCCESS", "INFO", user_id, "Identity authenticated.")
            return True
        self.database.record_auth_failure(user_id)
        since = (datetime.now(timezone.utc) - timedelta(seconds=self.observation_seconds)).isoformat()
        failure_count = self.database.auth_failure_count(user_id, since)
        self.database.log_event(
            "LOGIN_FAILURE",
            "HIGH" if failure_count >= self.max_failures else "MEDIUM",
            user_id,
            f"Rejected login attempt ({failure_count} failures in the observation window).",
        )
        if failure_count >= self.max_failures:
            self.database.log_event(
                "ACCOUNT_LOCKOUT",
                "HIGH",
                user_id,
                f"Account locked for {self.cooldown_seconds} seconds after repeated failures.",
            )
        return False

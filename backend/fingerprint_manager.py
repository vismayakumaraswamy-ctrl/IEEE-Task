from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import serialization

from database.database import AuditDatabase


def compute_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def verify_key_fingerprint(public_key, expected: str) -> bool:
    normalized_expected = expected.replace(":", "").replace(" ", "").upper()
    actual = compute_key_fingerprint(public_key).replace(":", "")
    return hmac.compare_digest(actual, normalized_expected)


class TofuPinningManager:
    def __init__(self, database: AuditDatabase) -> None:
        self.database = database

    def verify_or_pin(self, user_id: str, contact_id: str, signing_key, encryption_key) -> tuple[bool, str]:
        return self.database.pin_contact(
            user_id,
            contact_id,
            compute_key_fingerprint(signing_key),
            compute_key_fingerprint(encryption_key),
        )

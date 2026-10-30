from __future__ import annotations

import shutil
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.fingerprint_manager import compute_key_fingerprint
from backend.key_management import KeyVault
from database.database import AuditDatabase


class KeyRotationManager:
    def __init__(self, vault: KeyVault, database: AuditDatabase) -> None:
        self.vault = vault
        self.database = database

    def rotate(self, user_id: str, key_type: str, password: str) -> str:
        key_type = key_type.lower()
        if key_type not in {"enc", "sign"}:
            raise ValueError("Only RSA encryption or signing keys can be rotated.")
        private_path = self.vault.key_dir / f"{user_id.lower()}_{key_type}_priv.pem"
        public_path = self.vault.key_dir / f"{user_id.lower()}_{key_type}_pub.pem"
        if not private_path.is_file() or not public_path.is_file():
            raise FileNotFoundError("The active key pair is not present in the vault.")

        self.vault.load_private_key(user_id, key_type, password)
        old_public = self.vault.load_public_key(user_id, key_type)
        old_fingerprint = compute_key_fingerprint(old_public)
        archive_dir = self.vault.key_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        archived_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = old_fingerprint.replace(":", "")[:16]
        shutil.copy2(private_path, archive_dir / f"{user_id}_{key_type}_{suffix}_{archived_at}_priv.pem")
        shutil.copy2(public_path, archive_dir / f"{user_id}_{key_type}_{suffix}_{archived_at}_pub.pem")

        replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.vault._write_private_key(private_path, replacement, password)
        self.vault._write_public_key(public_path, replacement.public_key())
        old_record = self.database.get_key_record(old_fingerprint)
        if old_record is not None:
            self.database.revoke_key(old_fingerprint, "Replaced during key rotation.")
        new_fingerprint = compute_key_fingerprint(replacement.public_key())
        algorithm = "RSA-2048-OAEP-SHA256" if key_type == "enc" else "RSA-2048-PSS-SHA256"
        public_pem = replacement.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        self.database.add_key_record(new_fingerprint, user_id, key_type, algorithm, public_pem)
        self.database.log_event(
            "KEY_ROTATED", "MEDIUM", user_id, f"{key_type} key rotated; previous fingerprint revoked."
        )
        return new_fingerprint

    def revoke(self, fingerprint: str, reason: str) -> bool:
        changed = self.database.revoke_key(fingerprint, reason)
        if changed:
            record = self.database.get_key_record(fingerprint)
            if record is None:
                raise RuntimeError("Revoked key record disappeared before the audit event was written.")
            self.database.log_event(
                "KEY_REVOKED", "HIGH", record["user_id"], reason
            )
        return changed

    def signature_key_is_active(self, fingerprint: str) -> bool:
        record = self.database.get_key_record(fingerprint)
        return bool(record and record["status"] == "ACTIVE" and record["key_type"] == "sign")

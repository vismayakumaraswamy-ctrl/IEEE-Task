from __future__ import annotations

import hashlib
import os
import uuid
from typing import TypedDict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.hybrid_encryption import canonical_aad
from backend.key_management import KeyVault
from database.database import AuditDatabase


class ForwardSecretResult(TypedDict):
    nonce: bytes
    ciphertext: bytes
    ephemeral_public_key: bytes
    prekey_id: str
    session_key: bytes


def _derive_session_key(shared_secret: bytes, message_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(message_id.encode("utf-8")).digest(),
        info=b"CRYPTOSHIELD-X25519-PREKEY-V1",
    ).derive(shared_secret)


def create_one_time_prekeys(
    database: AuditDatabase, vault: KeyVault, user_id: str, password: str, count: int = 5
) -> int:
    if not 1 <= count <= 20:
        raise ValueError("Prekey count must be between 1 and 20.")
    created = 0
    for _ in range(count):
        private_key = x25519.X25519PrivateKey.generate()
        prekey_id = str(uuid.uuid4())
        public_pem, encrypted_private = vault.save_prekey(private_key, password)
        database.add_prekey(prekey_id, user_id, public_pem, encrypted_private)
        created += 1
    return created


def encrypt_forward_secret(
    plaintext: bytes,
    recipient_prekey_pem: str,
    sender_id: str,
    recipient_id: str,
    message_id: str,
    timestamp: str,
    prekey_id: str,
) -> ForwardSecretResult:
    recipient_prekey = serialization.load_pem_public_key(recipient_prekey_pem.encode("ascii"))
    if not isinstance(recipient_prekey, x25519.X25519PublicKey):
        raise ValueError("Recipient one-time prekey is not an X25519 public key.")
    ephemeral_private = x25519.X25519PrivateKey.generate()
    session_key = _derive_session_key(ephemeral_private.exchange(recipient_prekey), message_id)
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(
        nonce,
        plaintext,
        canonical_aad(sender_id, recipient_id, message_id, timestamp),
    )
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "ephemeral_public_key": ephemeral_public,
        "prekey_id": prekey_id,
        "session_key": session_key,
    }


def decrypt_forward_secret(
    nonce: bytes,
    ciphertext: bytes,
    ephemeral_public_key: bytes,
    recipient_prekey_private,
    sender_id: str,
    recipient_id: str,
    message_id: str,
    timestamp: str,
) -> bytes:
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_key)
    session_key = _derive_session_key(
        recipient_prekey_private.exchange(ephemeral_public), message_id
    )
    return AESGCM(session_key).decrypt(
        nonce,
        ciphertext,
        canonical_aad(sender_id, recipient_id, message_id, timestamp),
    )


def pqc_status() -> dict[str, str | bool]:
    try:
        import oqs

        supported = "ML-KEM-768" in oqs.get_enabled_kem_mechanisms()
        return {
            "installed": True,
            "available": supported,
            "message": "liboqs-python is installed; ML-KEM-768 is available."
            if supported
            else "liboqs-python is installed, but ML-KEM-768 is not enabled in this build.",
        }
    except (ImportError, OSError, RuntimeError, AttributeError):
        return {
            "installed": False,
            "available": False,
            "message": "Optional ML-KEM mode is unavailable: liboqs-python is not installed.",
        }

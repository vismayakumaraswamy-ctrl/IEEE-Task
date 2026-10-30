from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical_aad(sender_id: str, recipient_id: str, message_id: str, timestamp: str) -> bytes:
    return "|".join(
        (sender_id.lower(), recipient_id.lower(), message_id, timestamp)
    ).encode("utf-8")


def encrypt_hybrid(
    data_bytes: bytes,
    recipient_public_key,
    sender_id: str = "",
    recipient_id: str = "",
    message_id: str = "",
    timestamp: str = "",
) -> dict[str, bytes]:
    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(
        nonce,
        data_bytes,
        canonical_aad(sender_id, recipient_id, message_id, timestamp),
    )
    wrapped_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "enc_session_key": wrapped_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "session_key": session_key,
    }


def decrypt_hybrid(
    enc_session_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    recipient_private_key,
    sender_id: str = "",
    recipient_id: str = "",
    message_id: str = "",
    timestamp: str = "",
) -> bytes:
    session_key = recipient_private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AESGCM(session_key).decrypt(
        nonce,
        ciphertext,
        canonical_aad(sender_id, recipient_id, message_id, timestamp),
    )

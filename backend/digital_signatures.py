from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def create_signature_payload(
    sender_id: str,
    recipient_id: str,
    timestamp: str,
    ciphertext: bytes,
    message_id: str = "",
    context: bytes = b"",
) -> bytes:
    cipher_digest = hashlib.sha256(ciphertext).hexdigest()
    fields = [sender_id.lower(), recipient_id.lower(), message_id, timestamp, cipher_digest]
    if context:
        fields.append(hashlib.sha256(context).hexdigest())
    canonical = "|".join(fields)
    return canonical.encode("utf-8")


def sign_message(payload: bytes, sender_signing_private_key) -> bytes:
    return sender_signing_private_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(payload: bytes, signature: bytes, sender_signing_public_key) -> dict[str, object]:
    try:
        sender_signing_public_key.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return {"valid": True, "message": "RSA-PSS-SHA256 signature verified."}
    except InvalidSignature:
        return {"valid": False, "message": "RSA-PSS-SHA256 signature mismatch."}

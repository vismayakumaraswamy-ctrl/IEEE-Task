from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid


class PacketManager:
    VERSION = "CRYPTOSHIELD-v2.0"

    @staticmethod
    def signature_context(packet: dict[str, Any]) -> bytes:
        signed_packet_fields = {
            key: value for key, value in packet.items() if key != "authentication"
        }
        return json.dumps(
            signed_packet_fields, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def validate_crypto_suite(cls, packet: dict[str, Any]) -> bool:
        if packet.get("version") != cls.VERSION:
            return False
        suite = packet.get("crypto_suite")
        if not isinstance(suite, dict):
            return False
        mode = suite.get("mode")
        key_agreement = (
            "X25519-ECDH-HKDF-SHA256"
            if mode == "X25519 forward secrecy"
            else "RSA-2048-OAEP-SHA256"
        )
        return (
            mode in {"RSA key transport", "X25519 forward secrecy"}
            and suite.get("symmetric") == "AES-256-GCM"
            and suite.get("key_agreement") == key_agreement
            and suite.get("signature") == "RSA-PSS-SHA256"
        )

    @classmethod
    def assemble_packet(
        cls,
        sender_id: str,
        recipient_id: str,
        wrapped_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        signature: bytes,
        sender_fingerprint: str,
        sender_encryption_fingerprint: str,
        recipient_fingerprint: str,
        *,
        message_id: str | None = None,
        timestamp: str | None = None,
        crypto_mode: str = "RSA key transport",
        ephemeral_public_key: bytes | None = None,
        prekey_id: str | None = None,
    ) -> dict[str, Any]:
        mode = crypto_mode.lower()
        packet: dict[str, Any] = {
            "version": cls.VERSION,
            "message_id": message_id or str(uuid.uuid4()),
            "sender_id": sender_id.lower(),
            "recipient_id": recipient_id.lower(),
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "crypto_suite": {
                "mode": crypto_mode,
                "symmetric": "AES-256-GCM",
                "key_agreement": "X25519-ECDH-HKDF-SHA256"
                if mode.startswith("x25519")
                else "RSA-2048-OAEP-SHA256",
                "signature": "RSA-PSS-SHA256",
            },
            "fingerprints": {
                "sender_signing": sender_fingerprint,
                "sender_encryption": sender_encryption_fingerprint,
                "recipient_encryption": recipient_fingerprint,
            },
            "payload": {
                "nonce_hex": nonce.hex(),
                "wrapped_key_hex": wrapped_key.hex(),
                "ciphertext_hex": ciphertext.hex(),
            },
            "authentication": {"signature_hex": signature.hex()},
        }
        if ephemeral_public_key is not None:
            packet["payload"]["ephemeral_public_key_hex"] = ephemeral_public_key.hex()
        if prekey_id is not None:
            packet["payload"]["prekey_id"] = prekey_id
        return packet

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.brute_force_guard import BruteForceGuard
from backend.digital_signatures import create_signature_payload, verify_signature
from backend.fingerprint_manager import TofuPinningManager
from backend.hybrid_encryption import decrypt_hybrid
from backend.packet_manager import PacketManager
from backend.replay_guard import ReplayAttackException, ReplayGuard
from database.database import AuditDatabase

_PACKET_REJECTIONS = (InvalidTag, ValueError, TypeError, AttributeError, KeyError)


ATTACKS = [
    {
        "id": "ciphertext-bit-flip",
        "name": "Ciphertext Bit-Flipping",
        "description": "Changes one ciphertext bit after the sender has signed the original packet.",
        "severity": "CRITICAL",
        "steps": ["Copy a protected packet.", "Flip a ciphertext bit.", "Run the signature and GCM checks."],
    },
    {
        "id": "tag-tamper",
        "name": "Authentication Tag Tampering",
        "description": "Corrupts the final AES-GCM authentication-tag byte.",
        "severity": "CRITICAL",
        "steps": ["Copy a protected packet.", "Modify its GCM tag.", "Verify the signature and authenticated decryption."],
    },
    {
        "id": "unauthorized-decryption",
        "name": "Unauthorized Key Decapsulation",
        "description": "Attempts RSA-OAEP decryption using an unrelated private key.",
        "severity": "HIGH",
        "steps": ["Keep the packet unchanged.", "Use an unrelated private key.", "Attempt key decapsulation."],
    },
    {
        "id": "signature-forgery",
        "name": "Digital Signature Forgery",
        "description": "Replaces the sender's RSA-PSS signature with untrusted bytes.",
        "severity": "HIGH",
        "steps": ["Copy a protected packet.", "Replace the signature.", "Verify with the pinned sender key."],
    },
    {
        "id": "mitm-substitution",
        "name": "Man-in-the-Middle Key Substitution",
        "description": "Substitutes an attacker's key after the recipient has pinned the contact.",
        "severity": "CRITICAL",
        "steps": ["Pin the contact's original key pair.", "Present an alternate key pair.", "Compare both TOFU fingerprints."],
    },
    {
        "id": "replay",
        "name": "Replay Attack",
        "description": "Resubmits a previously accepted message ID inside the timestamp window.",
        "severity": "HIGH",
        "steps": ["Accept a fresh test packet.", "Resubmit the same message ID.", "Check the SQLite replay ledger."],
    },
    {
        "id": "sender-forgery",
        "name": "Sender Identity Forgery",
        "description": "Changes the sender header without the sender's signing key.",
        "severity": "HIGH",
        "steps": ["Copy a protected packet.", "Replace its sender identity.", "Check RSA-PSS and AES-GCM AAD."],
    },
    {
        "id": "downgrade",
        "name": "Cryptographic Downgrade",
        "description": "Rewrites the declared cryptographic suite to an unsupported algorithm.",
        "severity": "HIGH",
        "steps": ["Copy a protected packet.", "Advertise a weak/unrecognized suite.", "Apply the strict suite allowlist."],
    },
    {
        "id": "nonce-reuse",
        "name": "AES-GCM Nonce Reuse (Educational)",
        "description": "Demonstrates why a GCM nonce must never repeat under the same key; this intentionally unsafe operation is isolated to memory.",
        "severity": "CRITICAL",
        "steps": ["Generate an isolated demo key and nonce.", "Encrypt two equal-length messages with the same pair.", "Show that XOR of ciphertext streams reveals XOR of plaintexts."],
    },
    {
        "id": "brute-force-lockout",
        "name": "Brute-Force Login & Lockout",
        "description": "Attempts repeated incorrect passwords against a synthetic, non-existent lab identity and checks the account lockout response.",
        "severity": "HIGH",
        "steps": ["Use a synthetic lab identity only.", "Submit five incorrect authentication attempts.", "Confirm the 180-second lockout and audit events."],
    },
    {
        "id": "malformed-packet",
        "name": "Malformed / Truncated Packet Fuzzing",
        "description": "Truncates packet ciphertext and tests strict signature and AES-GCM validation.",
        "severity": "HIGH",
        "steps": ["Copy a local test packet.", "Truncate the ciphertext and GCM tag.", "Run signature and authenticated-decryption checks."],
    },
]


def _signature_ok(packet: dict[str, Any], sender_public_key) -> bool:
    payload = packet["payload"]
    signed = create_signature_payload(
        packet["sender_id"],
        packet["recipient_id"],
        packet["timestamp"],
        bytes.fromhex(payload["ciphertext_hex"]),
        packet["message_id"],
        PacketManager.signature_context(packet),
    )
    result = verify_signature(
        signed, bytes.fromhex(packet["authentication"]["signature_hex"]), sender_public_key
    )
    return bool(result["valid"])


def _aead_ok(packet: dict[str, Any], recipient_private_key) -> bool:
    payload = packet["payload"]
    decrypt_hybrid(
        bytes.fromhex(payload["wrapped_key_hex"]),
        bytes.fromhex(payload["nonce_hex"]),
        bytes.fromhex(payload["ciphertext_hex"]),
        recipient_private_key,
        packet["sender_id"],
        packet["recipient_id"],
        packet["message_id"],
        packet["timestamp"],
    )
    return True


class SecuritySimulator:
    @staticmethod
    def run_attack(
        attack_id: str,
        packet: dict[str, Any],
        recipient_private_key,
        sender_public_key,
        database: AuditDatabase,
        actor_id: str,
        *,
        unrelated_private_key=None,
        sender_encryption_key=None,
        alternate_signing_key=None,
        alternate_encryption_key=None,
    ) -> dict[str, Any]:
        descriptor = next((item for item in ATTACKS if item["id"] == attack_id), None)
        if descriptor is None:
            raise ValueError("Unknown educational attack scenario.")
        tested = copy.deepcopy(packet)
        signature_valid: bool | None = None
        aead_valid: bool | None = None
        defense = "Packet policy"

        if attack_id == "ciphertext-bit-flip":
            raw = bytearray.fromhex(tested["payload"]["ciphertext_hex"])
            if len(raw) < 1:
                raise ValueError("Attack target ciphertext is empty.")
            raw[len(raw) // 2] ^= 0x01
            tested["payload"]["ciphertext_hex"] = raw.hex()
        elif attack_id == "tag-tamper":
            raw = bytearray.fromhex(tested["payload"]["ciphertext_hex"])
            if len(raw) < 16:
                raise ValueError("Attack target has no complete GCM tag.")
            raw[-1] ^= 0x80
            tested["payload"]["ciphertext_hex"] = raw.hex()
        elif attack_id == "unauthorized-decryption":
            try:
                signature_valid = _signature_ok(tested, sender_public_key)
            except _PACKET_REJECTIONS:
                signature_valid = False
            try:
                _aead_ok(tested, unrelated_private_key or sender_public_key)
                aead_valid = True
            except _PACKET_REJECTIONS:
                aead_valid = False
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                not aead_valid,
                signature_valid,
                aead_valid,
                "RSA-OAEP key ownership",
                "Unrelated private key could not unwrap the AES session key."
                if not aead_valid
                else "Unauthorized private key decrypted the packet.",
            )
        elif attack_id == "signature-forgery":
            tested["authentication"]["signature_hex"] = "00" * 256
        elif attack_id == "mitm-substitution":
            tofu = TofuPinningManager(database)
            original_ok, _ = tofu.verify_or_pin(
                actor_id,
                tested["sender_id"],
                sender_public_key,
                sender_encryption_key,
            )
            alternate_signing_key = alternate_signing_key or sender_public_key
            alternate_encryption_key = alternate_encryption_key or sender_encryption_key
            if alternate_encryption_key is None:
                raise ValueError("MITM simulation requires an alternate public key.")
            blocked, message = tofu.verify_or_pin(
                actor_id,
                tested["sender_id"],
                alternate_signing_key,
                alternate_encryption_key,
            )
            defense = "TOFU fingerprint pinning"
            substitution_accepted = original_ok and blocked
            message = message if not blocked else "Substituted key unexpectedly matched the pin."
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                not substitution_accepted,
                original_ok,
                None,
                defense,
                message,
            )
        elif attack_id == "replay":
            replay_guard = ReplayGuard(database)
            test_packet = copy.deepcopy(tested)
            test_packet["message_id"] = f"simulation-{uuid.uuid4()}"
            test_packet["timestamp"] = datetime.now(timezone.utc).isoformat()
            replay_guard.accept(test_packet)
            try:
                replay_guard.validate(test_packet)
                caught = False
                message = "Duplicate packet was not rejected."
            except ReplayAttackException as exc:
                caught = True
                message = str(exc)
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                caught,
                None,
                None,
                "Replay guard / SQLite seen_messages",
                message,
            )
        elif attack_id == "sender-forgery":
            tested["sender_id"] = "forged-identity"
        elif attack_id == "downgrade":
            tested["crypto_suite"] = {
                "mode": "legacy",
                "symmetric": "AES-128-CBC",
                "key_agreement": "RSA-1024",
                "signature": "SHA1",
            }
            allowed = PacketManager.validate_crypto_suite(tested)
            try:
                signature_valid = _signature_ok(tested, sender_public_key)
            except _PACKET_REJECTIONS:
                signature_valid = False
            try:
                aead_valid = _aead_ok(tested, recipient_private_key)
            except _PACKET_REJECTIONS:
                aead_valid = False
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                not allowed,
                signature_valid,
                aead_valid,
                "Strict cryptographic-suite allowlist",
                "Rejected unsupported suite before cryptographic processing."
                if not allowed
                else "Downgraded suite was unexpectedly allowed.",
            )
        elif attack_id == "nonce-reuse":
            key = AESGCM.generate_key(bit_length=256)
            nonce = b"\x7f" * 12
            first_plaintext = b"KNOWN-PLAINTEXT!"
            second_plaintext = b"CHOSEN-PLAINTEXT"
            first_ciphertext = AESGCM(key).encrypt(nonce, first_plaintext, None)
            second_ciphertext = AESGCM(key).encrypt(nonce, second_plaintext, None)
            leaked_xor = bytes(
                left ^ right
                for left, right in zip(first_ciphertext[: len(first_plaintext)], second_ciphertext[: len(second_plaintext)])
            )
            plaintext_xor = bytes(
                left ^ right for left, right in zip(first_plaintext, second_plaintext)
            )
            demonstrated = leaked_xor == plaintext_xor
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                False,
                None,
                None,
                "AES-GCM nonce uniqueness",
                "Isolated proof: ciphertext XOR revealed plaintext XOR."
                if demonstrated
                else "The educational nonce-reuse proof did not reproduce.",
            )
        elif attack_id == "brute-force-lockout":
            synthetic_user = f"lab_{uuid.uuid4().hex[:12]}"
            login_guard = BruteForceGuard(database)
            for _ in range(5):
                login_guard.authenticate(synthetic_user, "synthetic-incorrect-password")
            remaining = login_guard.remaining_lock_seconds(synthetic_user)
            locked = remaining > 0
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                locked,
                None,
                None,
                "Brute-force rate limit / temporary lockout",
                f"Synthetic identity lockout {'active' if locked else 'not active'}; remaining seconds={remaining}.",
            )
        elif attack_id == "malformed-packet":
            raw = bytes.fromhex(tested["payload"]["ciphertext_hex"])
            tested["payload"]["ciphertext_hex"] = raw[:-8].hex()
            try:
                signature_valid = _signature_ok(tested, sender_public_key)
            except _PACKET_REJECTIONS:
                signature_valid = False
            try:
                aead_valid = _aead_ok(tested, recipient_private_key)
            except _PACKET_REJECTIONS:
                aead_valid = False
            return SecuritySimulator._finish(
                descriptor,
                database,
                actor_id,
                not (signature_valid and aead_valid),
                signature_valid,
                aead_valid,
                "Packet signature and AES-GCM length/tag validation",
                f"Truncated packet checks: RSA-PSS={signature_valid}; AES-GCM={aead_valid}.",
            )

        try:
            signature_valid = _signature_ok(tested, sender_public_key)
        except _PACKET_REJECTIONS:
            signature_valid = False
        try:
            aead_valid = _aead_ok(tested, recipient_private_key)
        except _PACKET_REJECTIONS as exc:
            aead_valid = False
            detail = "AES-GCM AAD/tag authentication rejected the modified packet."
            if isinstance(exc, InvalidTag):
                detail = "AES-GCM InvalidTag: ciphertext, tag, or authenticated header changed."
        else:
            detail = "Packet passed AES-GCM authentication."
        if not signature_valid:
            defense = "RSA-PSS-SHA256 signature"
        accepted = signature_valid and aead_valid
        summary = (
            f"RSA-PSS: {'passed' if signature_valid else 'rejected'}; "
            f"AES-GCM: {'passed' if aead_valid else 'rejected'}. {detail}"
        )
        return SecuritySimulator._finish(
            descriptor, database, actor_id, not accepted, signature_valid, aead_valid, defense, summary
        )

    @staticmethod
    def _finish(
        descriptor: dict[str, Any],
        database: AuditDatabase,
        actor_id: str,
        defended: bool,
        signature_valid: bool | None,
        aead_valid: bool | None,
        defense: str,
        details: str,
    ) -> dict[str, Any]:
        result = {
            "attack": descriptor["name"],
            "description": descriptor["description"],
            "steps": descriptor["steps"],
            "severity": descriptor["severity"],
            "defended": defended,
            "signature_valid": signature_valid,
            "aead_valid": aead_valid,
            "defense": defense,
            "details": details,
        }
        database.log_event(
            "SIMULATION_" + descriptor["id"].upper().replace("-", "_"),
            descriptor["severity"],
            actor_id,
            f"{'BLOCKED' if defended else 'NOT BLOCKED'}: {descriptor['name']} — {defense}",
        )
        return result

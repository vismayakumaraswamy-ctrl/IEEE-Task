from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePath
from typing import Any
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


CHUNK_SIZE = 64 * 1024


def _signature_input(package: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in package.items() if key != "signature_hex"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt_file(
    file_bytes: bytes,
    filename: str,
    recipient_public_key,
    signer_private_key,
    signer_fingerprint: str,
) -> dict[str, Any]:
    if not filename or len(filename) > 255 or PurePath(filename).name != filename:
        raise ValueError("File name must be a plain name without directory paths.")
    file_id = str(uuid.uuid4())
    base_nonce = os.urandom(8)
    session_key = AESGCM.generate_key(bit_length=256)
    chunks = [file_bytes[index : index + CHUNK_SIZE] for index in range(0, len(file_bytes), CHUNK_SIZE)]
    if not chunks:
        chunks = [b""]
    encrypted_chunks: list[str] = []
    for index, chunk in enumerate(chunks):
        nonce = base_nonce + index.to_bytes(4, "big")
        aad = f"{file_id}|{filename}|{index}|{len(chunks)}".encode("utf-8")
        encrypted_chunks.append(AESGCM(session_key).encrypt(nonce, chunk, aad).hex())
    wrapped_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    package: dict[str, Any] = {
        "format": "CRYPTOSHIELD-FILE-v1",
        "file_id": file_id,
        "filename": filename,
        "plaintext_size": len(file_bytes),
        "chunk_size": CHUNK_SIZE,
        "chunk_count": len(chunks),
        "base_nonce_hex": base_nonce.hex(),
        "wrapped_key_hex": wrapped_key.hex(),
        "ciphertext_chunks_hex": encrypted_chunks,
        "signer_fingerprint": signer_fingerprint,
        "plaintext_sha256": hashlib.sha256(file_bytes).hexdigest(),
    }
    package["signature_hex"] = signer_private_key.sign(
        _signature_input(package),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    ).hex()
    return package


def decrypt_file(package: dict[str, Any], recipient_private_key, signer_public_key) -> tuple[str, bytes]:
    if package.get("format") != "CRYPTOSHIELD-FILE-v1":
        raise ValueError("Unsupported or malformed encrypted file package.")
    try:
        signature = bytes.fromhex(package["signature_hex"])
        signer_public_key.verify(
            signature,
            _signature_input(package),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("Package signature is malformed or file metadata was modified.") from exc
    except InvalidSignature as exc:
        raise ValueError("File package signature verification failed.") from exc

    filename = package.get("filename")
    chunks = package.get("ciphertext_chunks_hex")
    count = package.get("chunk_count")
    if (
        not isinstance(filename, str)
        or PurePath(filename).name != filename
        or not isinstance(chunks, list)
        or not isinstance(count, int)
        or count != len(chunks)
        or count < 1
        or count > 100_000
    ):
        raise ValueError("Encrypted file chunk metadata is invalid or truncated.")
    session_key = recipient_private_key.decrypt(
        bytes.fromhex(package["wrapped_key_hex"]),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    base_nonce = bytes.fromhex(package["base_nonce_hex"])
    if len(base_nonce) != 8:
        raise ValueError("Encrypted file base nonce is malformed.")
    file_id = package["file_id"]
    plaintext_chunks = []
    for index, encrypted_hex in enumerate(chunks):
        nonce = base_nonce + index.to_bytes(4, "big")
        aad = f"{file_id}|{filename}|{index}|{count}".encode("utf-8")
        plaintext_chunks.append(
            AESGCM(session_key).decrypt(nonce, bytes.fromhex(encrypted_hex), aad)
        )
    plaintext = b"".join(plaintext_chunks)
    if len(plaintext) != package.get("plaintext_size"):
        raise ValueError("Decrypted file length does not match signed metadata.")
    if not hashlib.sha256(plaintext).hexdigest() == package.get("plaintext_sha256"):
        raise ValueError("Decrypted file digest does not match signed metadata.")
    return filename, plaintext

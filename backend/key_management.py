from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

from backend.fingerprint_manager import compute_key_fingerprint


SCRYPT_PARAMETERS = {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "salt_bytes": 16}
PRIVATE_KEY_HEADER = b"-----BEGIN CRYPTOSHIELD SCRYPT ENCRYPTED PRIVATE KEY-----\n"
PRIVATE_KEY_FOOTER = b"\n-----END CRYPTOSHIELD SCRYPT ENCRYPTED PRIVATE KEY-----\n"
PRIVATE_KEY_AAD = b"CRYPTOSHIELD-PRIVATE-KEY-V1"
DEFAULT_KEY_DIR = Path(__file__).resolve().parents[1] / "storage" / "keys"


def _derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_PARAMETERS["n"],
        r=SCRYPT_PARAMETERS["r"],
        p=SCRYPT_PARAMETERS["p"],
    ).derive(password.encode("utf-8"))


class KeyVault:
    def __init__(self, key_dir: str | os.PathLike[str] = DEFAULT_KEY_DIR) -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def encrypt_private_material(private_der: bytes, password: str) -> bytes:
        salt, nonce = os.urandom(16), os.urandom(12)
        ciphertext = AESGCM(_derive_key(password, salt)).encrypt(
            nonce, private_der, PRIVATE_KEY_AAD
        )
        return PRIVATE_KEY_HEADER + base64.b64encode(salt + nonce + ciphertext) + PRIVATE_KEY_FOOTER

    @staticmethod
    def decrypt_private_material(encrypted: bytes, password: str) -> bytes:
        if not encrypted.startswith(PRIVATE_KEY_HEADER):
            return encrypted
        body = encrypted[len(PRIVATE_KEY_HEADER) : -len(PRIVATE_KEY_FOOTER)].strip()
        try:
            data = base64.b64decode(body, validate=True)
            if len(data) <= 28:
                raise ValueError("Encrypted private-key envelope is truncated.")
            salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
            return AESGCM(_derive_key(password, salt)).decrypt(
                nonce, ciphertext, PRIVATE_KEY_AAD
            )
        except (InvalidTag, ValueError, IndexError) as exc:
            raise ValueError("Private key could not be unlocked; check the password or file integrity.") from exc

    def _write_private_key(
        self, path: Path, key: rsa.RSAPrivateKey | x25519.X25519PrivateKey, password: str
    ) -> None:
        private_der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.write_bytes(self.encrypt_private_material(private_der, password))

    @staticmethod
    def _write_public_key(path: Path, key: rsa.RSAPublicKey | x25519.X25519PublicKey) -> None:
        path.write_bytes(
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    def generate_user_identities(self, username: str, password: str) -> dict[str, str]:
        safe_name = username.strip().lower()
        if not safe_name or not safe_name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Invalid identity name.")
        enc_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sign_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        x_private = x25519.X25519PrivateKey.generate()
        paths = {
            "enc_priv": self.key_dir / f"{safe_name}_enc_priv.pem",
            "enc_pub": self.key_dir / f"{safe_name}_enc_pub.pem",
            "sign_priv": self.key_dir / f"{safe_name}_sign_priv.pem",
            "sign_pub": self.key_dir / f"{safe_name}_sign_pub.pem",
            "x25519_priv": self.key_dir / f"{safe_name}_x25519_priv.pem",
            "x25519_pub": self.key_dir / f"{safe_name}_x25519_pub.pem",
        }
        self._write_private_key(paths["enc_priv"], enc_private, password)
        self._write_public_key(paths["enc_pub"], enc_private.public_key())
        self._write_private_key(paths["sign_priv"], sign_private, password)
        self._write_public_key(paths["sign_pub"], sign_private.public_key())
        self._write_private_key(paths["x25519_priv"], x_private, password)
        self._write_public_key(paths["x25519_pub"], x_private.public_key())
        return {
            "username": safe_name,
            "enc_fingerprint": compute_key_fingerprint(enc_private.public_key()),
            "sign_fingerprint": compute_key_fingerprint(sign_private.public_key()),
            "x25519_fingerprint": compute_key_fingerprint(x_private.public_key()),
        }

    def load_private_key(
        self, username: str, key_type: str, password: str
    ) -> rsa.RSAPrivateKey | x25519.X25519PrivateKey:
        key_type = key_type.lower()
        if key_type not in {"enc", "sign", "x25519"}:
            raise ValueError("Unknown private key type.")
        path = self.key_dir / f"{username.strip().lower()}_{key_type}_priv.pem"
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise FileNotFoundError(f"No {key_type} private key is available for this identity.") from exc
        if raw.startswith(PRIVATE_KEY_HEADER):
            key_bytes = self.decrypt_private_material(raw, password)
            private_key = serialization.load_der_private_key(key_bytes, password=None)
        else:
            try:
                private_key = serialization.load_pem_private_key(
                    raw, password=password.encode("utf-8")
                )
            except (TypeError, ValueError) as exc:
                raise ValueError("Private key could not be unlocked; check the password or key file.") from exc
        if key_type == "x25519":
            if not isinstance(private_key, x25519.X25519PrivateKey):
                raise ValueError("Stored private key does not match the requested X25519 key type.")
        elif not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Stored private key does not match the requested RSA key type.")
        return private_key

    def load_public_key(
        self, username: str, key_type: str
    ) -> rsa.RSAPublicKey | x25519.X25519PublicKey:
        key_type = key_type.lower()
        if key_type not in {"enc", "sign", "x25519"}:
            raise ValueError("Unknown public key type.")
        path = self.key_dir / f"{username.strip().lower()}_{key_type}_pub.pem"
        try:
            public_key = serialization.load_pem_public_key(path.read_bytes())
        except OSError as exc:
            raise FileNotFoundError(f"No {key_type} public key is available for this identity.") from exc
        if key_type == "x25519":
            if not isinstance(public_key, x25519.X25519PublicKey):
                raise ValueError("Stored public key does not match the requested X25519 key type.")
        elif not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Stored public key does not match the requested RSA key type.")
        return public_key

    def user_exists(self, username: str) -> bool:
        return (self.key_dir / f"{username.strip().lower()}_enc_pub.pem").is_file()

    def ensure_x25519_identity(self, username: str, password: str) -> str:
        safe_name = username.strip().lower()
        private_path = self.key_dir / f"{safe_name}_x25519_priv.pem"
        public_path = self.key_dir / f"{safe_name}_x25519_pub.pem"
        if not private_path.exists() or not public_path.exists():
            private_key = x25519.X25519PrivateKey.generate()
            self._write_private_key(private_path, private_key, password)
            self._write_public_key(public_path, private_key.public_key())
        return compute_key_fingerprint(self.load_public_key(safe_name, "x25519"))

    def save_prekey(
        self,
        private_key: x25519.X25519PrivateKey,
        password: str,
    ) -> tuple[str, bytes]:
        private_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        encrypted = self.encrypt_private_material(private_der, password)
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return public_pem, encrypted

    def unlock_prekey(
        self, encrypted_private_key: bytes, password: str
    ) -> x25519.X25519PrivateKey:
        private_der = self.decrypt_private_material(encrypted_private_key, password)
        private_key = serialization.load_der_private_key(private_der, password=None)
        if not isinstance(private_key, x25519.X25519PrivateKey):
            raise ValueError("Stored one-time prekey is not an X25519 private key.")
        return private_key

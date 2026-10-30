"""
IEEE Secure Communication Demo: AES-GCM & RSA-OAEP
Handles text input, authenticated symmetric encryption, public-key cryptography,
file persistence, and input validation.
"""

import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


class SecureMessenger:
    def __init__(self):
        # 1. Initialize AES: Generate a 256-bit symmetric key
        self.aes_key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.aes_key)

        # 2. Initialize RSA: Generate 2048-bit keypair
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    # --- AES-GCM Encryption & Decryption ---
    def encrypt_aes(self, plaintext: str) -> dict:
        """Encrypts text using AES-256-GCM with a unique 96-bit nonce."""
        if not plaintext.strip():
            raise ValueError("Plaintext cannot be empty.")

        nonce = os.urandom(12)  # 12 bytes = 96-bit nonce recommended for GCM
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        return {
            "algorithm": "AES-256-GCM",
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex()
        }

    def decrypt_aes(self, nonce_hex: str, ciphertext_hex: str) -> str:
        """Decrypts and verifies authentication tag using AES-256-GCM."""
        try:
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            raise ValueError("Invalid hexadecimal format in Nonce or Ciphertext.")

        try:
            decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag:
            raise ValueError("Decryption failed: Authentication tag mismatch (data corrupted or tampered).")

    # --- RSA-OAEP Encryption & Decryption ---
    def encrypt_rsa(self, plaintext: str) -> dict:
        """Encrypts text using RSA Public Key with OAEP padding."""
        if not plaintext.strip():
            raise ValueError("Plaintext cannot be empty.")

        data = plaintext.encode("utf-8")
        # 2048-bit RSA with SHA-256 OAEP padding supports max 190 bytes
        max_size = 190
        if len(data) > max_size:
            raise ValueError(f"Message exceeds RSA-OAEP limit of {max_size} bytes.")

        ciphertext = self.rsa_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            "algorithm": "RSA-2048-OAEP-SHA256",
            "ciphertext_hex": ciphertext.hex()
        }

    def decrypt_rsa(self, ciphertext_hex: str) -> str:
        """Decrypts text using RSA Private Key with OAEP padding."""
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            raise ValueError("Invalid hexadecimal format in Ciphertext.")

        try:
            decrypted_bytes = self.rsa_private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_bytes.decode("utf-8")
        except Exception:
            raise ValueError("Decryption failed: Private key cannot decrypt this ciphertext.")

    # --- Storage ---
    @staticmethod
    def save_to_file(record: dict, filename: str = "encrypted_messages.json"):
        """Saves encrypted records cleanly to a JSON file."""
        records = []
        if os.path.exists(filename):
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    records = json.load(f)
                    if not isinstance(records, list):
                        records = []
            except Exception:
                records = []

        records.append(record)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=4)


def run_cli():
    messenger = SecureMessenger()

    print("\n" + "=" * 62)
    print("   IEEE SECURE COMMUNICATION SYSTEM (AES-GCM & RSA-OAEP)")
    print("=" * 62)
    print("[*] Keys generated: 256-bit AES & 2048-bit RSA Keypair ready.\n")

    while True:
        print("\n--- MENU ---")
        print("1. Encrypt message (AES-GCM)")
        print("2. Decrypt message (AES-GCM)")
        print("3. Encrypt message with Public Key (RSA-OAEP)")
        print("4. Decrypt message with Private Key (RSA-OAEP)")
        print("5. Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":
            msg = input("Enter plaintext to encrypt: ").strip()
            try:
                result = messenger.encrypt_aes(msg)
                print("\n[+] AES Encryption Result:")
                print(f"    Original  : {msg}")
                print(f"    Nonce(hex): {result['nonce_hex']}")
                print(f"    Ciphertext: {result['ciphertext_hex']}")

                save = input("Save to encrypted_messages.json? (y/n): ").strip().lower()
                if save == "y":
                    SecureMessenger.save_to_file(result)
                    print("[✓] Saved to 'encrypted_messages.json'.")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif choice == "2":
            nonce = input("Enter Nonce (hex): ").strip()
            ciphertext = input("Enter Ciphertext (hex): ").strip()
            try:
                decrypted = messenger.decrypt_aes(nonce, ciphertext)
                print("\n[+] AES Decryption Successful:")
                print(f"    Decrypted Plaintext: {decrypted}")
            except ValueError as e:
                print(f"[!] Decryption Error: {e}")

        elif choice == "3":
            msg = input("Enter plaintext (max 190 characters): ").strip()
            try:
                result = messenger.encrypt_rsa(msg)
                print("\n[+] RSA Public-Key Encryption Result:")
                print(f"    Original  : {msg}")
                print(f"    Ciphertext: {result['ciphertext_hex']}")

                save = input("Save to encrypted_messages.json? (y/n): ").strip().lower()
                if save == "y":
                    SecureMessenger.save_to_file(result)
                    print("[✓] Saved to 'encrypted_messages.json'.")
            except ValueError as e:
                print(f"[!] Error: {e}")

        elif choice == "4":
            ciphertext = input("Enter RSA Ciphertext (hex): ").strip()
            try:
                decrypted = messenger.decrypt_rsa(ciphertext)
                print("\n[+] RSA Private-Key Decryption Successful:")
                print(f"    Decrypted Plaintext: {decrypted}")
            except ValueError as e:
                print(f"[!] Decryption Error: {e}")

        elif choice == "5":
            print("\nExiting")
            break

        else:
            print("[!] Invalid option. Enter a number between 1 and 5.")


if __name__ == "__main__":
    run_cli()
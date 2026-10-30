🛡️ CRYPTOSHIELD | Security Operations Center (SOC)
> **Advanced Multi-User Secure Communication, Cryptographic Key Vault & Threat Detection Platform**
https://www.python.org/
https://cryptography.io/
https://streamlit.io/
[]()
License
CRYPTOSHIELD is an enterprise-inspired Security Operations Center (SOC) and cryptographic communication platform. It upgrades traditional command-line cryptographic assignments into a production-grade, interactive dashboard featuring Hybrid Authenticated Encryption (AES-GCM + AAD), Digital Signatures (RSA-PSS), Perfect Forward Secrecy (X25519 ECDH + HKDF), Trust-On-First-Use (TOFU) Pinning, Hash-Chained Audit Logging, and an interactive Security Attack Simulation Lab.
---
📑 Table of Contents
Key Features & Cryptographic Architecture
Directory Structure
Cryptographic Specifications
Attack Simulation Lab
Installation & Quickstart
Evaluation & Demo Walkthrough
Default Demo Credentials
Security Invariants & Defenses
---
⚡ Key Features & Cryptographic Architecture
1. Hybrid Authenticated Encryption with AAD
Arbitrary Length Payload Support: Encrypts data using authenticated symmetric AES-256-GCM with fresh 96-bit CSPRNG nonces (`os.urandom(12)`).
Associated Authenticated Data (AAD): Cryptographically binds packet metadata (`sender|recipient|message_id|timestamp`) into the AES-GCM authentication tag. Any tampering with headers causes decryption to fail immediately.
Key Encapsulation: Protects ephemeral 256-bit AES session keys using the recipient's RSA-2048-OAEP public key with SHA-256 and MGF1 padding.
2. Perfect Forward Secrecy (PFS) Mode
Ephemeral X25519 ECDH: An optional transmission mode using one-time ephemeral Elliptic Curve Diffie-Hellman (X25519) key agreement.
HKDF-SHA256 Derivation: Derives the AES-256 session key dynamically using HKDF with the packet nonce as salt.
Past Session Protection: Even if a user's long-term RSA private key is compromised in the future, past recorded forward-secret ciphertexts cannot be decrypted.
3. Digital Signatures & Sender Authentication
RSA-2048-PSS: Generates probabilistic digital signatures using SHA-256 and maximum salt length to guarantee non-repudiation and authenticity.
Metadata Binding: Signs a canonical digest over `sender|recipient|message_id|timestamp|sha256(ciphertext)`. Attackers cannot re-target or alter packet headers without invalidating the signature.
4. Key Vault & Scrypt KDF Lifecycle
Zero Plaintext Storage: Private keys are encrypted at rest using high-memory Scrypt KDF parameters ($N=32768, r=8, p=1$, 16-byte salt) inside PKCS#8 PEM files.
Key Rotation & Revocation: Supports rotating keypairs with fresh passphrases. Old key fingerprints are marked as `REVOKED` in SQLite, and the system automatically rejects messages signed with revoked keys.
Out-of-Band Fingerprint Verification: Computes canonical colon-separated SHA-256 fingerprints with on-screen QR codes for out-of-band identity checks.
5. Replay Attack & Timestamp Defense
120-Second Sliding Window: Enforces message freshness by comparing real UTC timestamps against a configurable 120s window (with 15s future drift tolerance).
Seen-Message Tracking: Persists unique `message_id` records in SQLite to detect and immediately block duplicate packet re-injections.
6. Trust-On-First-Use (TOFU) Pinning
Automatic Pinning: Automatically pins a contact's public-key fingerprint upon the first interaction.
Man-in-the-Middle (MITM) Defense: Detects if an attacker attempts to substitute a public key in transit, raising a critical alert and halting transmission.
7. Chunked Binary File Encryption Vault
64 KB Chunked Streaming: Encrypts large binary files (PDFs, images, office files) in 64 KB chunks using AES-256-GCM.
Sequence-Bound Nonces: Derives nonces with sequential chunk indices (`base_nonce + chunk_index`) to prevent chunk reordering, truncation, or splicing attacks.
Signed Packages: Downloads self-contained `.shield.json` encrypted packages that can be uploaded and verified by authorized recipients.
8. Hash-Chained Audit Ledger
Tamper-Evident Ledger: Every security event is chained to the preceding entry using SHA-256 (`current_hash = SHA256(prev_hash|timestamp|event_type|severity|user|details)`).
Pinpointed Verification: The "Verify Entire Audit Chain Integrity" tool validates the entire chain from the genesis block (`000...`) and pinpoints the exact row number if database tampering occurs.
---
📂 Directory Structure
```text
cryptoshield/
├── .streamlit/
│   └── config.toml             # Dark cyber-SOC aesthetic & security settings
├── requirements.txt            # Project dependencies
├── app.py                      # Complete Streamlit SOC interactive application
├── backend/
│   ├── __init__.py
│   ├── fingerprint_manager.py  # SHA-256 public key fingerprinting & TOFU pinning
│   ├── replay_guard.py         # Timestamp window & seen-message replay defense
│   ├── brute_force_guard.py    # Rate-limiting & identity lockout engine
│   ├── hybrid_encryption.py    # AES-256-GCM (with AAD) + RSA-2048-OAEP
│   ├── forward_secrecy.py      # Ephemeral X25519 ECDH + HKDF-SHA256 PFS engine
│   ├── digital_signatures.py   # RSA-2048-PSS SHA-256 with metadata binding
│   ├── key_rotation.py         # Key lifecycle, rotation & revocation registry
│   ├── key_management.py       # Scrypt PKCS#8 encrypted PEM vault
│   ├── packet_manager.py       # Standardized cryptographic envelope serialization
│   ├── file_crypto.py          # Chunked AES-GCM file encryption & verification
│   ├── audit_chain.py          # SHA-256 hash-chained immutable audit ledger
│   ├── qr_generator.py         # QR code generator for out-of-band verification
│   └── security_simulator.py   # Dual-layer attack simulation testbed
├── database/
│   ├── __init__.py
│   └── database.py             # SQLite WAL-mode persistent database
└── storage/
    ├── keys/                   # Encrypted PKCS#8 private keys & public PEMs
    ├── messages/               # Exported JSON packets
    └── encrypted_files/        # Encrypted file packages
```
---
🔒 Cryptographic Specifications
Component	Standard / Algorithm	Parameters / Configuration	Security Purpose
Symmetric Cipher	AES-256-GCM	256-bit key, 96-bit CSPRNG nonce, 128-bit GMAC tag	Payload confidentiality & integrity
Associated Data (AAD)	Bound Canonical String	`sender|recipient|message_id|timestamp`	Header tamper resistance
Key Transport	RSA-OAEP	2048-bit key, $e=65537$, SHA-256 digest, MGF1	Asymmetric session key encapsulation
Forward Secrecy	X25519 ECDH + HKDF	Curve25519, HKDF-SHA256, 32-byte derived key	Compromised key isolation
Digital Signatures	RSA-PSS	2048-bit key, SHA-256, Maximum salt length	Non-repudiation & sender authentication
Key Storage KDF	Scrypt (PKCS#8)	$N=32768, r=8, p=1$, 16-byte salt	Anti-GPU/ASIC password protection
Identity Pinning	TOFU Fingerprint	Canonical SubjectPublicKeyInfo SHA-256 DER digest	Man-in-the-Middle (MITM) mitigation
Audit Chaining	Merkle-Damgård Chain	Cumulative SHA-256 recursive hashing	Tamper-evident log auditing
---
🧪 Attack Simulation Lab
The Security Attack Simulation Lab provides safe, controlled, and isolated demonstrations of multi-layered defense mechanisms:
Ciphertext Bit-Flipping Attack: Inverts bits in the ciphertext body. Detected by both Layer 1 (RSA-PSS digest) and Layer 2 (AES-GCM tag).
Authentication Tag Tampering: Alters the 16-byte GMAC tag. Blocked immediately by AES-GCM authentication.
Unauthorized Key Decapsulation: Attempts to decrypt Bob's packet using an unauthorized private key (Eve). Mathematically rejected by RSA-OAEP.
Digital Signature Forgery: Modifies the signature bytes or signed document text. Fails RSA-PSS probabilistic verification.
MITM Public Key Substitution: Injects an attacker's public key in place of genuine Bob. Blocked and alerted by TOFU Fingerprint Pinning.
Replay Attack: Replays an identical valid historical packet. Blocked by SQLite Seen-Message Tracking.
Sender Identity Forgery: Changes sender header in transit. Blocked by AES-GCM AAD and RSA-PSS metadata binding.
Cryptographic Downgrade Attack: Modifies the packet cipher suite to an insecure cipher (e.g. `DES-ECB`). Blocked by Cipher Suite Whitelist Policy.
---
🚀 Installation & Quickstart
Prerequisites
Python 3.11, 3.12, or 3.13
Git
1. Clone the Repository
```bash
git clone https://github.com/vismayakumaraswamy-ctrl/IEEE-Task.git
cd IEEE-Task
```
2. Install Dependencies
```bash
pip install -r requirements.txt
```
3. Launch the SOC Platform
```bash
streamlit run app.py
```
The application will automatically launch in your browser at `http://localhost:8501`.
---
👤 Default Demo Credentials
The platform initializes three default identities with pre-configured persistent keypairs:
Identity	Role	Default Passphrase	Key Types Available
Alice	Primary Sender / Operator	`AliceSecret123!`	RSA Enc, RSA Sign, X25519
Bob	Recipient / Operator	`BobSecret456!`	RSA Enc, RSA Sign, X25519
Eve	Attacker / Unauthorized Entity	`EveAttacker789!`	RSA Enc, RSA Sign, X25519
(You can also register custom identities with custom passphrases directly from the login screen).
---
🎯 Evaluation & Demo Walkthrough (3-Minute Script)
Session Authentication:
Select Alice, type `AliceSecret123!`, and click Unlock Session.
Hybrid & Forward Secrecy Messaging:
Open Secure Messenger -> Compose & Transmit.
Select Bob as recipient, enter your message, enable the Perfect Forward Secrecy (X25519) toggle, and click Encrypt & Transmit.
Note the delivery confirmation into SQLite.
Persistent Inbox Decryption:
Click Terminate Session in the sidebar. Log in as Bob using `BobSecret456!`.
Open Secure Messenger -> Inbox, select Alice's packet from the dropdown, and click Authenticate & Decrypt.
Demonstrate the recovered plaintext alongside green verification badges for RSA-PSS Signature and AES-GCM AAD Tag.
Threat Defense & Attack Lab:
Open Attack Simulation Lab.
Run Attack 1 (Bit-Flipping) to showcase dual-layer tamper detection.
Run Attack 5 (MITM Substitution) to show how TOFU pinning detects and halts public key replacement.
Run Attack 6 (Replay Attack) to demonstrate that duplicate packet injection is stopped by seen-message tracking.
Key Vault & Audit Ledger Verification:
Open Key Vault & Lifecycle to view active SHA-256 fingerprints, QR codes, and Scrypt KDF parameters.
Open Audit Ledger Integrity and click Verify Entire Audit Chain Integrity to show the unbroken cryptographic ledger.
---
🛡️ Security Invariants & Defenses
Confidentiality: Guaranteed via AES-256-GCM symmetric encryption and RSA-2048-OAEP / X25519 session key encapsulation.
Integrity & Authenticity: Guaranteed via 128-bit GMAC tags bound to AAD and RSA-2048-PSS digital signatures.
Non-Repudiation: Senders cannot deny authoring messages due to private signing keys.
Replay Immunity: Stale timestamps (>120s) and duplicate `message_id`s are blocked.
Forward Secrecy: Ephemeral X25519 keys ensure past session traffic cannot be decrypted retroactively.
Tamper Evidence: Any modification to SQLite audit logs breaks the SHA-256 hash chain and pinpoints the compromised row.

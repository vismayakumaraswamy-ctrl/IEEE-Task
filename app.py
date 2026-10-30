from __future__ import annotations

import html
import json
import time
import uuid
import csv
from datetime import datetime, timezone
from io import BytesIO, StringIO
from typing import Any

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from backend.brute_force_guard import BruteForceGuard
from backend.digital_signatures import create_signature_payload, sign_message, verify_signature
from backend.file_crypto import decrypt_file, encrypt_file
from backend.fingerprint_manager import TofuPinningManager, compute_key_fingerprint
from backend.forward_secrecy import (
    create_one_time_prekeys,
    decrypt_forward_secret,
    encrypt_forward_secret,
    pqc_status,
)
from backend.hybrid_encryption import decrypt_hybrid, encrypt_hybrid
from backend.key_management import SCRYPT_PARAMETERS, KeyVault
from backend.key_rotation import KeyRotationManager
from backend.packet_manager import PacketManager
from backend.replay_guard import ReplayAttackException, ReplayGuard
from backend.security_simulator import ATTACKS, SecuritySimulator
from backend.qr_generator import fingerprint_qr_png
from database.database import AuditDatabase, normalize_user


st.set_page_config(
    page_title="CRYPTOSHIELD | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root { --cyan:#00f0ff; --green:#39d353; --panel:rgba(19,27,46,.78); }
    .stApp { background: radial-gradient(circle at 75% 0%, #14213b 0, #0b0f19 43%); }
    section[data-testid="stSidebar"] { background:linear-gradient(180deg,#111a2d,#0b0f19); border-right:1px solid #163b4b; }
    section[data-testid="stSidebar"] * { color:#dce7f3; }
    .soc-banner { border:1px solid #00f0ff66; border-radius:16px; padding:18px 22px;
      background:linear-gradient(110deg,rgba(0,240,255,.10),rgba(57,211,83,.045));
      box-shadow:0 0 25px #00f0ff12; margin-bottom:18px; }
    .soc-title { color:#e7fbff; font-weight:800; letter-spacing:.08em; font-size:1.55rem; }
    .soc-subtitle { color:#9cb2c9; font-size:.88rem; }
    .status-dot { color:#39d353; text-shadow:0 0 10px #39d353; }
    div[data-testid="stMetric"] { background:var(--panel); border:1px solid #00f0ff33;
      border-radius:14px; padding:14px; box-shadow:0 0 15px #00f0ff0c; }
    div[data-testid="stTabs"] button[aria-selected="true"] { color:#00f0ff; }
    .hex { font-family:Consolas,monospace; color:#7eeaff; overflow-wrap:anywhere; }
    .bubble { padding:12px 15px; border-radius:14px; margin:8px 0; background:#142138;
      border:1px solid #00f0ff33; }
    .verified { color:#39d353; font-weight:700; }
    .alert-card { padding:10px 12px; border-left:4px solid #00f0ff; border-radius:8px;
      background:#111a2b; margin:7px 0; }
    .alert-high { border-left-color:#ffb020; } .alert-critical { border-left-color:#ff4d6d; }
    code, pre { font-family:Consolas,monospace !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

database = AuditDatabase()
vault = KeyVault()
guard = BruteForceGuard(database)
rotation = KeyRotationManager(vault, database)
tofu = TofuPinningManager(database)


def _register_key_record(user_id: str, key_type: str, algorithm: str, public_key) -> str:
    fingerprint = compute_key_fingerprint(public_key)
    if database.get_key_record(fingerprint) is None:
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        database.add_key_record(fingerprint, user_id, key_type, algorithm, public_pem)
    return fingerprint


def _prepare_identity(user_id: str, password: str) -> None:
    if not vault.user_exists(user_id):
        vault.generate_user_identities(user_id, password)
    else:
        vault.ensure_x25519_identity(user_id, password)
    _register_key_record(
        user_id, "enc", "RSA-2048-OAEP-SHA256", vault.load_public_key(user_id, "enc")
    )
    _register_key_record(
        user_id, "sign", "RSA-2048-PSS-SHA256", vault.load_public_key(user_id, "sign")
    )
    _register_key_record(
        user_id, "x25519", "X25519", vault.load_public_key(user_id, "x25519")
    )
    if len(database.get_active_prekeys(user_id)) < 2:
        create_one_time_prekeys(database, vault, user_id, password, 5)


def _show_login() -> None:
    st.markdown(
        '<div class="soc-banner"><div class="soc-title">🛡️ CRYPTOSHIELD | SOC</div>'
        '<div class="soc-subtitle">Secure Communication &amp; Threat Detection · '
        '<span class="status-dot">●</span> Identity gateway online</div></div>',
        unsafe_allow_html=True,
    )
    st.title("Secure identity gateway")
    st.caption("Authenticate to unlock your local identity. Password verifiers are salted PBKDF2 hashes in SQLite.")
    names = database.user_ids()
    choices = ["Sign in", "Create new identity"]
    choice = st.radio("Access mode", choices, horizontal=True)
    if choice == "Sign in":
        selected = st.selectbox("Identity", names, format_func=lambda value: value.title())
        password = st.text_input("Password", type="password", key="login_password")
        remaining = guard.remaining_lock_seconds(selected)
        if remaining:
            st.warning(f"Temporary lockout active. Try again in {remaining} seconds.")
        if st.button("Authenticate", type="primary", disabled=remaining > 0):
            try:
                accepted = guard.authenticate(selected, password)
                if not accepted:
                    st.error("Authentication failed. Repeated failures trigger a temporary lockout.")
                else:
                    _prepare_identity(selected, password)
                    st.session_state["authenticated"] = True
                    st.session_state["user_id"] = selected
                    st.toast(f"Authenticated as {selected.title()}", icon="✅")
                    st.rerun()
            except (ValueError, PermissionError, OSError) as exc:
                st.error(str(exc))
    else:
        username = st.text_input("New identity", placeholder="e.g. Charlie")
        password = st.text_input("Create password", type="password", key="register_password")
        confirm = st.text_input("Confirm password", type="password", key="register_confirm")
        st.caption("Use at least 12 characters. Password verifiers use salted PBKDF2-HMAC-SHA256.")
        if st.button("Create account", type="primary"):
            try:
                normalized = normalize_user(username)
                if password != confirm:
                    raise ValueError("Password confirmation does not match.")
                database.register_user(normalized, password)
                vault.generate_user_identities(normalized, password)
                _prepare_identity(normalized, password)
                database.log_event("IDENTITY_CREATED", "INFO", normalized, "New local identity enrolled.")
                st.session_state["authenticated"] = True
                st.session_state["user_id"] = normalized
                st.toast("Identity created and keys provisioned.", icon="✅")
                st.rerun()
            except (ValueError, OSError) as exc:
                st.error(str(exc))


if not st.session_state.get("authenticated") or not st.session_state.get("user_id"):
    _show_login()
    st.stop()

user_id = str(st.session_state["user_id"])
display_user = user_id.title()
other_users = [candidate for candidate in database.user_ids() if candidate != user_id]

with st.sidebar:
    st.markdown("## 🛡️ CRYPTOSHIELD")
    st.caption("SECURE COMMUNICATION & THREAT DETECTION")
    st.markdown(f"Signed in as **{display_user}**")
    st.markdown('<span class="status-dot">●</span> All core services operational', unsafe_allow_html=True)
    navigation = {
        "📊 Overview & Telemetry": "Overview & Telemetry",
        "💬 Secure Messenger": "Secure Messenger",
        "🔑 Key Vault & Lifecycle": "Key Vault & Lifecycle",
        "✍️ Digital Signatures": "Digital Signatures",
        "📁 File Encryption Vault": "File Encryption Vault",
        "🧪 Attack Simulation Lab": "Attack Simulation Lab",
        "⛓️ Audit Ledger Integrity": "Audit Ledger Integrity",
        "⚙️ Encryption Visualizer & Benchmark": "Encryption Visualizer & Benchmark",
    }
    selected_page = st.radio(
        "SOC NAVIGATION",
        list(navigation),
        label_visibility="collapsed",
    )
    page = navigation[selected_page]
    if st.button("Log out", use_container_width=True):
        database.log_event("LOGOUT", "INFO", user_id, "User logged out.")
        st.session_state.clear()
        st.rerun()

st.markdown(
    f'<div class="soc-banner"><div class="soc-title">🛡️ CRYPTOSHIELD | SOC</div>'
    f'<div class="soc-subtitle">Secure Communication &amp; Threat Detection · '
    f'<span class="status-dot">●</span> Authenticated session: {html.escape(display_user)}</div></div>',
    unsafe_allow_html=True,
)


def _packet_build(
    sender: str,
    recipient: str,
    text: str,
    password: str,
    mode: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    recipient_sign = vault.load_public_key(recipient, "sign")
    recipient_enc = vault.load_public_key(recipient, "enc")
    sender_sign = vault.load_private_key(sender, "sign", password)
    sender_enc_pub = vault.load_public_key(sender, "enc")
    sender_sign_fp = compute_key_fingerprint(vault.load_public_key(sender, "sign"))
    sender_enc_fp = compute_key_fingerprint(sender_enc_pub)
    recipient_enc_fp = compute_key_fingerprint(recipient_enc)
    accepted, notice = tofu.verify_or_pin(sender, recipient, recipient_sign, recipient_enc)
    if not accepted:
        raise PermissionError(notice)
    if notice.startswith("First contact"):
        database.log_event("TOFU_PINNED", "INFO", sender, f"Initial fingerprints pinned for {recipient}.")
    signature_record = database.get_key_record(sender_sign_fp)
    if signature_record is None or signature_record["status"] != "ACTIVE":
        raise PermissionError("The active signing key is revoked or missing.")

    message_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    aad_args = (sender, recipient, message_id, timestamp)
    prekey_id_to_claim: str | None = None
    visualizer: dict[str, Any]
    if mode == "X25519 forward secrecy":
        prekeys = database.get_active_prekeys(recipient)
        if not prekeys:
            raise ValueError(
                f"{recipient.title()} has no active one-time prekeys. Ask them to sign in once to provision prekeys."
            )
        prekey = prekeys[0]
        prekey_id_to_claim = prekey["prekey_id"]
        pfs_result = encrypt_forward_secret(
            text.encode("utf-8"),
            prekey["public_key_pem"],
            *aad_args,
            prekey["prekey_id"],
        )
        nonce = pfs_result["nonce"]
        ciphertext = pfs_result["ciphertext"]
        wrapped_key = b""
        visualizer = {
            "mode": mode,
            "session_key": pfs_result["session_key"].hex(),
            "ephemeral_public_key": pfs_result["ephemeral_public_key"].hex(),
            "prekey_id": prekey["prekey_id"],
        }
        packet = PacketManager.assemble_packet(
            sender,
            recipient,
            wrapped_key,
            nonce,
            ciphertext,
            b"",
            sender_sign_fp,
            sender_enc_fp,
            recipient_enc_fp,
            message_id=message_id,
            timestamp=timestamp,
            crypto_mode=mode,
            ephemeral_public_key=pfs_result["ephemeral_public_key"],
            prekey_id=prekey["prekey_id"],
        )
    else:
        encrypted = encrypt_hybrid(
            text.encode("utf-8"), recipient_enc, *aad_args
        )
        nonce = encrypted["nonce"]
        ciphertext = encrypted["ciphertext"]
        wrapped_key = encrypted["enc_session_key"]
        visualizer = {
            "mode": mode,
            "session_key": encrypted["session_key"].hex(),
            "wrapped_key": wrapped_key.hex(),
        }
        packet = PacketManager.assemble_packet(
            sender,
            recipient,
            wrapped_key,
            nonce,
            ciphertext,
            b"",
            sender_sign_fp,
            sender_enc_fp,
            recipient_enc_fp,
            message_id=message_id,
            timestamp=timestamp,
            crypto_mode=mode,
        )
    signature_payload = create_signature_payload(
        sender,
        recipient,
        timestamp,
        ciphertext,
        message_id,
        PacketManager.signature_context(packet),
    )
    signature = sign_message(signature_payload, sender_sign)
    packet["authentication"]["signature_hex"] = signature.hex()
    if prekey_id_to_claim and not database.claim_prekey(prekey_id_to_claim, recipient):
        raise ValueError("Selected one-time prekey was claimed concurrently; retry the send.")
    try:
        database.save_packet(packet)
    except Exception:
        if prekey_id_to_claim:
            database.release_prekey(prekey_id_to_claim, recipient)
        raise
    database.log_event("MESSAGE_SENT", "INFO", sender, f"Encrypted packet sent to {recipient}.")
    visualizer.update(
        {
            "plaintext": text,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "signature": signature.hex(),
            "packet": packet,
            "recipient_sign_fp": compute_key_fingerprint(recipient_sign),
            "aad": "|".join(aad_args),
        }
    )
    return packet, visualizer


def _render_packet_inspector(packet: dict[str, Any]) -> None:
    packet_json = json.dumps(packet, indent=2, sort_keys=True)
    st.caption(f"Serialized packet size: {len(packet_json.encode('utf-8')):,} bytes")
    payload = packet["payload"]
    st.markdown("**Nonce**")
    st.code(payload["nonce_hex"], language="text")
    st.markdown("**Ciphertext + GCM tag**")
    st.code(payload["ciphertext_hex"], language="text")
    st.markdown("**Wrapped session key / X25519 ephemeral public key**")
    st.code(payload.get("wrapped_key_hex") or payload.get("ephemeral_public_key_hex", ""), language="text")
    with st.expander("Full packet JSON"):
        st.json(packet)


def _render_dashboard() -> None:
    summary = database.get_summary()
    events = database.get_recent_events(100)
    chain_ok, broken_id, total_rows, _ = database.verify_chain()
    my_sign_fp = compute_key_fingerprint(vault.load_public_key(user_id, "sign"))
    signing_record = database.get_key_record(my_sign_fp)
    checks_passed = sum(
        (
            chain_ok,
            bool(signing_record and signing_record["status"] == "ACTIVE"),
            database.user_exists(user_id),
            True,
        )
    )
    security_score = round(100 * checks_passed / 4)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Persisted packets", summary["total_messages"])
    c2.metric("High / critical alerts", summary["alerts"])
    c3.metric("Registered identities", summary["active_users"])
    c4.metric("Audit rows", total_rows)
    st.caption("Cryptographic policy: AES-256-GCM · RSA-2048-OAEP/PSS · X25519/HKDF · PBKDF2 auth · Scrypt private keys")

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Security score")
        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=security_score,
                number={"suffix": "%"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#00f0ff"},
                    "steps": [
                        {"range": [0, 50], "color": "#3a1c2a"},
                        {"range": [50, 80], "color": "#3a3420"},
                        {"range": [80, 100], "color": "#143326"},
                    ],
                    "bgcolor": "#131b2e",
                },
            )
        )
        gauge.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0", margin=dict(t=20, b=10))
        st.plotly_chart(gauge, use_container_width=True)
    with right:
        st.subheader("Event severity")
        if events:
            severity_counts: dict[str, int] = {}
            for event in events:
                severity = str(event["severity"])
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            severities = [
                {"severity": severity, "events": count}
                for severity, count in severity_counts.items()
            ]
            donut = px.pie(severities, names="severity", values="events", hole=0.62, color="severity",
                           color_discrete_map={"INFO": "#00f0ff", "MEDIUM": "#ffd166", "HIGH": "#ff8c42", "CRITICAL": "#ff4d6d"})
            donut.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0", margin=dict(t=10, b=5))
            st.plotly_chart(donut, use_container_width=True)
        else:
            st.info("Events appear here as the system is used.")

    st.subheader("Live alert timeline")
    refresh = st.toggle("Auto-refresh view", value=False)
    if refresh:
        st_autorefresh(interval=15_000, limit=None, key="soc_auto_refresh")
    if events:
        event_counts: dict[str, int] = {}
        for event in events:
            event_type = str(event["event_type"])
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        counts = [
            {"event_type": event_type, "size": count}
            for event_type, count in sorted(
                event_counts.items(), key=lambda item: item[1], reverse=True
            )[:12]
        ]
        chart = px.bar(counts, x="event_type", y="size", color="size", color_continuous_scale=["#00f0ff", "#39d353"])
        chart.update_layout(height=260, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0", xaxis_title="Event type", yaxis_title="Count")
        st.plotly_chart(chart, use_container_width=True)
        for event in events[:12]:
            severity = str(event["severity"]).lower()
            css_class = "alert-critical" if severity == "critical" else ("alert-high" if severity in {"high", "medium"} else "")
            st.markdown(
                f'<div class="alert-card {css_class}"><b>{html.escape(str(event["severity"]))}</b> · '
                f'{html.escape(str(event["event_type"]))} · {html.escape(str(event["user_id"]))} · '
                f'{html.escape(str(event["timestamp"]))}<br>{html.escape(str(event["details"]))}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("No audit events have been recorded.")
    if not chain_ok:
        st.error(f"Audit-chain integrity check failed at row {broken_id}.")

    if events:
        csv_buffer = StringIO()
        fieldnames = list(events[0].keys())
        writer = csv.DictWriter(
            csv_buffer,
            fieldnames=fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(events)
        csv_data = csv_buffer.getvalue().encode("utf-8")
        st.download_button("Export incident report (CSV)", csv_data, "cryptoshield_incidents.csv", "text/csv")
    if st.button("Prepare incident report (PDF)"):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = [Paragraph("CRYPTOSHIELD SOC Incident Report", styles["Title"]), Spacer(1, 12)]
            report_rows = [["Time", "Severity", "Event", "Identity", "Details"]]
            report_rows.extend(
                [
                    str(row[key])[:250]
                    for key in ("timestamp", "severity", "event_type", "user_id", "details")
                ]
                for row in events
            )
            table = Table(report_rows, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#15354a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)
            doc.build(story)
            st.download_button("Download incident report (PDF)", buffer.getvalue(), "cryptoshield_incidents.pdf", "application/pdf")
        except ImportError as exc:
            st.error(f"PDF reporting dependency is unavailable: {exc}")


if page == "Overview & Telemetry":
    st.title("Overview & Telemetry")
    _render_dashboard()

elif page == "Secure Messenger":
    st.title("Secure Messenger")
    compose_tab, inbox_tab = st.tabs(["Compose & transmit", "Persistent inbox"])
    with compose_tab:
        if not other_users:
            st.info("Create another local identity to exchange encrypted packets.")
        else:
            recipient = st.selectbox("Recipient identity", other_users, format_func=lambda value: value.title())
            mode = st.radio(
                "Key agreement",
                ["RSA key transport", "X25519 forward secrecy"],
                horizontal=True,
            )
            message = st.text_area("Plaintext", placeholder="Write a message to encrypt…", height=120)
            password = st.text_input("Confirm signing-key password", type="password", key="send_password")
            progress = st.progress(0, text="Ready to encrypt")
            if st.button("Encrypt & transmit", type="primary", disabled=not message.strip()):
                try:
                    with st.status("Building authenticated packet…", expanded=True) as status:
                        progress.progress(20, text="Checking contact pin and active signing key")
                        packet, visualizer = _packet_build(user_id, recipient, message, password, mode)
                        progress.progress(100, text="Packet stored in SQLite")
                        status.update(label="Packet encrypted and signed", state="complete")
                    st.session_state["last_visualizer"] = visualizer
                    st.success(f"Packet {packet['message_id']} delivered to {recipient.title()}.")
                    st.json(packet)
                    st.toast("Encrypted packet persisted.", icon="🔐")
                except (ValueError, PermissionError, OSError) as exc:
                    progress.empty()
                    st.error(str(exc))
        visualizer = st.session_state.get("last_visualizer")
        if visualizer:
            with st.expander("Encryption visualizer · real values", expanded=True):
                st.write("**Plaintext**")
                st.code(visualizer["plaintext"], language="text")
                st.write("**AES-256 session key (shown only in this authenticated session; never persisted)**")
                st.code(visualizer["session_key"], language="text")
                if visualizer["mode"] == "X25519 forward secrecy":
                    st.info("Leak demonstration: this packet has no RSA-wrapped session key. A leaked long-term RSA private key cannot decrypt it; after the recipient consumes the one-time X25519 prekey, its private material is erased.")
                st.write("**AAD**")
                st.code(visualizer["aad"], language="text")
                st.write("**Ciphertext + GCM tag**")
                st.code(visualizer["ciphertext"], language="text")
                st.write("**Signature (RSA-PSS-SHA256)**")
                st.code(visualizer["signature"], language="text")
                _render_packet_inspector(visualizer["packet"])

    with inbox_tab:
        inbox = database.list_packets(user_id, "inbox")
        if not inbox:
            st.info("No packets addressed to this identity yet. Messages are persisted in SQLite.")
        else:
            options = [packet["message_id"] for packet in inbox]
            selected_id = st.selectbox(
                "Select any historical inbox packet",
                options,
                format_func=lambda mid: next(
                    f"{packet['sender_id'].title()} · {packet['timestamp']} · {mid[:12]}"
                    for packet in inbox
                    if packet["message_id"] == mid
                ),
            )
            packet = next(item for item in inbox if item["message_id"] == selected_id)
            st.caption(f"From **{packet['sender_id'].title()}** · {packet['timestamp']} · {packet['crypto_suite']['mode']}")
            with st.expander("Packet inspector"):
                _render_packet_inspector(packet)
            password = st.text_input("Confirm decryption-key password", type="password", key="receive_password")
            if st.button("Verify & decrypt selected packet", type="primary"):
                try:
                    if not PacketManager.validate_crypto_suite(packet):
                        raise PermissionError("Unsupported or downgraded cryptographic suite; packet rejected.")
                    ReplayGuard(database).validate(packet)
                    sign_fp = packet["fingerprints"]["sender_signing"]
                    sign_record = database.get_key_record(sign_fp)
                    if not sign_record or sign_record["status"] != "ACTIVE" or sign_record["key_type"] != "sign":
                        raise PermissionError("Sender signing key is unknown or revoked; packet rejected.")
                    if sign_record["user_id"] != packet["sender_id"]:
                        raise PermissionError("Signing fingerprint is not registered to the claimed sender.")
                    sender_public = serialization.load_pem_public_key(sign_record["public_key_pem"].encode("ascii"))
                    recipient_enc_fp = packet["fingerprints"]["recipient_encryption"]
                    if recipient_enc_fp != compute_key_fingerprint(vault.load_public_key(user_id, "enc")):
                        raise PermissionError("Packet targets a different or rotated recipient key.")
                    sender_enc_record = next(
                        (
                            record for record in database.list_key_records(packet["sender_id"])
                            if record["key_type"] == "enc"
                            and record["status"] == "ACTIVE"
                            and record["fingerprint"] == packet["fingerprints"].get("sender_encryption")
                        ),
                        None,
                    )
                    if sender_enc_record is None:
                        raise PermissionError("Sender encryption key is not active in the key registry.")
                    sender_enc = serialization.load_pem_public_key(sender_enc_record["public_key_pem"].encode("ascii"))
                    pin_ok, pin_message = tofu.verify_or_pin(
                        user_id, packet["sender_id"], sender_public, sender_enc
                    )
                    if not pin_ok:
                        database.log_event("TOFU_SUBSTITUTION_BLOCKED", "CRITICAL", user_id, pin_message)
                        raise PermissionError(pin_message)
                    if pin_message.startswith("First contact"):
                        database.log_event("TOFU_PINNED", "INFO", user_id, f"Initial fingerprints pinned for {packet['sender_id']}.")
                    signature_payload = create_signature_payload(
                        packet["sender_id"],
                        packet["recipient_id"],
                        packet["timestamp"],
                        bytes.fromhex(packet["payload"]["ciphertext_hex"]),
                        packet["message_id"],
                        PacketManager.signature_context(packet),
                    )
                    signature_result = verify_signature(
                        signature_payload,
                        bytes.fromhex(packet["authentication"]["signature_hex"]),
                        sender_public,
                    )
                    if not signature_result["valid"]:
                        raise PermissionError(signature_result["message"])
                    mode = packet["crypto_suite"]["mode"]
                    payload = packet["payload"]
                    if mode == "RSA key transport":
                        recipient_private = vault.load_private_key(user_id, "enc", password)
                        plaintext_bytes = decrypt_hybrid(
                            bytes.fromhex(payload["wrapped_key_hex"]),
                            bytes.fromhex(payload["nonce_hex"]),
                            bytes.fromhex(payload["ciphertext_hex"]),
                            recipient_private,
                            packet["sender_id"],
                            packet["recipient_id"],
                            packet["message_id"],
                            packet["timestamp"],
                        )
                    elif mode == "X25519 forward secrecy":
                        vault.load_private_key(user_id, "enc", password)
                        encrypted_prekey = database.consume_prekey(payload["prekey_id"], user_id)
                        if encrypted_prekey is None:
                            raise ReplayAttackException("One-time X25519 prekey was already consumed or revoked.")
                        prekey_private = vault.unlock_prekey(encrypted_prekey, password)
                        plaintext_bytes = decrypt_forward_secret(
                            bytes.fromhex(payload["nonce_hex"]),
                            bytes.fromhex(payload["ciphertext_hex"]),
                            bytes.fromhex(payload["ephemeral_public_key_hex"]),
                            prekey_private,
                            packet["sender_id"],
                            packet["recipient_id"],
                            packet["message_id"],
                            packet["timestamp"],
                        )
                    else:
                        raise PermissionError("Unsupported cryptographic suite; downgrade rejected.")
                    if not database.mark_message_seen(
                        packet["message_id"], packet["sender_id"], packet["recipient_id"], packet["timestamp"]
                    ):
                        raise ReplayAttackException("Duplicate message ID: replay rejected.")
                    plaintext = plaintext_bytes.decode("utf-8")
                    st.session_state.setdefault("decrypted_messages", {})[packet["message_id"]] = plaintext
                    database.log_event("MESSAGE_DECRYPTED", "INFO", user_id, f"Verified packet from {packet['sender_id']}.")
                    st.success("✓ RSA-PSS signature verified · ✓ AES-GCM AAD verified")
                    st.markdown(f'<div class="bubble"><b>{html.escape(packet["sender_id"].title())}</b><br>{html.escape(plaintext)}</div>', unsafe_allow_html=True)
                    with st.expander("Verification details"):
                        st.write("**RSA-PSS-SHA256:** valid, signer fingerprint is active and registered to the sender.")
                        st.write("**AES-256-GCM:** valid, sender / recipient / message ID / timestamp authenticated as AAD.")
                        st.write(f"**TOFU:** {pin_message}")
                        st.write("**Replay:** timestamp is fresh and message ID has been atomically marked seen.")
                    st.toast("Message authenticated and decrypted.", icon="✅")
                except (ValueError, PermissionError, OSError, KeyError, TypeError, InvalidTag, ReplayAttackException) as exc:
                    database.log_event("MESSAGE_REJECTED", "HIGH", user_id, str(exc))
                    st.error(f"Packet rejected: {exc}")
            for previous in inbox:
                body = st.session_state.get("decrypted_messages", {}).get(previous["message_id"])
                if body is not None and previous["message_id"] != selected_id:
                    st.markdown(
                        f'<div class="bubble"><span class="verified">✓ Verified</span> · '
                        f'{html.escape(previous["sender_id"].title())}<br>{html.escape(body)}</div>',
                        unsafe_allow_html=True,
                    )

elif page == "Key Vault & Lifecycle":
    st.title("Key Vault & Lifecycle")
    st.warning("Private key material is never displayed. Keep your identity password private.")
    current_keys = []
    for key_type, algorithm in (
        ("enc", "RSA-2048-OAEP-SHA256"),
        ("sign", "RSA-2048-PSS-SHA256"),
        ("x25519", "X25519"),
    ):
        public_key = vault.load_public_key(user_id, key_type)
        fingerprint = compute_key_fingerprint(public_key)
        record = database.get_key_record(fingerprint)
        current_keys.append({"Key type": key_type, "Algorithm": algorithm, "Fingerprint": fingerprint, "Status": record["status"] if record else "UNREGISTERED"})
    st.dataframe(current_keys, use_container_width=True, hide_index=True)
    sign_fp = compute_key_fingerprint(vault.load_public_key(user_id, "sign"))
    st.subheader("Public signing-key fingerprint")
    st.code(sign_fp)
    qr_png = fingerprint_qr_png(sign_fp)
    if qr_png:
        st.image(qr_png, caption="Scan out-of-band to verify this fingerprint")
    else:
        st.info("QR code unavailable: install the optional qrcode package.")
    st.subheader("Private-key protection parameters")
    st.dataframe([SCRYPT_PARAMETERS], use_container_width=True, hide_index=True)
    st.caption("RSA and X25519 private-key files contain PKCS#8 material encrypted with AES-GCM under a Scrypt-derived key.")
    st.subheader("Key records")
    records = database.list_key_records(user_id)
    if records:
        st.dataframe([{key: row[key] for key in ("fingerprint", "key_type", "algorithm", "created_at", "status", "revoked_at", "revocation_reason")} for row in records], use_container_width=True, hide_index=True)
    with st.expander("Rotate active key"):
        key_to_rotate = st.selectbox("Key type", ["enc", "sign"])
        password = st.text_input("Confirm identity password", type="password", key="rotate_password")
        if st.button("Rotate key and revoke previous fingerprint"):
            try:
                new_fp = rotation.rotate(user_id, key_to_rotate, password)
                st.success(f"Rotation complete. New active fingerprint: {new_fp}")
                st.rerun()
            except (ValueError, OSError) as exc:
                st.error(str(exc))
    with st.expander("Revoke a key"):
        active = [row for row in records if row["status"] == "ACTIVE"]
        if active:
            selected = st.selectbox("Active key fingerprint", [row["fingerprint"] for row in active])
            reason = st.text_input("Revocation reason", value="Manual security response")
            if st.button("Revoke selected key"):
                if rotation.revoke(selected, reason):
                    st.success("Key marked revoked; signatures from it will be rejected.")
                    st.rerun()
                else:
                    st.error("The selected key was not active.")
    with st.expander("TOFU contact pins"):
        contacts = [item for item in other_users if vault.user_exists(item)]
        if contacts:
            contact = st.selectbox("Contact to re-pin after out-of-band verification", contacts)
            verified = st.checkbox("I verified the contact fingerprint through a trusted channel")
            if st.button("Update TOFU pin", disabled=not verified):
                sign_key = vault.load_public_key(contact, "sign")
                enc_key = vault.load_public_key(contact, "enc")
                database.update_tofu_pin(user_id, contact, compute_key_fingerprint(sign_key), compute_key_fingerprint(enc_key))
                database.log_event("TOFU_PIN_UPDATED", "MEDIUM", user_id, f"Manual re-pin for {contact}.")
                st.success("TOFU pin updated.")
    pqc = pqc_status()
    st.info(pqc["message"])

elif page == "Digital Signatures":
    st.title("Digital Signatures Studio")
    sign_tab, verify_tab = st.tabs(["Sign document", "Verify signature"])
    with sign_tab:
        document = st.text_area("Document or message", placeholder="Enter text to sign…", key="sign_document")
        password = st.text_input("Confirm signing-key password", type="password", key="document_sign_password")
        if st.button("Sign with my RSA-PSS key", disabled=not document):
            try:
                fp = compute_key_fingerprint(vault.load_public_key(user_id, "sign"))
                record = database.get_key_record(fp)
                if not record or record["status"] != "ACTIVE":
                    raise PermissionError("Your signing key is revoked.")
                signature = sign_message(document.encode("utf-8"), vault.load_private_key(user_id, "sign", password))
                st.session_state["standalone_signature"] = {
                    "document": document,
                    "signature_hex": signature.hex(),
                    "fingerprint": fp,
                }
                st.success("Document signed using RSA-PSS-SHA256.")
                st.code(signature.hex(), language="text")
            except (ValueError, PermissionError, OSError) as exc:
                st.error(str(exc))
    with verify_tab:
        saved = st.session_state.get("standalone_signature")
        verify_document = st.text_area("Document", value=saved["document"] if saved else "", key="verify_document")
        signature_text = st.text_area("Signature (hex)", value=saved["signature_hex"] if saved else "", key="verify_signature")
        fingerprint = st.text_input("Signer fingerprint", value=saved["fingerprint"] if saved else "")
        if st.button("Verify RSA-PSS signature"):
            try:
                record = database.get_key_record(fingerprint)
                if not record or record["status"] != "ACTIVE" or record["key_type"] != "sign":
                    raise PermissionError("Signer fingerprint is unknown or revoked.")
                public_key = serialization.load_pem_public_key(record["public_key_pem"].encode("ascii"))
                result = verify_signature(verify_document.encode("utf-8"), bytes.fromhex(signature_text), public_key)
                st.success(result["message"]) if result["valid"] else st.error(result["message"])
            except (ValueError, PermissionError) as exc:
                st.error(str(exc))

elif page == "File Encryption Vault":
    st.title("File Encryption Vault")
    st.caption("Files are encrypted in 64 KiB AES-256-GCM chunks. Each chunk has an index-bound AAD and sequential nonce.")
    encrypt_tab, decrypt_tab = st.tabs(["Encrypt file", "Decrypt & verify"])
    with encrypt_tab:
        uploaded = st.file_uploader("Choose a file", key="file_upload")
        password = st.text_input("Confirm signing-key password", type="password", key="file_sign_password")
        if uploaded is not None:
            if uploaded.size > 25 * 1024 * 1024:
                st.error("Maximum demo upload size is 25 MiB.")
            elif st.button("Encrypt, sign, and package file"):
                try:
                    sign_fp = compute_key_fingerprint(vault.load_public_key(user_id, "sign"))
                    sign_record = database.get_key_record(sign_fp)
                    if not sign_record or sign_record["status"] != "ACTIVE":
                        raise PermissionError("Your signing key is revoked or missing.")
                    package = encrypt_file(
                        uploaded.getvalue(),
                        uploaded.name,
                        vault.load_public_key(user_id, "enc"),
                        vault.load_private_key(user_id, "sign", password),
                        sign_fp,
                    )
                    st.session_state["file_package"] = package
                    st.success(f"Encrypted {package['chunk_count']} authenticated chunk(s).")
                    st.download_button(
                        "Download .shield.json package",
                        json.dumps(package, indent=2).encode("utf-8"),
                        f"{uploaded.name}.shield.json",
                        "application/json",
                    )
                except (ValueError, PermissionError, OSError) as exc:
                    st.error(str(exc))
    with decrypt_tab:
        encrypted_upload = st.file_uploader("Upload .shield.json package", type=["json"], key="encrypted_upload")
        password = st.text_input("Confirm decryption-key password", type="password", key="file_decrypt_password")
        if encrypted_upload and encrypted_upload.size > 60 * 1024 * 1024:
            st.error("Encrypted package exceeds the 60 MiB demo limit.")
        elif encrypted_upload and st.button("Verify and restore file"):
            try:
                package = json.loads(encrypted_upload.getvalue().decode("utf-8"))
                signer_record = database.get_key_record(package["signer_fingerprint"])
                if not signer_record or signer_record["status"] != "ACTIVE" or signer_record["key_type"] != "sign":
                    raise PermissionError("Package signer key is unknown or revoked.")
                signer_public = serialization.load_pem_public_key(signer_record["public_key_pem"].encode("ascii"))
                recipient_private = vault.load_private_key(user_id, "enc", password)
                filename, restored = decrypt_file(package, recipient_private, signer_public)
                st.success("Signature, chunk order, authentication tags, and file digest verified.")
                st.download_button("Download restored file", restored, filename, "application/octet-stream")
            except (ValueError, KeyError, TypeError, PermissionError, OSError, InvalidTag, json.JSONDecodeError) as exc:
                st.error(f"File package rejected: {exc}")

elif page == "Attack Simulation Lab":
    st.title("Attack Simulation Lab")
    st.warning("Educational local simulations only. No external targets or network traffic are used.")
    description = st.selectbox("Scenario", [item["id"] for item in ATTACKS], format_func=lambda attack_id: next(item["name"] for item in ATTACKS if item["id"] == attack_id))
    attack = next(item for item in ATTACKS if item["id"] == description)
    st.write(attack["description"])
    for step in attack["steps"]:
        st.markdown(f"- {step}")
    password = st.text_input("Confirm signing-key password for the lab packet", type="password", key="lab_password")
    run_one = st.button("Run selected simulation", type="primary")
    run_all = st.button("Run all simulations")
    if run_one or run_all:
        try:
            signer_fingerprint = compute_key_fingerprint(vault.load_public_key(user_id, "sign"))
            signer_record = database.get_key_record(signer_fingerprint)
            if not signer_record or signer_record["status"] != "ACTIVE":
                raise PermissionError("Your signing key is revoked or missing.")
            sender_sign = vault.load_private_key(user_id, "sign", password)
            sender_public = vault.load_public_key(user_id, "sign")
            sender_enc = vault.load_public_key(user_id, "enc")
            demo_message_id = str(uuid.uuid4())
            demo_timestamp = datetime.now(timezone.utc).isoformat()
            demo_encrypted = encrypt_hybrid(
                b"educational SOC test packet",
                sender_enc,
                user_id,
                user_id,
                demo_message_id,
                demo_timestamp,
            )
            demo_packet = PacketManager.assemble_packet(
                user_id,
                user_id,
                demo_encrypted["enc_session_key"],
                demo_encrypted["nonce"],
                demo_encrypted["ciphertext"],
                b"",
                compute_key_fingerprint(sender_public),
                compute_key_fingerprint(sender_enc),
                compute_key_fingerprint(sender_enc),
                message_id=demo_message_id,
                timestamp=demo_timestamp,
                crypto_mode="RSA key transport",
            )
            demo_packet["authentication"]["signature_hex"] = sign_message(
                create_signature_payload(
                    user_id,
                    user_id,
                    demo_timestamp,
                    demo_encrypted["ciphertext"],
                    demo_message_id,
                    PacketManager.signature_context(demo_packet),
                ),
                sender_sign,
            ).hex()
            recipient_private = vault.load_private_key(user_id, "enc", password)
            outsider = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rogue_sign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            rogue_enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            targets = [item["id"] for item in ATTACKS] if run_all else [description]
            results = []
            progress = st.progress(0, text="Starting isolated simulations")
            for index, attack_id in enumerate(targets):
                result = SecuritySimulator.run_attack(
                    attack_id,
                    demo_packet,
                    recipient_private,
                    sender_public,
                    database,
                    user_id,
                    unrelated_private_key=outsider,
                    sender_encryption_key=sender_enc,
                    alternate_signing_key=rogue_sign.public_key(),
                    alternate_encryption_key=rogue_enc.public_key(),
                )
                results.append(result)
                progress.progress(int((index + 1) * 100 / len(targets)), text=f"Completed {result['attack']}")
            st.dataframe(
                [
                    {
                        "Attack": item["attack"],
                        "Severity": item["severity"],
                        "Result": "BLOCKED" if item["defended"] else "NOT BLOCKED",
                        "Defense": item["defense"],
                        "RSA-PSS": item["signature_valid"],
                        "AES-GCM": item["aead_valid"],
                    }
                    for item in results
                ],
                use_container_width=True,
                hide_index=True,
            )
            for result in results:
                with st.expander(f"{'🛡️ BLOCKED' if result['defended'] else '⚠️ NOT BLOCKED'} · {result['attack']} · {result['severity']}"):
                    st.write(result["description"])
                    st.write("**Execution:** " + " → ".join(result["steps"]))
                    st.write(f"**Defense:** {result['defense']}")
                    st.write(f"**RSA-PSS check:** {result['signature_valid']}")
                    st.write(f"**AES-GCM/AAD check:** {result['aead_valid']}")
                    st.write(result["details"])
            st.toast("Simulation results recorded in the audit ledger.", icon="🧪")
        except (ValueError, PermissionError, OSError) as exc:
            st.error(str(exc))

elif page == "Audit Ledger Integrity":
    st.title("Audit Ledger Integrity")
    st.caption("Every event is chained as SHA-256(previous hash | timestamp | event | severity | user | details).")
    if st.button("Verify Entire Audit Chain Integrity", type="primary"):
        valid, broken_row, count, rows = database.verify_chain()
        if valid:
            st.success(f"Integrity verified across {count} audit row(s).")
        else:
            st.error(f"Integrity verification failed at database row {broken_row} of {count}.")
            st.dataframe([row for row in rows if row["id"] == broken_row], use_container_width=True)
        database.log_event(
            "AUDIT_CHAIN_VERIFIED" if valid else "AUDIT_CHAIN_FAILURE",
            "INFO" if valid else "CRITICAL",
            user_id,
            f"Integrity verification result: {'valid' if valid else f'broken at row {broken_row}'}; rows={count}.",
        )
    audit_rows = database.get_recent_events(200)
    if audit_rows:
        st.dataframe(audit_rows, use_container_width=True, hide_index=True)

elif page == "Encryption Visualizer & Benchmark":
    st.title("Encryption Visualizer & Benchmark")
    last = st.session_state.get("last_visualizer")
    if last:
        st.write(f"Mode: **{last['mode']}**")
        st.write("**Plaintext**")
        st.code(last["plaintext"])
        st.write("**Session key (ephemeral; not stored)**")
        st.code(last["session_key"])
        if last["mode"] == "X25519 forward secrecy":
            st.info("RSA long-term keys are not used to wrap this session key. The recipient's one-time X25519 prekey is erased after successful decryption.")
        st.write("**Ciphertext**")
        st.code(last["ciphertext"])
        st.write("**Signature**")
        st.code(last["signature"])
        _render_packet_inspector(last["packet"])
    else:
        st.info("Send a message from Secure Messenger to populate the live visualizer.")
    st.subheader("Local encryption timing benchmark")
    bench_password = st.text_input("Confirm key password", type="password", key="bench_password")
    if st.button("Run benchmark (single local sample)"):
        try:
            sample = b"CRYPTOSHIELD timing sample " * 3
            public = vault.load_public_key(user_id, "enc")
            private = vault.load_private_key(user_id, "enc", bench_password)
            start = time.perf_counter()
            public.encrypt(sample, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            rsa_ms = (time.perf_counter() - start) * 1000
            start = time.perf_counter()
            bench_id = str(uuid.uuid4())
            bench_timestamp = datetime.now(timezone.utc).isoformat()
            hybrid = encrypt_hybrid(sample, public, user_id, user_id, bench_id, bench_timestamp)
            decrypt_hybrid(
                hybrid["enc_session_key"], hybrid["nonce"], hybrid["ciphertext"], private,
                user_id, user_id, bench_id, bench_timestamp,
            )
            hybrid_ms = (time.perf_counter() - start) * 1000
            st.warning("RSA-only timing measures public-key encryption for a small message. Hybrid timing includes AES-GCM and OAEP setup; compare only as a local illustrative sample.")
            rows = [
                {"Mode": "RSA-only", "Milliseconds": rsa_ms},
                {"Mode": "AES-GCM + RSA-OAEP hybrid", "Milliseconds": hybrid_ms},
            ]
            prekeys = database.get_active_prekeys(user_id)
            if prekeys:
                start = time.perf_counter()
                encrypt_forward_secret(
                    sample,
                    prekeys[0]["public_key_pem"],
                    user_id,
                    user_id,
                    str(uuid.uuid4()),
                    datetime.now(timezone.utc).isoformat(),
                    prekeys[0]["prekey_id"],
                )
                rows.append({"Mode": "X25519 forward secrecy", "Milliseconds": (time.perf_counter() - start) * 1000})
            st.plotly_chart(px.bar(rows, x="Mode", y="Milliseconds", color="Mode"), use_container_width=True)
        except (ValueError, OSError) as exc:
            st.error(str(exc))

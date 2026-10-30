from __future__ import annotations

from io import BytesIO


def fingerprint_qr_png(fingerprint: str) -> bytes | None:
    try:
        import qrcode
    except ImportError:
        return None
    image = qrcode.make(fingerprint)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()

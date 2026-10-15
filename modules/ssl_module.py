
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

TIMEOUT = 6


def _decode_name(name: "x509.Name", oid):
    try:
        attrs = name.get_attributes_for_oid(oid)
    except Exception:
        return None
    return attrs[0].value if attrs else None


def _get_cert_der(hostname: str):
    """Complete a TLS handshake without verifying trust, and return the
    raw DER certificate bytes plus the negotiated protocol version.
    This succeeds as long as the server speaks TLS on port 443,
    regardless of whether the certificate is expired, self-signed,
    hostname-mismatched, or otherwise untrusted."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            protocol_version = tls_sock.version()
    return der_cert, protocol_version


def _check_trust(hostname: str):
    """Separately attempt a verified handshake purely to determine
    whether the certificate is trusted by a standard trust store, and
    if not, capture why."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                pass
        return True, None
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", None) or str(exc)
        return False, reason
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return False, str(exc)


def assess(hostname: str) -> dict:

    evidence = {
        "module": "ssl",
        "certificate_found": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "is_expired": None,
        "is_self_signed": None,
        "trust_verified": None,
        "verification_error": None,
        "protocol_version": None,
        "error": None,
    }

    # Step 1: retrieve the certificate itself, independent of trust status.
    try:
        der_cert, protocol_version = _get_cert_der(hostname)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        evidence["error"] = "Unable to establish a TLS connection on port 443."
        return evidence
    except ssl.SSLError as exc:
        # Handshake itself failed for a non-certificate reason (e.g. no
        # TLS on that port, protocol mismatch).
        evidence["error"] = f"TLS handshake failed: {exc}"
        return evidence

    if not der_cert:
        evidence["error"] = "No certificate was presented."
        return evidence

    evidence["certificate_found"] = True
    evidence["protocol_version"] = protocol_version

    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
    except Exception as exc:
        evidence["error"] = f"Certificate could not be parsed: {exc}"
        evidence["certificate_found"] = False
        return evidence

    issuer_org = _decode_name(cert.issuer, x509.oid.NameOID.ORGANIZATION_NAME)
    issuer_cn = _decode_name(cert.issuer, x509.oid.NameOID.COMMON_NAME)
    subject_org = _decode_name(cert.subject, x509.oid.NameOID.ORGANIZATION_NAME)
    subject_cn = _decode_name(cert.subject, x509.oid.NameOID.COMMON_NAME)

    evidence["issuer"] = issuer_org or issuer_cn
    evidence["subject"] = subject_cn

    try:
        # cryptography >= 42 exposes timezone-aware accessors directly.
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older cryptography versions (naive datetimes).
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    evidence["valid_from"] = not_before.strftime("%b %d %H:%M:%S %Y GMT")
    evidence["valid_until"] = not_after.strftime("%b %d %H:%M:%S %Y GMT")

    now = datetime.now(timezone.utc)
    delta = not_after - now
    evidence["days_remaining"] = delta.days
    evidence["is_expired"] = delta.total_seconds() < 0

    evidence["is_self_signed"] = bool(
        issuer_cn is not None
        and issuer_cn == subject_cn
        and issuer_org == subject_org
    )

    # Step 2: separately determine trust status / reason for distrust.
    # Failure here should never wipe out the certificate data we already
    # gathered above.
    try:
        trusted, reason = _check_trust(hostname)
    except Exception as exc:
        trusted, reason = False, f"Trust check failed: {exc}"

    evidence["trust_verified"] = trusted
    evidence["verification_error"] = reason

    return evidence

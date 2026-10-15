
POINTS = {
    "https_enabled": 20,
    "valid_ssl_certificate": 20,
    "hsts": 10,
    "csp": 15,
    "x_frame_options": 10,
    "x_content_type_options": 10,
    "referrer_policy": 10,
    "permissions_policy": 5,
}

MAX_SCORE = sum(POINTS.values())  # 100


def _rating_for(total: int) -> str:
    if total >= 80:
        return "Secure"
    if total >= 60:
        return "Moderate"
    return "Needs Improvement"


def calculate_score(evidence: dict) -> dict:

    breakdown = []
    total = 0

    https_evidence = evidence.get("https", {})
    https_ok = bool(https_evidence.get("https_available"))
    points = POINTS["https_enabled"] if https_ok else 0
    total += points
    if https_ok and https_evidence.get("certificate_trusted") is False:
        https_reason = (
            "HTTPS connection was established, but the presented "
            "certificate is not trusted by a standard trust store."
        )
    elif https_ok:
        https_reason = "HTTPS connection was successfully established."
    else:
        https_reason = "The website did not respond over HTTPS on port 443."
    breakdown.append({
        "key": "https_enabled",
        "label": "HTTPS Enabled",
        "points_awarded": points,
        "points_possible": POINTS["https_enabled"],
        "reason": https_reason,
    })

    ssl_evidence = evidence.get("ssl", {})
    cert_found = bool(ssl_evidence.get("certificate_found"))
    is_expired = ssl_evidence.get("is_expired")
    trust_verified = bool(ssl_evidence.get("trust_verified"))
    # A certificate only counts as "valid" for scoring purposes if it was
    # found, is not expired, AND is trusted by a standard trust store.
    # This ensures self-signed / untrusted-CA certs correctly score 0
    # instead of passing just because they haven't expired.
    ssl_valid = cert_found and is_expired is False and trust_verified
    points = POINTS["valid_ssl_certificate"] if ssl_valid else 0
    total += points

    if not cert_found:
        reason = "No valid TLS certificate could be retrieved."
    elif is_expired:
        reason = "The TLS certificate has expired."
    elif not trust_verified:
        detail = ssl_evidence.get("verification_error") or "verification failed"
        reason = f"The certificate is not trusted by browsers ({detail})."
    else:
        reason = f"A valid, trusted certificate was found, issued by {ssl_evidence.get('issuer') or 'an unspecified authority'}."
    breakdown.append({
        "key": "valid_ssl_certificate",
        "label": "Valid SSL Certificate",
        "points_awarded": points,
        "points_possible": POINTS["valid_ssl_certificate"],
        "reason": reason,
    })

    headers_evidence = evidence.get("headers", {}).get("headers", {})
    header_score_map = [
        ("hsts", "hsts", "Strict-Transport-Security"),
        ("csp", "csp", "Content-Security-Policy"),
        ("x_frame_options", "x_frame_options", "X-Frame-Options"),
        ("x_content_type_options", "x_content_type_options", "X-Content-Type-Options"),
        ("referrer_policy", "referrer_policy", "Referrer-Policy"),
        ("permissions_policy", "permissions_policy", "Permissions-Policy"),
    ]

    for points_key, evidence_key, header_name in header_score_map:
        present = bool(headers_evidence.get(evidence_key, {}).get("present"))
        points = POINTS[points_key] if present else 0
        total += points
        breakdown.append({
            "key": points_key,
            "label": header_name,
            "points_awarded": points,
            "points_possible": POINTS[points_key],
            "reason": (
                f"{header_name} header was detected in the response."
                if present else
                f"{header_name} header was not detected in the response."
            ),
        })

    return {
        "total": total,
        "max": MAX_SCORE,
        "rating": _rating_for(total),
        "breakdown": breakdown,
    }

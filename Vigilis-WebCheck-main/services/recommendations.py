
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def generate(evidence: dict) -> list:

    findings = []

    https_evidence = evidence.get("https", {})
    if not https_evidence.get("https_available"):
        findings.append({
            "finding": "HTTPS is not enabled",
            "risk": "Traffic between users and the website may be intercepted or modified in transit.",
            "severity": "High",
            "recommendation": "Enable HTTPS using a valid SSL/TLS certificate from a trusted certificate authority.",
        })
    elif https_evidence.get("http_available") and not https_evidence.get("http_redirects_to_https"):
        findings.append({
            "finding": "HTTP does not redirect to HTTPS",
            "risk": "Users who type the address without 'https://' remain on an unencrypted connection.",
            "severity": "Medium",
            "recommendation": "Configure the web server to redirect all HTTP requests to HTTPS.",
        })

    ssl_evidence = evidence.get("ssl", {})
    if not ssl_evidence.get("certificate_found"):
        findings.append({
            "finding": "No valid TLS certificate could be retrieved",
            "risk": "Browsers may warn or block users, and encrypted communication cannot be guaranteed.",
            "severity": "High",
            "recommendation": "Install a valid certificate from a trusted certificate authority, such as Let's Encrypt.",
        })
    else:
        if ssl_evidence.get("is_expired"):
            findings.append({
                "finding": "TLS certificate has expired",
                "risk": "Browsers will display security warnings, undermining user trust.",
                "severity": "High",
                "recommendation": "Renew the TLS certificate immediately.",
            })
        else:
            days_remaining = ssl_evidence.get("days_remaining")
            if isinstance(days_remaining, int) and 0 <= days_remaining <= 30:
                findings.append({
                    "finding": f"TLS certificate expires in {days_remaining} day(s)",
                    "risk": "An expiring certificate will soon cause browser security warnings.",
                    "severity": "Medium",
                    "recommendation": "Renew the certificate before it expires, and consider enabling automatic renewal.",
                })

        if ssl_evidence.get("is_self_signed"):
            findings.append({
                "finding": "Certificate appears to be self-signed",
                "risk": "Self-signed certificates are not trusted by browsers by default.",
                "severity": "Medium",
                "recommendation": "Replace the self-signed certificate with one issued by a trusted certificate authority.",
            })
        elif (
            not ssl_evidence.get("is_expired")
            and ssl_evidence.get("trust_verified") is False
        ):
            # Untrusted for a reason other than being self-signed --
            # e.g. issued by an unknown/private CA, incomplete chain,
            # or a hostname mismatch.
            detail = ssl_evidence.get("verification_error")
            findings.append({
                "finding": "Certificate is not trusted by browsers",
                "risk": "Browsers will display security warnings, undermining user trust, even though the certificate has not expired.",
                "severity": "Medium",
                "recommendation": (
                    "Investigate why the certificate fails verification"
                    + (f" ({detail})" if detail else "")
                    + " and replace it with one issued by a publicly trusted certificate authority."
                ),
            })

    header_findings = {
        "csp": (
            "Content-Security-Policy header is missing",
            "The site is more exposed to Cross-Site Scripting (XSS) attacks.",
            "High",
            "Implement a strict Content-Security-Policy header limiting allowed content sources.",
        ),
        "hsts": (
            "Strict-Transport-Security header is missing",
            "Browsers are not instructed to always use HTTPS for this site, permitting downgrade attacks.",
            "Medium",
            "Add a Strict-Transport-Security header with an appropriate max-age directive.",
        ),
        "x_frame_options": (
            "X-Frame-Options header is missing",
            "The site may be embedded in a hidden frame, enabling clickjacking attacks.",
            "Medium",
            "Add an X-Frame-Options header set to DENY or SAMEORIGIN.",
        ),
        "x_content_type_options": (
            "X-Content-Type-Options header is missing",
            "Browsers may MIME-sniff responses, potentially executing unintended content.",
            "Low",
            "Add an X-Content-Type-Options header set to nosniff.",
        ),
        "referrer_policy": (
            "Referrer-Policy header is missing",
            "Full URLs, including potentially sensitive query parameters, may leak to third parties.",
            "Low",
            "Add a Referrer-Policy header, such as strict-origin-when-cross-origin.",
        ),
        "permissions_policy": (
            "Permissions-Policy header is missing",
            "Browser features such as camera or geolocation are not explicitly restricted.",
            "Low",
            "Add a Permissions-Policy header restricting unused browser features.",
        ),
    }

    headers_evidence = evidence.get("headers", {}).get("headers", {})
    for key, (finding, risk, severity, recommendation) in header_findings.items():
        header_info = headers_evidence.get(key, {})
        if not header_info.get("present"):
            findings.append({
                "finding": finding,
                "risk": risk,
                "severity": severity,
                "recommendation": recommendation,
            })

    if not findings:
        findings.append({
            "finding": "No significant issues detected",
            "risk": "None identified by this assessment.",
            "severity": "Low",
            "recommendation": "Continue monitoring the website's security configuration and certificate expiry over time.",
        })

    findings.sort(key=lambda item: SEVERITY_ORDER.get(item["severity"], 99))
    return findings

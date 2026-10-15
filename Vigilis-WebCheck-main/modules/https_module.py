
import requests
import urllib3

# We deliberately retry with verify=False when a verified HTTPS request
# fails on a certificate error, purely to determine whether HTTPS is
# genuinely being served (e.g. with an expired or self-signed cert).
# We already surface that untrusted status explicitly via
# `certificate_trusted`, so silence the redundant urllib3 warning noise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 6


def assess(hostname: str) -> dict:

    evidence = {
        "module": "https",
        "https_available": False,
        "http_available": False,
        "http_redirects_to_https": False,
        "certificate_trusted": None,
        "final_url": None,
        "error": None,
    }

    try:
        https_response = requests.get(
            f"https://{hostname}",
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "VIGILIS-SecurityAssessment/1.0"},
        )
        evidence["https_available"] = True
        evidence["certificate_trusted"] = True
        evidence["final_url"] = https_response.url
    except requests.exceptions.SSLError:
        # The certificate failed verification, but the server may still
        # be genuinely serving HTTPS (e.g. expired or self-signed cert).
        # Retry without verification so we don't misreport a live HTTPS
        # endpoint as unavailable -- ssl_module is the source of truth
        # for *why* the certificate is untrusted.
        try:
            https_response = requests.get(
                f"https://{hostname}",
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "VIGILIS-SecurityAssessment/1.0"},
            )
            evidence["https_available"] = True
            evidence["certificate_trusted"] = False
            evidence["final_url"] = https_response.url
        except requests.exceptions.RequestException:
            evidence["https_available"] = False
            evidence["error"] = "TLS handshake failed."
    except requests.exceptions.RequestException:
        evidence["https_available"] = False

    try:
        http_response = requests.get(
            f"http://{hostname}",
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "VIGILIS-SecurityAssessment/1.0"},
        )
        evidence["http_available"] = True
        if http_response.url.startswith("https://"):
            evidence["http_redirects_to_https"] = True
    except requests.exceptions.RequestException:
        evidence["http_available"] = False

    if not evidence["https_available"] and not evidence["http_available"]:
        evidence["error"] = "The website could not be reached."

    return evidence

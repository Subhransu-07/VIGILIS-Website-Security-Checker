
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 6


CHECKED_HEADERS = [
    {
        "key": "hsts",
        "header": "Strict-Transport-Security",
        "purpose": "Forces browsers to communicate over HTTPS only.",
    },
    {
        "key": "csp",
        "header": "Content-Security-Policy",
        "purpose": "Restricts sources of executable content, reducing XSS risk.",
    },
    {
        "key": "x_frame_options",
        "header": "X-Frame-Options",
        "purpose": "Prevents the page from being embedded in a frame, mitigating clickjacking.",
    },
    {
        "key": "x_content_type_options",
        "header": "X-Content-Type-Options",
        "purpose": "Prevents browsers from MIME-sniffing responses away from the declared type.",
    },
    {
        "key": "referrer_policy",
        "header": "Referrer-Policy",
        "purpose": "Controls how much referrer information is leaked to other sites.",
    },
    {
        "key": "permissions_policy",
        "header": "Permissions-Policy",
        "purpose": "Restricts which browser features and APIs the page may use.",
    },
]


def _fetch(scheme: str, hostname: str):
    """Try a verified request first; on a certificate error, retry
    unverified so header data can still be collected from sites with
    expired/self-signed certs. Returns a Response or None."""
    try:
        return requests.get(
            f"{scheme}://{hostname}",
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "VIGILIS-SecurityAssessment/1.0"},
        )
    except requests.exceptions.SSLError:
        try:
            return requests.get(
                f"{scheme}://{hostname}",
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "VIGILIS-SecurityAssessment/1.0"},
            )
        except requests.exceptions.RequestException:
            return None
    except requests.exceptions.RequestException:
        return None


def assess(hostname: str) -> dict:

    evidence = {
        "module": "headers",
        "reachable": False,
        "headers": {},
        "raw_headers": {},
        "error": None,
    }

    response = None
    for scheme in ("https", "http"):
        response = _fetch(scheme, hostname)
        if response is not None:
            break

    if response is None:
        evidence["error"] = "The website could not be reached to inspect headers."
        for item in CHECKED_HEADERS:
            evidence["headers"][item["key"]] = {
                "present": False,
                "value": None,
                "purpose": item["purpose"],
                "header_name": item["header"],
            }
        return evidence

    evidence["reachable"] = True
    evidence["raw_headers"] = dict(response.headers)

    for item in CHECKED_HEADERS:
        header_value = response.headers.get(item["header"])
        evidence["headers"][item["key"]] = {
            "present": header_value is not None,
            "value": header_value,
            "purpose": item["purpose"],
            "header_name": item["header"],
        }

    return evidence

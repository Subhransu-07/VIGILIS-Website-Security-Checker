
from datetime import datetime, timezone

from modules import https_module, ssl_module, headers_module
from services import scoring, recommendations


def run_assessment(hostname: str) -> dict:
    
    evidence = {}

    try:
        evidence["https"] = https_module.assess(hostname)
    except Exception as exc:  
        evidence["https"] = {"module": "https", "error": f"Module failure: {exc}"}

    try:
        evidence["ssl"] = ssl_module.assess(hostname)
    except Exception as exc:
        evidence["ssl"] = {"module": "ssl", "error": f"Module failure: {exc}"}

    try:
        evidence["headers"] = headers_module.assess(hostname)
    except Exception as exc:
        evidence["headers"] = {"module": "headers", "error": f"Module failure: {exc}"}

    score = scoring.calculate_score(evidence)
    findings = recommendations.generate(evidence)

    return {
        "hostname": hostname,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "evidence": evidence,
        "score": score,
        "recommendations": findings,
    }

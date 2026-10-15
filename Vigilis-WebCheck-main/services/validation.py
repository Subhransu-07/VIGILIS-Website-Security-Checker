
import re
from urllib.parse import urlparse


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


class ValidationError(Exception):
    """Raised when user input cannot be safely processed."""


def normalize_input(raw_input: str) -> str:
    
    if raw_input is None:
        raise ValidationError("Please enter a website address.")

    candidate = raw_input.strip()

    if not candidate:
        raise ValidationError("Please enter a website address.")

    if len(candidate) > 2048:
        raise ValidationError("That address is too long to process.")

    if re.search(r"\s", candidate):
        raise ValidationError("Website addresses cannot contain spaces.")

    
    parse_target = candidate
    if "://" not in parse_target:
        parse_target = "https://" + parse_target

    parsed = urlparse(parse_target)
    hostname = parsed.hostname

    if not hostname:
        raise ValidationError(
            "Please enter a valid website address, such as example.com."
        )

    hostname = hostname.lower()

    if not _HOSTNAME_RE.match(hostname):
        raise ValidationError(
            "Please enter a valid website address, such as example.com."
        )

    
    blocked_hosts = {"localhost"}
    if hostname in blocked_hosts or hostname.startswith("127.") or hostname == "0.0.0.0":
        raise ValidationError(
            "VIGILIS assesses publicly accessible websites only."
        )

    return hostname

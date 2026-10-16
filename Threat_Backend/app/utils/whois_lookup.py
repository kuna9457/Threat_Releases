import ipaddress
import socket
import whois
from datetime import datetime

# python-whois talks to WHOIS servers over raw sockets with no timeout param
# of its own — a slow/unresponsive registrar (seen taking 13s+ on some ccTLDs)
# would otherwise block indefinitely. This caps every socket the process
# opens that doesn't set its own timeout (requests/dnspython calls elsewhere
# already pass explicit timeouts, so they're unaffected).
socket.setdefaulttimeout(8)


def _extract_host(url: str) -> str:
    host = url.split("//")[-1].split("/")[0]
    return host.split(":")[0]


def _is_bare_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_whois_info(url: str) -> dict:
    """WHOIS with retry: lookup failures are re-tried (pausing while the internet is down)."""
    from app.utils.resilient import wait_for_internet, pause
    info = {}
    for attempt in range(1, 4):
        info = _get_whois_info_once(url)
        err = info.get("error") or ""
        if not err or "No creation date" in err:
            return info
        wait_for_internet("WHOIS")
        if attempt < 3:
            pause("WHOIS", f"lookup problem ({err[:80]})", attempt, base=5, cap=20)
    return info


def _get_whois_info_once(url: str) -> dict:
    """
    Returns {"age_days": int|None, "is_ip": bool, "error": str|None}.

    - is_ip=True for a bare-IP target: WHOIS domain-age scoring doesn't apply,
      so callers must treat this source as skipped (not "Unknown"), per the
      risk methodology.
    - error is set (age_days=None) when the lookup genuinely failed/timed
      out, so callers can exclude it from risk consideration instead of
      silently treating it as a long-lived, low-risk domain.
    """
    host = _extract_host(url)

    if _is_bare_ip(host):
        return {"age_days": None, "is_ip": True, "error": None}

    try:
        w = whois.whois(host)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age = (datetime.now() - creation_date).days
            return {"age_days": age, "is_ip": False, "error": None}

        return {"age_days": None, "is_ip": False, "error": "No creation date in WHOIS record"}
    except Exception as e:
        # Some registries return their full plaintext WHOIS response (including
        # the ICANN disclaimer paragraph) as the exception message when
        # python-whois can't parse it — cap it so error handling elsewhere
        # never has to render a multi-KB blob.
        msg = str(e).strip().replace("\n", " ").replace("\r", " ")
        msg = " ".join(msg.split())
        if len(msg) > 150:
            msg = msg[:150] + "…"
        return {"age_days": None, "is_ip": False, "error": f"WHOIS lookup failed: {msg}"}


def get_domain_age(url: str):
    """
    Returns domain age in days.
    If age cannot be determined, returns a default high age (stable) for safety in this demo.

    Legacy shape kept for callers (e.g. exception_risk_engine) that expect a
    plain int; new risk scoring uses get_whois_info() instead so it can tell
    "unknown" and "bare IP" apart from a genuinely old domain.
    """
    info = get_whois_info(url)
    if info["age_days"] is not None:
        return info["age_days"]
    return 3650  # Default 10 years if unknown or bare IP

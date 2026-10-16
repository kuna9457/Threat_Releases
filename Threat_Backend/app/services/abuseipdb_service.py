import itertools
import socket
import threading
import time
import requests
from urllib.parse import urlparse
from app.config import settings
from app.utils.rate_limiter import RateLimiter
from app.utils.resilient import pause, wait_for_internet, _say


def _load_keys() -> list[str]:
    """
    ABUSEIPDB_API_KEY can hold one key or several, comma- or newline-separated
    (same as VIRUSTOTAL_API_KEY). Each key has its own daily quota and its own
    per-minute bucket; calls round-robin across the keys, and a key whose daily
    quota is used up rests until its reset while the others carry on.
    """
    raw = settings.abuseipdb_api_key or ""
    keys = [k.strip() for k in raw.replace("\n", ",").split(",")]
    return [k for k in keys if k and "your_" not in k]


_KEYS = _load_keys()
_LIMITERS = {k: RateLimiter(max_calls=settings.abuseipdb_rpm, period_seconds=60) for k in _KEYS}
_key_cycle = itertools.cycle(_KEYS) if _KEYS else None
_cycle_lock = threading.Lock()
_COOLDOWN = {}          # key -> monotonic time until which the key must not be used
_announced_until = 0.0  # so the "all keys exhausted" notice is printed once per wait, not per thread
_IP_CACHE = {}          # ip -> successful result; many URLs share one IP, so look each IP up only once


def _next_key() -> str:
    """Next key that is not resting. If every key is resting, wait for the earliest reset."""
    global _announced_until
    while True:
        with _cycle_lock:
            now = time.monotonic()
            for _ in range(len(_KEYS)):
                k = next(_key_cycle)
                if _COOLDOWN.get(k, 0) <= now:
                    return k
            wait = min(_COOLDOWN.values()) - now
            announce = _announced_until < now
            if announce:
                _announced_until = now + wait
        if announce:
            _say(f"[PAUSED] AbuseIPDB: all {len(_KEYS)} key(s) are at their limit. "
                 f"Waiting ~{wait / 60:.0f} min for the earliest reset, then continuing ...")
        time.sleep(min(max(wait, 1), 30))


def _lookup(ip: str):
    """One AbuseIPDB check for `ip`: rotates keys, pauses and retries on limits / errors / no internet."""
    attempt = 0
    auth_fail = 0
    while True:
        key = _next_key()
        _LIMITERS[key].acquire()
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
                timeout=15,
            )
        except requests.RequestException as e:
            attempt += 1
            wait_for_internet("AbuseIPDB")
            pause("AbuseIPDB", f"connection problem ({type(e).__name__})", attempt, base=10)
            continue
        sc = r.status_code
        if sc == 200:
            return r
        if sc == 429:
            attempt += 1
            ra = r.headers.get("Retry-After", "")
            cool = int(ra) + 2 if ra.isdigit() else 65
            _COOLDOWN[key] = time.monotonic() + cool
            _say(f"[PAUSED] AbuseIPDB key ...{key[-4:]} ({_KEYS.index(key) + 1}/{len(_KEYS)}): limit reached, "
                 f"resting {cool / 3600:.1f}h; other keys continue.")
            continue
        if sc in (401, 403):
            auth_fail += 1
            _COOLDOWN[key] = time.monotonic() + 30
            if auth_fail >= 3 * len(_KEYS):
                return r
            continue
        if sc >= 500:
            attempt += 1
            pause("AbuseIPDB", f"server error {sc}", attempt)
            continue
        return r


def check_abuseipdb(url: str):
    if not _KEYS:
        return {"error": "No API key configured"}

    # Normalise: bare domains like 'welthwest.com' have no scheme,
    # so urlparse puts everything in 'path', not 'netloc'.
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc.split(':')[0]
    if not domain:
        return {"error": "Invalid URL format"}

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        wait_for_internet("AbuseIPDB")   # internet down -> wait; otherwise the domain truly does not resolve
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {"error": "Could not resolve domain to IP"}

    if ip in _IP_CACHE:
        return dict(_IP_CACHE[ip])

    try:
        response = _lookup(ip)
        if response.status_code == 200:
            data = response.json().get("data", {})
            result = {
                "ip": ip,
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "usageType": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "countryCode": data.get("countryCode", "Unknown")
            }
            _IP_CACHE[ip] = result
            return dict(result)
        return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

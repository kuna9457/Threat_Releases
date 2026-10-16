import ipaddress
import itertools
import re
from urllib.parse import urlparse
import threading
import time
import requests
import base64
from app.config import settings
from app.utils.rate_limiter import RateLimiter
from app.utils.resilient import pause, wait_for_internet, _say


def _load_keys() -> list[str]:
    """
    VIRUSTOTAL_API_KEY can hold one key or several, comma- or newline-
    separated. Each valid key gets its own 4/min bucket and calls round-robin
    across all of them, so N keys give roughly N x virustotal_rpm effective
    throughput instead of being stuck behind one shared limit.
    """
    raw = settings.virustotal_api_key or ""
    keys = [k.strip() for k in raw.replace("\n", ",").split(",")]
    return [k for k in keys if k and "your_" not in k]


_VT_KEYS = _load_keys()
_VT_LIMITERS = {key: RateLimiter(max_calls=settings.virustotal_rpm, period_seconds=60) for key in _VT_KEYS}
_vt_key_cycle = itertools.cycle(_VT_KEYS) if _VT_KEYS else None
_vt_cycle_lock = threading.Lock()


_VT_COOLDOWN = {}   # key -> monotonic time until which the key must not be used


def _next_vt_key() -> str:
    """Next key (round-robin) that is not cooling down; waits if every key is cooling down."""
    while True:
        with _vt_cycle_lock:
            now = time.monotonic()
            for _ in range(len(_VT_KEYS)):
                k = next(_vt_key_cycle)
                if _VT_COOLDOWN.get(k, 0) <= now:
                    return k
            wait = min(_VT_COOLDOWN.values()) - now
        time.sleep(max(wait, 1))


def check_virustotal(url: str) -> dict:
    """
    VirusTotal lookup. A URL written without a protocol is looked up as https:// first
    (VirusTotal would otherwise treat it as http://); if VirusTotal has no record for that,
    http:// is tried. The caller keeps the URL exactly as written for display.
    """
    if not _VT_KEYS:
        return _check_virustotal_one(url)
    bare = url.strip()
    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", bare, re.I))
    result = _check_virustotal_one(bare if has_scheme else "https://" + bare)
    if result.get("not_found") and not has_scheme:
        alt = _check_virustotal_one("http://" + bare)
        if not alt.get("not_found"):
            return alt
    if result.get("not_found"):
        # No record of this exact URL: fall back to VirusTotal's record for its domain.
        host = urlparse(bare if has_scheme else "https://" + bare).hostname or ""
        if host and not _is_ip(host):
            dom = _domain_lookup(host)
            if not dom.get("not_found") and not dom.get("error"):
                return dom
    return result


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


_DOMAIN_CACHE = {}


def _domain_lookup(host: str) -> dict:
    """Domain-level VirusTotal verdict (many URLs share a domain, so each domain is fetched once)."""
    host = host.lower()
    if host not in _DOMAIN_CACHE:
        _DOMAIN_CACHE[host] = _check_virustotal_one(host, domain_mode=True)
    return dict(_DOMAIN_CACHE[host])


def _check_virustotal_one(url: str, domain_mode: bool = False) -> dict:
    """
    Returns a rich dict of VirusTotal data for the given URL (or, in domain_mode, for the domain `url`).
    Falls back to mock data if no valid API key is configured.
    """
    if not _VT_KEYS:
        # Mock fallback
        is_malicious = "malicious" in url.lower()
        return {
            "malicious": 10 if is_malicious else 0,
            "suspicious": 0,
            "harmless": 60,
            "undetected": 25,
            "timeout": 0,
            "final_url": url,
            "title": "N/A (mock)",
            "tags": [],
            "categories": {},
            "redirection_chain": [],
            "times_submitted": 0,
            "last_http_response_code": None,
            "last_analysis_results": {},
            "threat_names": [],
            "reputation": 0,
            "mock": True,
        }

    if domain_mode:
        api_url = f"https://www.virustotal.com/api/v3/domains/{url}"
    else:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    attempt = 0
    auth_fail = 0
    while True:
        api_key = _next_vt_key()
        headers = {"x-apikey": api_key}
        print(f"[VirusTotal] key ...{api_key[-4:]} ({_VT_KEYS.index(api_key) + 1}/{len(_VT_KEYS)}) -> {url}")
        _VT_LIMITERS[api_key].acquire()
        try:
            response = requests.get(api_url, headers=headers, timeout=20)
        except requests.RequestException as e:
            attempt += 1
            wait_for_internet("VirusTotal")
            pause("VirusTotal", f"connection problem ({type(e).__name__})", attempt, base=10)
            continue

        sc = response.status_code
        if sc == 200:
            break
        if sc == 404:
            # Not in VT's database: nothing was assessed -> flagged so it is excluded from the risk result.
            result = _empty_vt_result()
            result["not_found"] = True
            return result
        if sc == 429:
            # Rate / quota limit: rest this key and carry on with the others (or wait if all rest).
            attempt += 1
            code = ""
            try:
                code = response.json().get("error", {}).get("code", "")
            except Exception:
                pass
            cool = 600 if "quota" in code.lower() else 65
            _VT_COOLDOWN[api_key] = time.monotonic() + cool
            _say(f"[PAUSED] VirusTotal key ...{api_key[-4:]}: rate/quota limit ({code or '429'}). "
                 f"Key rests {cool}s; retrying (attempt {attempt}).")
            continue
        if sc in (401, 403):
            auth_fail += 1
            _VT_COOLDOWN[api_key] = time.monotonic() + 30
            if auth_fail >= 3 * len(_VT_KEYS):
                result = _empty_vt_result()
                result["error"] = f"VirusTotal HTTP {sc} - API key rejected"
                return result
            continue
        if sc >= 500 or sc == 408:
            attempt += 1
            pause("VirusTotal", f"server error {sc}", attempt)
            continue
        result = _empty_vt_result()
        if sc in (400, 422):
            # VirusTotal rejects the input itself (malformed URL/domain): it can never be assessed,
            # so treat it like "not found" (excluded from the risk result) instead of a failed lookup.
            result["not_found"] = True
            return result
        result["error"] = f"VirusTotal HTTP {sc}"
        return result

    try:
        raw = response.json()
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Collect engines that flagged as malicious or suspicious
        threat_names = [
            engine
            for engine, detail in results.items()
            if detail.get("category") in ("malicious", "suspicious")
        ]

        return {
            "domain_level": domain_mode,
            "domain": url if domain_mode else "",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "final_url": "" if domain_mode else attrs.get("last_final_url", url),
            "title": attrs.get("title", ""),
            "tags": attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
            "redirection_chain": attrs.get("redirection_chain", []),
            "times_submitted": attrs.get("times_submitted", 0),
            "last_http_response_code": attrs.get("last_http_response_code"),
            "last_analysis_results": results,
            "threat_names": threat_names,
            "reputation": attrs.get("reputation", 0),
            "mock": False,
        }

    except Exception as e:
        print(f"VT integration error: {e}")
        result = _empty_vt_result()
        result["error"] = f"VirusTotal integration error: {e}"
        return result


def _empty_vt_result() -> dict:
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
        "final_url": "",
        "title": "",
        "tags": [],
        "categories": {},
        "redirection_chain": [],
        "times_submitted": 0,
        "last_http_response_code": None,
        "last_analysis_results": {},
        "threat_names": [],
        "reputation": 0,
        "mock": False,
    }

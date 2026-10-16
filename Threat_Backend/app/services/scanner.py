from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from app.services.virustotal import check_virustotal
from app.services.google_safe import check_google_safe
from app.utils.whois_lookup import get_whois_info
from app.core.risk_engine import calculate_score, calculate_risk_levels
from app.core.policy_engine import decide_verdict
from app.services.urlscan_service import check_urlscan
from app.services.abuseipdb_service import check_abuseipdb
from app.services.sslyze_service import check_sslyze
from app.cache.memory_cache import get_cache, set_cache

# Note: app/services/ssl_labs_service.py (Qualys SSL Labs API) is kept in the
# codebase but no longer wired into the scan pipeline — SSLyze now covers the
# TLS/SSL protocol check locally, without SSL Labs' slow (up to 180s) remote
# assessment queue, and per risk.md only SSLyze is part of the risk model.

# Each source hits a different, independent third-party API — safe to run
# concurrently. This pool is shared across every URL being scanned at once,
# so it's sized for many URLs in flight together (batches up to 100), not
# just one URL's 7 sources. The *real* pacing against vendor rate limits
# happens inside each rate-limited service (see app/utils/rate_limiter.py) —
# extra threads here just queue politely instead of firing 429s.
_SOURCE_EXECUTOR = ThreadPoolExecutor(max_workers=40, thread_name_prefix="scan-source")


def scan_url_service(url: str):
    # 1. Check cache
    cached = get_cache(url)
    if cached:
        return cached

    # 2. API Calls — fired concurrently instead of one after another.
    futures = {
        "virustotal": _SOURCE_EXECUTOR.submit(check_virustotal, url),
        "phishing": _SOURCE_EXECUTOR.submit(check_google_safe, url),
        "whois": _SOURCE_EXECUTOR.submit(get_whois_info, url),
        "urlscan": _SOURCE_EXECUTOR.submit(check_urlscan, url),
        "abuseipdb": _SOURCE_EXECUTOR.submit(check_abuseipdb, url),
        "sslyze": _SOURCE_EXECUTOR.submit(check_sslyze, url),
    }
    vt_data = futures["virustotal"].result()
    phishing = futures["phishing"].result()
    whois_info = futures["whois"].result()
    urlscan_data = futures["urlscan"].result()
    abuseipdb_data = futures["abuseipdb"].result()
    sslyze_data = futures["sslyze"].result()

    # Legacy plain-int domain age, kept for older consumers (e.g. the
    # inherent/residual "exception risk" assessment flow) that expect a
    # number rather than the richer {age_days, is_ip, error} shape.
    domain_age = whois_info["age_days"] if whois_info.get("age_days") is not None else 3650

    # Build the data block — keep legacy keys for risk engine compatibility
    data = {
        # Legacy keys (risk engine uses these)
        "vt_malicious": vt_data.get("malicious", 0),
        "phishing": phishing,
        "domain_age": domain_age,
        # Rich VirusTotal data
        "virustotal": vt_data,
        "urlscan": urlscan_data,
        "abuseipdb": abuseipdb_data,
        # New integrations
        "sslyze": sslyze_data,
        "whois": whois_info,
    }

    score, score_breakdown = calculate_score(data)
    verdict = decide_verdict(score)
    risk_assessment = calculate_risk_levels(data)

    result = {
        "url": url,
        "score": score,
        "score_breakdown": score_breakdown,
        "verdict": verdict,
        "risk_sources": risk_assessment["sources"],
        "final_risk_level": risk_assessment["final_level"],
        "inherent_risk_level": risk_assessment.get("inherent_final_level", risk_assessment["final_level"]),
        "mitigated_sources": risk_assessment.get("mitigated_sources", []),
        "risk_remarks": risk_assessment["remarks"],
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # 3. Cache
    set_cache(url, result)
    return result


# This no longer needs to be tiny to "protect" vendor rate limits — the
# per-vendor RateLimiters (VirusTotal, AbuseIPDB, URLScan) and the SSL Labs
# concurrency semaphore do that job directly, correctly, regardless of how
# many URLs are in flight. This just caps how many URLs' worth of non-limited
# work (WHOIS) run at once so a 100-URL batch doesn't open an unreasonable
# number of sockets simultaneously.
_BATCH_CONCURRENCY = 20


def scan_urls_batch(urls: list[str]) -> list[dict]:
    """Scan multiple URLs concurrently (bounded), preserving input order."""
    cleaned = [u.strip() for u in urls if u.strip()]
    if not cleaned:
        return []
    with ThreadPoolExecutor(max_workers=min(_BATCH_CONCURRENCY, len(cleaned)), thread_name_prefix="scan-batch") as executor:
        return list(executor.map(scan_url_service, cleaned))

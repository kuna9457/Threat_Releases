"""
SSL Labs Integration Service
Uses the Qualys SSL Labs API v3 (free, no key required) to analyse
SSL/TLS configuration of a domain.
Docs: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
"""

import threading
import time
import requests
from urllib.parse import urlparse
from app.config import settings

SSL_LABS_API = "https://api.ssllabs.com/api/v3"

# Qualys doesn't publish a requests/minute quota — instead they ask clients not
# to run many fresh assessments at once. This caps how many check_ssl_labs()
# calls can be actively polling at the same time; extra calls queue on the
# semaphore rather than piling on and getting the client IP throttled.
_ssl_labs_semaphore = threading.Semaphore(settings.ssl_labs_max_concurrent)


def _extract_domain(url: str) -> str:
    """Extract bare hostname from a URL string."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).netloc.split(":")[0]


def check_ssl_labs(url: str, max_wait: int = 180) -> dict:
    """
    Kick off an SSL Labs assessment and poll until it finishes or
    *max_wait* seconds elapse.  Returns a rich dict of certificate /
    protocol / vulnerability data.
    """
    domain = _extract_domain(url)
    if not domain:
        return {"error": "Invalid URL — could not extract domain"}

    with _ssl_labs_semaphore:
        return _run_assessment(domain, max_wait)


def _run_assessment(domain: str, max_wait: int) -> dict:
    try:
        # Start a new assessment (use cache if a recent one exists)
        params = {
            "host": domain,
            "publish": "off",
            "startNew": "off",         # use cached if available
            "fromCache": "on",
            "maxAge": 24,              # hours
            "all": "done",
        }

        deadline = time.time() + max_wait

        while time.time() < deadline:
            resp = requests.get(
                f"{SSL_LABS_API}/analyze",
                params=params,
                timeout=20,
            )
            if resp.status_code == 429:
                # rate-limited — back off
                time.sleep(10)
                continue
            if resp.status_code != 200:
                return {"error": f"SSL Labs HTTP {resp.status_code}: {resp.text[:200]}"}

            body = resp.json()
            status = body.get("status")

            if status == "READY":
                return _parse_ssl_result(body, domain)
            elif status == "ERROR":
                return {"error": body.get("statusMessage", "SSL Labs returned an error")}
            elif status in ("DNS", "IN_PROGRESS"):
                # Remove startNew after first request so we just poll
                params.pop("startNew", None)
                time.sleep(8)
                continue
            else:
                # Unknown status — try kicking off a fresh scan
                params["startNew"] = "on"
                params.pop("fromCache", None)
                time.sleep(5)
                continue

        return {"error": "SSL Labs timed out — assessment still running"}

    except Exception as e:
        return {"error": f"SSL Labs integration error: {str(e)}"}


def _parse_ssl_result(body: dict, domain: str) -> dict:
    """Turn raw SSL Labs JSON into a clean, frontend-friendly dict."""
    endpoints = body.get("endpoints", [])
    if not endpoints:
        return {
            "domain": domain,
            "grade": "N/A",
            "error": "No endpoints found (server may not support HTTPS)",
        }

    ep = endpoints[0]
    details = ep.get("details", {})

    # ── Certificate info ──────────────────────────────────────────────
    certs = details.get("certChains", [{}])
    cert_info = {}
    if certs:
        first_chain = certs[0]
        chain_certs = first_chain.get("certIds", [])
        # Get the leaf certificate
        all_certs = details.get("certs", [])
        if all_certs:
            leaf = all_certs[0]
            cert_info = {
                "subject": leaf.get("subject", ""),
                "issuer": leaf.get("issuerSubject", ""),
                "sig_alg": leaf.get("sigAlg", ""),
                "key_alg": leaf.get("keyAlg", ""),
                "key_size": leaf.get("keySize", 0),
                "key_strength": leaf.get("keyStrength", 0),
                "not_before": leaf.get("notBefore"),
                "not_after": leaf.get("notAfter"),
                "serial": leaf.get("serialNumber", ""),
                "sha256_fingerprint": leaf.get("sha256Hash", ""),
                "san": leaf.get("altNames", []),
                "sct": leaf.get("sct", False),
                "must_staple": leaf.get("mustStaple", 0),
                "revocation_status": leaf.get("revocationStatus", 0),
                "crl_revocation_status": leaf.get("crlRevocationStatus", 0),
                "ocsp_revocation_status": leaf.get("ocspRevocationStatus", 0),
            }

    # ── Protocol support ──────────────────────────────────────────────
    protocols_raw = details.get("protocols", [])
    protocols = []
    for p in protocols_raw:
        protocols.append({
            "name": p.get("name", ""),
            "version": p.get("version", ""),
            "id": p.get("id", 0),
        })

    # ── Cipher suites ────────────────────────────────────────────────
    suites_list = details.get("suites", [])
    cipher_suites = []
    for suite_group in suites_list:
        proto = suite_group.get("protocol", 0)
        for s in suite_group.get("list", []):
            cipher_suites.append({
                "name": s.get("name", ""),
                "cipher_strength": s.get("cipherStrength", 0),
                "protocol_id": proto,
                "kx_type": s.get("kxType", ""),
                "kx_strength": s.get("kxStrength", 0),
            })

    # ── Vulnerabilities ───────────────────────────────────────────────
    vuln_map = {
        "heartbleed": details.get("heartbleed", False),
        "heartbeat": details.get("heartbeat", False),
        "poodle_tls": details.get("poodleTls", 0),
        "poodle_ssl3": details.get("poodle", False),
        "freak": details.get("freak", False),
        "logjam": details.get("logjam", False),
        "drown_vulnerable": details.get("drownVulnerable", False),
        "ticketbleed": details.get("ticketbleed", 0),
        "bleichenbacher": details.get("bleichenbacher", 0),
        "zombie_poodle": details.get("zombiePoodle", 0),
        "golden_doodle": details.get("goldenDoodle", 0),
        "sleeping_poodle": details.get("sleepingPoodle", 0),
        "zero_length_padding_oracle": details.get("zeroLengthPaddleOracle", 0),
        "openssl_ccs": details.get("openSslCcs", 0),
        "openssl_lucky_minus20": details.get("openSSLLuckyMinus20", 0),
    }

    # ── HSTS / security headers ───────────────────────────────────────
    hsts_policy = details.get("hstsPolicy", {})
    hpkp_policy = details.get("hpkpPolicy", {})

    return {
        "domain": domain,
        "host": body.get("host", domain),
        "port": body.get("port", 443),
        "protocol": body.get("protocol", ""),
        "is_public": body.get("isPublic", False),
        "status": "READY",
        "grade": ep.get("grade", "N/A"),
        "grade_trust_ignored": ep.get("gradeTrustIgnored", "N/A"),
        "has_warnings": ep.get("hasWarnings", False),
        "is_exceptional": ep.get("isExceptional", False),
        "delegation": ep.get("delegation", 0),
        "ip_address": ep.get("ipAddress", ""),
        "server_name": ep.get("serverName", ""),

        # Certificate
        "certificate": cert_info,

        # Protocols
        "protocols": protocols,

        # Cipher suites (top 20 for brevity)
        "cipher_suites": cipher_suites[:20],
        "total_cipher_suites": len(cipher_suites),

        # Vulnerabilities
        "vulnerabilities": vuln_map,

        # Security headers
        "hsts": {
            "status": hsts_policy.get("status", "unknown"),
            "max_age": hsts_policy.get("maxAge", 0),
            "include_subdomains": hsts_policy.get("includeSubDomains", False),
            "preload": hsts_policy.get("preload", False),
        },
        "hpkp": {
            "status": hpkp_policy.get("status", "unknown"),
        },

        # Forward Secrecy
        "forward_secrecy": details.get("forwardSecrecy", 0),
        "supports_alpn": details.get("supportsAlpn", False),
        "session_resumption": details.get("sessionResumption", 0),
        "ocsp_stapling": details.get("ocspStapling", False),
        "supports_rc4": details.get("supportsRc4", False),
    }

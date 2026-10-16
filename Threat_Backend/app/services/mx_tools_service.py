"""
MX Tools Integration Service
Uses dnspython to perform comprehensive mail-server / DNS analysis:
  - MX records
  - SPF, DMARC, DKIM selectors
  - A, AAAA, NS, SOA, CNAME, TXT records
  - Reverse DNS on resolved IPs
  - SMTP banner grab (port 25)
"""

import socket
import dns.resolver
import dns.reversename
from urllib.parse import urlparse
from typing import Optional


def _extract_domain(url: str) -> str:
    """Extract bare hostname from a URL string."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).netloc.split(":")[0]


def _safe_resolve(domain: str, rdtype: str, timeout: float = 8.0) -> list:
    """Resolve DNS records, returning empty list on any failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, rdtype)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def _get_mx_records(domain: str) -> list[dict]:
    """Return a list of MX records with preference & exchange."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 8
        resolver.lifetime = 8
        answers = resolver.resolve(domain, "MX")
        records = []
        for rdata in answers:
            records.append({
                "preference": rdata.preference,
                "exchange": str(rdata.exchange).rstrip("."),
            })
        return sorted(records, key=lambda r: r["preference"])
    except Exception:
        return []


def _get_spf_record(domain: str) -> Optional[str]:
    """Find the SPF TXT record for a domain."""
    txt_records = _safe_resolve(domain, "TXT")
    for txt in txt_records:
        cleaned = txt.strip('"')
        if cleaned.lower().startswith("v=spf1"):
            return cleaned
    return None


def _get_dmarc_record(domain: str) -> Optional[str]:
    """Fetch the DMARC record at _dmarc.<domain>."""
    records = _safe_resolve(f"_dmarc.{domain}", "TXT")
    for txt in records:
        cleaned = txt.strip('"')
        if cleaned.lower().startswith("v=dmarc1"):
            return cleaned
    return None


def _get_dkim_record(domain: str, selectors: list[str] | None = None) -> dict:
    """Try common DKIM selectors and return any found records."""
    if selectors is None:
        selectors = [
            "default", "google", "selector1", "selector2",
            "k1", "k2", "dkim", "mail", "s1", "s2",
        ]
    found = {}
    for sel in selectors:
        records = _safe_resolve(f"{sel}._domainkey.{domain}", "TXT")
        if records:
            found[sel] = records[0].strip('"')
    return found


def _reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return str(list(answers)[0]).rstrip(".")
    except Exception:
        return ""


def _smtp_banner(mx_host: str, timeout: float = 5.0) -> str:
    """Try to grab the SMTP banner from port 25 of a mail server."""
    try:
        with socket.create_connection((mx_host, 25), timeout=timeout) as sock:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner
    except Exception:
        return ""


def _get_soa_record(domain: str) -> dict:
    """Fetch SOA record details."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 8
        resolver.lifetime = 8
        answers = resolver.resolve(domain, "SOA")
        soa = list(answers)[0]
        return {
            "mname": str(soa.mname).rstrip("."),
            "rname": str(soa.rname).rstrip("."),
            "serial": soa.serial,
            "refresh": soa.refresh,
            "retry": soa.retry,
            "expire": soa.expire,
            "minimum": soa.minimum,
        }
    except Exception:
        return {}


def check_mx_tools(url: str) -> dict:
    """
    Full MX / DNS analysis for the domain extracted from *url*.
    Returns a rich dict with all mail and DNS intelligence.
    """
    domain = _extract_domain(url)
    if not domain:
        return {"error": "Invalid URL — could not extract domain"}

    try:
        # ── Core DNS Records ─────────────────────────────────────────
        mx_records = _get_mx_records(domain)
        a_records = _safe_resolve(domain, "A")
        aaaa_records = _safe_resolve(domain, "AAAA")
        ns_records = [r.rstrip(".") for r in _safe_resolve(domain, "NS")]
        cname_records = [r.rstrip(".") for r in _safe_resolve(domain, "CNAME")]
        txt_records = [r.strip('"') for r in _safe_resolve(domain, "TXT")]
        soa = _get_soa_record(domain)

        # ── Mail Security ────────────────────────────────────────────
        spf_record = _get_spf_record(domain)
        dmarc_record = _get_dmarc_record(domain)
        dkim_records = _get_dkim_record(domain)

        # ── Reverse DNS for A records ────────────────────────────────
        reverse_dns = {}
        for ip in a_records[:5]:  # limit to first 5
            ptr = _reverse_dns(ip)
            if ptr:
                reverse_dns[ip] = ptr

        # ── SMTP banners for top MX servers ──────────────────────────
        smtp_banners = {}
        for mx in mx_records[:3]:  # limit to first 3
            banner = _smtp_banner(mx["exchange"])
            if banner:
                smtp_banners[mx["exchange"]] = banner

        # ── MX host IP resolution ────────────────────────────────────
        mx_host_ips = {}
        for mx in mx_records[:5]:
            ips = _safe_resolve(mx["exchange"], "A")
            if ips:
                mx_host_ips[mx["exchange"]] = ips

        # ── Mail security posture assessment ─────────────────────────
        mail_security_score = _assess_mail_security(
            spf_record, dmarc_record, dkim_records, mx_records
        )

        return {
            "domain": domain,
            "mx_records": mx_records,
            "a_records": a_records,
            "aaaa_records": aaaa_records,
            "ns_records": ns_records,
            "cname_records": cname_records,
            "txt_records": txt_records,
            "soa": soa,
            "spf": {
                "record": spf_record,
                "exists": spf_record is not None,
            },
            "dmarc": {
                "record": dmarc_record,
                "exists": dmarc_record is not None,
                "policy": _parse_dmarc_policy(dmarc_record) if dmarc_record else None,
            },
            "dkim": {
                "selectors_found": list(dkim_records.keys()),
                "records": dkim_records,
                "exists": len(dkim_records) > 0,
            },
            "reverse_dns": reverse_dns,
            "smtp_banners": smtp_banners,
            "mx_host_ips": mx_host_ips,
            "mail_security": mail_security_score,
        }

    except Exception as e:
        return {"error": f"MX Tools integration error: {str(e)}"}


def _parse_dmarc_policy(record: str) -> dict:
    """Parse key fields from a DMARC record string."""
    result = {"policy": None, "subdomain_policy": None, "pct": 100, "rua": None, "ruf": None}
    if not record:
        return result
    parts = record.replace(" ", "").split(";")
    for part in parts:
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip().lower()
        val = val.strip()
        if key == "p":
            result["policy"] = val
        elif key == "sp":
            result["subdomain_policy"] = val
        elif key == "pct":
            try:
                result["pct"] = int(val)
            except ValueError:
                pass
        elif key == "rua":
            result["rua"] = val
        elif key == "ruf":
            result["ruf"] = val
    return result


def _assess_mail_security(
    spf: Optional[str],
    dmarc: Optional[str],
    dkim: dict,
    mx_records: list,
) -> dict:
    """
    Produce a simple mail-security posture score (0-100) and
    per-check breakdown.
    """
    checks = {}
    score = 0

    # SPF (25 pts)
    if spf:
        checks["spf"] = {"status": "PASS", "detail": "SPF record found"}
        score += 25
        if "-all" in spf:
            checks["spf"]["detail"] += " (strict -all)"
        elif "~all" in spf:
            checks["spf"]["detail"] += " (soft-fail ~all)"
            score -= 5
    else:
        checks["spf"] = {"status": "FAIL", "detail": "No SPF record found"}

    # DMARC (25 pts)
    if dmarc:
        checks["dmarc"] = {"status": "PASS", "detail": "DMARC record found"}
        score += 25
        policy = _parse_dmarc_policy(dmarc)
        if policy.get("policy") == "reject":
            checks["dmarc"]["detail"] += " (policy=reject)"
        elif policy.get("policy") == "quarantine":
            checks["dmarc"]["detail"] += " (policy=quarantine)"
            score -= 5
        elif policy.get("policy") == "none":
            checks["dmarc"]["detail"] += " (policy=none — monitoring only)"
            score -= 15
    else:
        checks["dmarc"] = {"status": "FAIL", "detail": "No DMARC record found"}

    # DKIM (25 pts)
    if dkim:
        checks["dkim"] = {
            "status": "PASS",
            "detail": f"DKIM found ({', '.join(dkim.keys())})",
        }
        score += 25
    else:
        checks["dkim"] = {
            "status": "WARN",
            "detail": "No DKIM selectors found (common selectors checked)",
        }

    # MX records (25 pts)
    if mx_records:
        checks["mx"] = {
            "status": "PASS",
            "detail": f"{len(mx_records)} MX record(s) found",
        }
        score += 25
    else:
        checks["mx"] = {"status": "FAIL", "detail": "No MX records found"}

    return {
        "score": max(0, min(score, 100)),
        "checks": checks,
    }

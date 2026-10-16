# ── New risk methodology (see risk.md) ──────────────────────────────────
#
# Final_Risk_Level is the WORST level among whichever of these four sources
# returned a usable result for the entry:
#   - VirusTotal   : malicious-engine count out of total engines
#   - AbuseIPDB    : abuse confidence score (0-100) for the resolved IP
#   - SSLyze       : weakest TLS/SSL protocol still accepted on port 443,
#                    found by a real local SSLyze scan (app/services/sslyze_service.py)
#   - WHOIS        : domain age in days (skipped for bare-IP targets)
#
# Google Safe Browsing and URLScan.io keep running (their data is still
# collected and cached) but are intentionally excluded from this
# methodology and from the report/UI it drives.

_LEVEL_ORDER = {"No Risk": 0, "Low": 1, "Medium": 2, "High": 3}

_TLS_PROTOCOL_ORDER = {
    "SSL 2.0": 0, "SSL 3.0": 1, "TLS 1.0": 2, "TLS 1.1": 3, "TLS 1.2": 4, "TLS 1.3": 5,
}

_WEAK_TLS_PROTOCOLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}


def _score_virustotal(vt: dict) -> dict:
    if not vt or "error" in vt:
        return {"usable": False, "level": None, "detail": vt.get("error", "No result") if vt else "No result"}

    malicious = vt.get("malicious", 0)
    total = malicious + vt.get("suspicious", 0) + vt.get("harmless", 0) + vt.get("undetected", 0) + vt.get("timeout", 0)

    # URL unknown to VirusTotal (404) / no engine verdicts: nothing was actually assessed,
    # so it must not be counted as "No Risk" - exclude it from the calculation.
    if vt.get("not_found") or total == 0:
        return {"usable": False, "level": None, "detail": "Not found in VirusTotal"}

    if malicious == 0:
        level = "No Risk"
    elif malicious <= 2:
        level = "Low"
    elif malicious <= 5:
        level = "Medium"
    else:
        level = "High"

    detail = f"{malicious}/{total}" + (" - domain level" if vt.get("domain_level") else "")
    return {
        "usable": True,
        "level": level,
        "detail": detail,
    }


def _score_abuseipdb(abuse: dict) -> dict:
    if not abuse or "error" in abuse:
        return {"usable": False, "level": None, "detail": abuse.get("error", "No result") if abuse else "No result"}

    conf = abuse.get("abuseConfidenceScore", 0)
    if conf == 0:
        level = "No Risk"
    elif conf <= 24:
        level = "Low"
    elif conf <= 74:
        level = "Medium"
    else:
        level = "High"

    return {
        "usable": True,
        "level": level,
        "detail": f"{conf}%",
    }


def _weakest_tls_protocol(protocols: list[dict]) -> str | None:
    weakest = None
    weakest_rank = None
    for p in protocols:
        name = (p.get("name") or "").strip()
        version = (p.get("version") or "").strip()
        label = f"{name} {version}".strip()
        rank = _TLS_PROTOCOL_ORDER.get(label)
        if rank is None:
            continue
        if weakest_rank is None or rank < weakest_rank:
            weakest_rank = rank
            weakest = label
    return weakest


def _score_sslyze(sslyze: dict) -> dict:
    if not sslyze or sslyze.get("error"):
        return {"usable": False, "level": None, "detail": sslyze.get("error", "No result") if sslyze else "No result"}

    protocols = sslyze.get("protocols", [])
    weakest = _weakest_tls_protocol(protocols)
    if weakest is None:
        return {"usable": False, "level": None, "detail": "No recognised TLS/SSL protocols reported"}

    level = "Medium" if weakest in _WEAK_TLS_PROTOCOLS else "No Risk"
    return {
        "usable": True,
        "level": level,
        "detail": f"Weakest enabled: {weakest}",
    }


def _score_whois(whois_info: dict) -> dict:
    if not whois_info:
        return {"usable": False, "level": None, "detail": "No result"}

    if whois_info.get("is_ip"):
        return {"usable": False, "level": None, "detail": "Bare-IP input — WHOIS not applicable"}

    if whois_info.get("error") or whois_info.get("age_days") is None:
        return {"usable": False, "level": None, "detail": whois_info.get("error") or "Domain age unknown"}

    age = whois_info["age_days"]
    level = "No Risk" if age >= 30 else "Low"
    return {
        "usable": True,
        "level": level,
        "detail": f"{age} days",
    }


def calculate_risk_levels(data: dict) -> dict:
    """
    Implements the risk methodology: per-source No Risk/Low/Medium/High
    levels for VirusTotal, AbuseIPDB, SSLyze (weakest TLS protocol) and WHOIS.
    The Final_Risk_Level is the single worst (highest-severity) result among
    every source that returned a usable value.
    """
    sources = {
        "VirusTotal": _score_virustotal(data.get("virustotal", {})),
        "AbuseIPDB": _score_abuseipdb(data.get("abuseipdb", {})),
        "SSLyze": _score_sslyze(data.get("sslyze", {})),
        "WHOIS": _score_whois(data.get("whois", {})),
    }

    usable_levels = [s["level"] for s in sources.values() if s["usable"]]

    if not usable_levels:
        final_level = "Unknown"
    else:
        final_level = max(usable_levels, key=lambda l: _LEVEL_ORDER[l])

    used = [name for name, s in sources.items() if s["usable"]]
    errors = []

    remarks_parts = []
    remarks_parts.append(f"Based on: {', '.join(used)}" if used else "No source returned a usable result")
    if errors:
        remarks_parts.append("; ".join(errors))
    remarks = " — ".join(remarks_parts)

    return {
        "sources": sources,
        "final_level": final_level,
        "remarks": remarks,
    }


def calculate_score(data: dict):
    score = 0
    breakdown = {}

    # Domain Age logic (Newer domains are riskier)
    da_score = 0
    da = data.get("domain_age", 3650)
    if da < 7:
        da_score = 50
    elif da < 30:
        da_score = 30
    elif da < 90:
        da_score = 15
    score += da_score
    if da_score > 0: breakdown["Domain Age"] = da_score

    # VirusTotal logic
    vt_score = 0
    vt_malicious = data.get("vt_malicious", 0)
    if vt_malicious > 5:
        vt_score = 40
    elif vt_malicious > 0:
        vt_score = 20
    score += vt_score
    if vt_score > 0: breakdown["VirusTotal"] = vt_score

    # Google Safe Browsing logic
    gsb_score = 0
    if data.get("phishing"):
        gsb_score = 100 # Immediate high risk
    score += gsb_score
    if gsb_score > 0: breakdown["Google Safe Browsing"] = gsb_score

    # URLScan logic
    url_score = 0
    urlscan = data.get("urlscan", {})
    if urlscan.get("malicious"):
        url_score = 30
    score += url_score
    if url_score > 0: breakdown["URLScan.io"] = url_score

    # AbuseIPDB logic
    abuse_score_val = 0
    abuseipdb = data.get("abuseipdb", {})
    abuse_confidence = abuseipdb.get("abuseConfidenceScore", 0)
    if abuse_confidence > 80:
        abuse_score_val = 40
    elif abuse_confidence > 40:
        abuse_score_val = 20
    score += abuse_score_val
    if abuse_score_val > 0: breakdown["AbuseIPDB"] = abuse_score_val

    # SSL Labs logic — poor grades indicate risk
    ssl_score = 0
    ssl = data.get("ssl_labs", {})
    if "error" not in ssl:
        grade = ssl.get("grade", "")
        if grade:
            g = grade.upper()
            if g.startswith("F") or g.startswith("T"):
                ssl_score += 25
            elif g.startswith("D"):
                ssl_score += 15
            elif g.startswith("C"):
                ssl_score += 8

        # Known vulnerabilities add risk
        vulns = ssl.get("vulnerabilities", {})
        if vulns.get("heartbleed"):
            ssl_score += 15
        if vulns.get("poodle_ssl3"):
            ssl_score += 10
        if vulns.get("drown_vulnerable"):
            ssl_score += 10
        if vulns.get("freak"):
            ssl_score += 10
            
    score += ssl_score
    if ssl_score > 0: breakdown["SSL Labs"] = ssl_score

    return min(score, 100), breakdown

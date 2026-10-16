"""
Email Security Posture Validator (SPF, DKIM, DMARC)
Converted from legacy PowerShell audit tool.

Section 7 Qualification Bar
────────────────────────────
A domain qualifies (meets_qualification=True) ONLY when ALL three are met:
  1. SPF  : Present AND enforces -all (HARD FAIL) or ~all (SOFT FAIL).
             Permissive (+all), neutral (?all), or missing → FAIL.
  2. DMARC: Record exists with p=reject OR p=quarantine. (p=none → FAIL)
  3. DKIM : Verified via active selector DNS TXT query containing valid
             v=DKIM1 or p= tags (wildcard-safe).
"""

from __future__ import annotations

import re
from email import policy as email_policy
from email.parser import BytesParser
from typing import Optional

import dns.resolver
import dns.exception


# ─────────────────────────────────────────────────────────────────────────────
# COMMON DKIM SELECTORS (heuristic – user-provided selectors take priority)
# ─────────────────────────────────────────────────────────────────────────────
_COMMON_SELECTORS = [
    "selector1", "selector2",
    "google", "googlemail",
    "s1", "s2",
    "k1", "k2",
    "dkim", "mail", "email",
    "default", "smtp",
    "pps1", "pm", "cm",
    "mx", "2024mail", "2023mail",
    "mailjet", "sendgrid", "mcsv",
    "zoho", "protonmail", "fastmail",
]

# ─────────────────────────────────────────────────────────────────────────────
# DNS RESOLVER FACTORY
# ─────────────────────────────────────────────────────────────────────────────
_RESOLVER_MAP = {
    "default": "1.1.1.1",
    "google":  "8.8.8.8",
    "quad9":   "9.9.9.9",
}


def _make_resolver(resolver_name: str = "default") -> dns.resolver.Resolver:
    """Build a dnspython Resolver with explicit timeouts and optional NS override."""
    r = dns.resolver.Resolver(configure=False)
    r.timeout  = 2.0
    r.lifetime = 3.0
    ns_ip = _RESOLVER_MAP.get(resolver_name.lower(), "1.1.1.1")
    r.nameservers = [ns_ip]
    return r


def _safe_txt(name: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Return a list of TXT record strings for *name*, silencing all DNS errors."""
    try:
        answers = resolver.resolve(name, "TXT")
        return [rdata.to_text().strip('"').replace('" "', "") for rdata in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []


# ─────────────────────────────────────────────────────────────────────────────
# SPF EVALUATION
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_spf(domain: str, resolver: dns.resolver.Resolver) -> dict:
    """
    Evaluate the SPF record for *domain*.

    Returns:
        {
            "exists":  bool,
            "record":  str | None,
            "policy":  "-all" | "~all" | "+all" | "?all" | "none" | "missing",
            "pass":    bool,   # True only for -all or ~all
        }
    """
    txt_records = _safe_txt(domain, resolver)
    spf_record: Optional[str] = None
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            spf_record = txt
            break

    if spf_record is None:
        return {"exists": False, "record": None, "policy": "missing", "pass": False}

    # Determine the all-mechanism
    lower = spf_record.lower()
    if "-all" in lower:
        policy, qualifies = "-all", True
    elif "~all" in lower:
        policy, qualifies = "~all", True
    elif "+all" in lower:
        policy, qualifies = "+all", False
    elif "?all" in lower:
        policy, qualifies = "?all", False
    else:
        policy, qualifies = "none", False

    return {
        "exists": True,
        "record": spf_record,
        "policy": policy,
        "pass":   qualifies,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DMARC EVALUATION
# ─────────────────────────────────────────────────────────────────────────────

def _parse_dmarc_tags(record: str) -> dict:
    """Parse all tag=value pairs from a DMARC record string."""
    tags: dict = {}
    for part in record.replace(" ", "").split(";"):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        tags[k.lower()] = v.strip()
    return tags


def evaluate_dmarc(domain: str, resolver: dns.resolver.Resolver) -> dict:
    """
    Evaluate the DMARC record for *domain*.

    Returns:
        {
            "exists":  bool,
            "record":  str | None,
            "policy":  "reject" | "quarantine" | "none" | "missing",
            "rua":     str | None,
            "ruf":     str | None,
            "pass":    bool,   # True only for reject or quarantine
        }
    """
    txt_records = _safe_txt(f"_dmarc.{domain}", resolver)
    dmarc_record: Optional[str] = None
    for txt in txt_records:
        if txt.lower().startswith("v=dmarc1"):
            dmarc_record = txt
            break

    if dmarc_record is None:
        return {
            "exists": False, "record": None,
            "policy": "missing", "rua": None, "ruf": None, "pass": False,
        }

    tags = _parse_dmarc_tags(dmarc_record)
    p = tags.get("p", "none").lower()
    qualifies = p in ("reject", "quarantine")

    return {
        "exists": True,
        "record": dmarc_record,
        "policy": p,
        "rua":    tags.get("rua"),
        "ruf":    tags.get("ruf"),
        "sp":     tags.get("sp"),
        "pct":    tags.get("pct", "100"),
        "pass":   qualifies,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DKIM EVALUATION (wildcard-safe)
# ─────────────────────────────────────────────────────────────────────────────

def _is_valid_dkim_txt(txt: str) -> bool:
    """
    Return True only when the TXT record contains valid DKIM key material.
    Prevents wildcard DNS false positives:
      - must contain v=DKIM1 OR a p= tag with a non-empty value.
    """
    lower = txt.lower()
    if "v=dkim1" in lower:
        return True
    # Check for p= with a non-empty value
    match = re.search(r"\bp=([A-Za-z0-9+/=]+)", txt)
    if match and match.group(1):
        return True
    return False


def evaluate_dkim(
    domain: str,
    custom_selectors: list[str] | None,
    resolver: dns.resolver.Resolver,
) -> dict:
    """
    Evaluate DKIM by probing selectors (user-provided first, then common list).

    Returns:
        {
            "exists":           bool,
            "selectors_found":  list[str],
            "records":          dict[selector -> raw_txt],
            "pass":             bool,
            "disclaimer":       str | None,
        }
    """
    probed: list[str] = []
    if custom_selectors:
        # Deduplicate while preserving order
        seen: set[str] = set()
        for s in custom_selectors:
            s = s.strip()
            if s and s not in seen:
                probed.append(s)
                seen.add(s)
    # Append common selectors not already in the list
    for s in _COMMON_SELECTORS:
        if s not in probed:
            probed.append(s)

    found_selectors: list[str] = []
    found_records: dict[str, str] = {}

    for selector in probed:
        name = f"{selector}._domainkey.{domain}"
        txt_records = _safe_txt(name, resolver)
        for txt in txt_records:
            if _is_valid_dkim_txt(txt):
                found_selectors.append(selector)
                found_records[selector] = txt
                break  # one valid record per selector is enough

    exists = len(found_selectors) > 0
    disclaimer: Optional[str] = None
    if not exists:
        disclaimer = (
            "No common DKIM selector found. This does not confirm the sender lacks DKIM; "
            "they may use an unlisted selector. Please supply their selector or send a "
            "test email and paste the raw headers to verify."
        )

    return {
        "exists":          exists,
        "selectors_found": found_selectors,
        "records":         found_records,
        "pass":            exists,
        "disclaimer":      disclaimer,
    }


# ─────────────────────────────────────────────────────────────────────────────
# RAW EMAIL HEADER PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_raw_email_header(raw_header: str) -> dict:
    """
    Parse a raw email header string and extract DKIM-related fields.

    Extracts from DKIM-Signature header(s):
        d= (signing domain)
        s= (selector)

    Returns:
        {
            "domain":    str | None,   # first d= value found
            "selectors": list[str],    # all s= values found
            "raw_dkim_signatures": list[str],
        }
    """
    try:
        # Normalise line endings and ensure it's bytes
        raw_bytes = raw_header.replace("\r\n", "\n").replace("\n", "\r\n").encode()
        msg = BytesParser(policy=email_policy.compat32).parsebytes(raw_bytes)

        domains:    list[str] = []
        selectors:  list[str] = []
        raw_sigs:   list[str] = []

        dkim_headers = msg.get_all("DKIM-Signature") or []
        for sig in dkim_headers:
            raw_sigs.append(sig)
            # Parse individual tag=value pairs within the signature
            for part in re.split(r";\s*", sig):
                part = part.strip()
                if part.lower().startswith("d="):
                    d = part[2:].strip().rstrip(".")
                    if d and d not in domains:
                        domains.append(d)
                elif part.lower().startswith("s="):
                    s = part[2:].strip()
                    if s and s not in selectors:
                        selectors.append(s)

        return {
            "domain":              domains[0] if domains else None,
            "selectors":           selectors,
            "raw_dkim_signatures": raw_sigs,
        }
    except Exception as exc:
        return {"domain": None, "selectors": [], "raw_dkim_signatures": [], "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def validate_domain(
    domain:          str,
    selectors:       list[str] | None = None,
    raw_header:      str | None = None,
    resolver_name:   str = "default",
) -> dict:
    """
    Orchestrate SPF, DMARC, and DKIM checks for a single domain.

    If *raw_header* is supplied, d= / s= values are extracted and merged
    with *domain* / *selectors* respectively.

    Returns:
        {
            "domain":             str,
            "meets_qualification": bool,
            "spf":                {...},
            "dmarc":              {...},
            "dkim":               {...},
            "header_parse":       {...} | None,
            "resolver_used":      str,
        }
    """
    # ── 1. Extract from raw header if provided ──────────────────────────────
    header_parse: Optional[dict] = None
    resolved_domain = domain.strip().lower().lstrip("@")
    merged_selectors: list[str] = list(selectors or [])

    if raw_header and raw_header.strip():
        header_parse = parse_raw_email_header(raw_header)
        # If the header provides a domain and caller didn't, use it
        if not resolved_domain and header_parse.get("domain"):
            resolved_domain = header_parse["domain"]
        # Merge selectors from header (prepend so they're tried first)
        for s in header_parse.get("selectors", []):
            if s not in merged_selectors:
                merged_selectors.insert(0, s)

    if not resolved_domain:
        return {
            "domain":              resolved_domain,
            "meets_qualification": False,
            "error":               "No domain provided",
            "spf":                 {"exists": False, "pass": False},
            "dmarc":               {"exists": False, "pass": False},
            "dkim":                {"exists": False, "pass": False},
            "header_parse":        header_parse,
            "resolver_used":       resolver_name,
        }

    resolver = _make_resolver(resolver_name)

    # ── 2. Run all three checks ────────────────────────────────────────────
    spf_result   = evaluate_spf(resolved_domain, resolver)
    dmarc_result = evaluate_dmarc(resolved_domain, resolver)
    dkim_result  = evaluate_dkim(resolved_domain, merged_selectors or None, resolver)

    # ── 3. Section 7 qualification gate ───────────────────────────────────
    meets = spf_result["pass"] and dmarc_result["pass"] and dkim_result["pass"]

    return {
        "domain":              resolved_domain,
        "meets_qualification": meets,
        "spf":                 spf_result,
        "dmarc":               dmarc_result,
        "dkim":                dkim_result,
        "header_parse":        header_parse,
        "resolver_used":       resolver_name,
    }


## Project Architecture & Overview
This project provides an automated Email Security Posture Validator (SPF, DKIM, DMARC) converted from a legacy PowerShell audit tool to Python. It verifies whether counterparty domains qualify for automated whitelisting.

### Qualification Bar (Section 7 Standard)
A domain qualifies (`meets_qualification = True`) ONLY when all three criteria are met:
1. **SPF**: Present and enforces `HARD FAIL (-all)` or `SOFT FAIL (~all)`. Permissive (`+all`), neutral (`?all`), or missing policies fail.
2. **DMARC**: Record exists with policy set to `p=reject` or `p=quarantine`. (`p=none` fails).
3. **DKIM**: Verified via active selector DNS TXT query containing valid `v=DKIM1` or `p=` tags.

---

## Technical Constraints & DNS Rules

1. **Pure Python DNS Resolution**:
   - Use `dnspython` (`dns.resolver.Resolver`).
   - Do NOT shell out to PowerShell, `dig`, or `nslookup`.
   - Always set explicit timeouts on the resolver (`timeout=2.0`, `lifetime=3.0`) to avoid blocking API threads.

2. **DKIM Selector Handling**:
   - DKIM cannot be discovered by root zone inspection.
   - Probing common selectors (`selector1`, `google`, `s1`, etc.) is heuristic and prone to false negatives.
   - **Wildcard Defense**: A TXT hit on `<selector>._domainkey.<domain>` must be inspected for `p=` or `v=DKIM1`. Do NOT mark DKIM found just because a DNS record resolved (prevents wildcard false positives).
   - Support dynamic user-provided selectors passed via query param or header.

3. **Backend Stack**:
   - Python 3.10+
   - Asynchronous/FastAPI endpoints (or Flask/MERN integration proxy).

---

## Commands & Development Workflow

- **Install Dependencies**: `pip install dnspython fastapi uvicorn pydantic`
- **Run Local Server**: `uvicorn app.main:app --reload --port 8000`
- **Run Tests**: `pytest tests/`

---

## Code Style & Error Handling
- Use typed Python (`pydantic` schemas for API inputs/outputs).
- Handle DNS exceptions gracefully: `dns.resolver.NXDOMAIN`, `dns.resolver.NoAnswer`, `dns.resolver.Timeout`, and `dns.resolver.NoNameservers` must never crash the service; return standardized empty/failed payload models.
2. UI Information RequirementsTo solve the selector discovery problem for your users, the frontend must collect specific inputs and clearly communicate what the results mean.A. Input Form ElementsDomain Input (Required): e.g., company.comCustom DKIM Selector Input (Optional): Text field allowing one or more comma-separated selectors (e.g., k1, pps1, 2024mail). Provide a helper tooltip:"DKIM selectors cannot be discovered automatically if non-standard. If known from an email header (s= tag), enter it here.""Extract from Email Header" Accordion/Box (Recommended): A textarea where users can paste raw email headers. Your backend parses the s= (selector) and d= (domain) tags automatically.DNS Resolver Override (Advanced dropdown): Default (System / 1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9).  B. Result Display & BadgesOverall Status Banner:Passed / Whitelisted (Green): All Section 7 criteria met.Action Required / Review (Amber/Red): Missing DKIM or permissive SPF/DMARC.Granular Breakdown Table/Cards:SPF Status: Show policy badge (-all, ~all, ?all, +all, or None) alongside the raw record string.DMARC Status: Show policy (reject, quarantine, or none) and report recipient (rua=).DKIM Status & Disclaimers:If found: List verified selectors (e.g., selector1, s1).If NOT found: Show an amber notice:"No common DKIM selector found. This does not confirm the sender lacks DKIM; they may use an unlisted selector. Please supply their selector or send a test email to verify."  3. Implementation PlanPhase 1: Python Core Engine ──> Phase 2: REST API Endpoints ──> Phase 3: UI & Extraction
Phase 1: DNS & Validation Logic (app/services/dns_validator.py)Implement evaluate_spf(domain) checking for -all / ~all.  Implement evaluate_dmarc(domain) querying _dmarc.<domain> and validating p=quarantine|reject.  Implement evaluate_dkim(domain, custom_selectors=[]):Combine custom selectors with the common dictionary.  Filter responses to ensure p= or v=DKIM1 exists (prevent wildcard false positives).Implement raw header parser (email.parser.BytesParser) to extract d= and s= directly.Phase 2: API Layer (app/main.py)Create POST /api/v1/validate-domain:Accepts { domain: str, selectors: Optional[List[str]], raw_header: Optional[str] }.Returns full evaluation payload with meets_qualification: bool.Create POST /api/v1/validate-batch:Uses asyncio or worker threads to test lists of domains concurrently.Phase 3: Frontend IntegrationBuild domain input with the optional selector/email-header dropzone.Render Section 7 qualification status cards.Add a "Copy Governance JSON/CSV" export button for compliance audit trails.
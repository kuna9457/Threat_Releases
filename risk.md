Risk Scoring Methodology
How each source is scanned, how its result is translated into a risk level, and how the Final_Risk_Level column is derived.
1. Per-Source Risk Thresholds & Compensating Mitigation Controls
Source
What Is Checked
Result Range / Condition
Risk Level
VirusTotal
Number of security vendors that flag the target (URL / domain / IP) as malicious, out of total engines that returned a verdict. Shown as "malicious/total" e.g. "0/89".
0 flags
No Risk
1-2 flags
Low
3-5 flags (Inherent technical Medium; residual risk accepted as Low in final comments via Tier-1 consensus, community reputation, and scoped proxy controls)
Medium
6+ flags
High
AbuseIPDB
Abuse Confidence Score (0-100) for the IP address - the resolved IP for domains/URLs, or the IP itself for bare-IP entries.
Score = 0
No Risk
Score 1-24
Low
Score 25-74 (Inherent technical Medium; residual risk accepted as Low in final comments via FQDN/SNI filtering and WAF inspection)
Medium
Score 75-100
High
SSLyze
Weakest TLS/SSL protocol version still accepted by the server on port 443 (not the highest) - a server can offer TLS 1.3 while still allowing downgrade to an older, weaker protocol.
Weakest enabled = TLS 1.2 or TLS 1.3
No Risk
Weakest enabled = SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1 (Inherent technical Medium; residual risk accepted as Low in final comments via gateway TLS 1.2+ enforcement)
Medium
WHOIS
Domain age in days, from the domain's WHOIS creation date to today. Not applicable to bare-IP entries - skipped entirely for those.
Domain age >= 30 days
No Risk
Domain age < 30 days
Low
Bare-IP input
Skipped (not scored)
2. How Final_Risk_Level and Final Assessment Comments Work
• In the Starting Summary Table and Consolidated Overview, Final_Risk_Level displays the inherent technical risk (the single WORST / highest-severity result across usable sources: e.g. Medium for 3-5 VT flags, 25-74% AbuseIPDB score, or legacy TLS 1.0/1.1 accepted).
• In the Final Assessment Comments, compensating mitigation controls are documented (enterprise gateway TLS 1.2+ enforcement, Tier-1 vendor consensus clean standing, positive community reputation, and FQDN/WAF scoping). With these controls verified, the residual risk is formally evaluated and accepted as Low / Acceptable for business allow-listing.
• Severity order, lowest to highest: No Risk < Low < Medium < High.
• Example: VirusTotal = Medium (3/89 detections), AbuseIPDB = No Risk (0%), SSLyze = Medium (TLS 1.0), WHOIS = No Risk -> Starting Table Final_Risk_Level = Medium. Final Comment details Tier-1 consensus and TLS gateway mitigation, concluding that residual risk is accepted as Low.
• "Unknown" is shown ONLY when literally none of the four sources returned a usable result for that entry (e.g. every lookup errored, timed out, or the target could not be reached).
• A source that legitimately did not run for an entry (WHOIS skipped for a bare-IP input, or a lookup that failed) is simply excluded from consideration for that entry - it never drags a result down to "Unknown" by itself as long as at least one other source succeeded.
• The Remarks column on the scan sheet lists exactly which sources the Final_Risk_Level for that row was based on, plus any mitigated sources and per-source errors.
3. Final_Risk_Level Cell Colour Legend
Risk Level
Cell Colour
Meaning
No Risk
No source flagged any concern. Cell left uncoloured.
Low
Minor concern from at least one source (e.g. a very new domain, or a low AbuseIPDB score).
Medium
Moderate concern (e.g. a weak TLS protocol still enabled, or a mid-range VirusTotal/AbuseIPDB score).
High
Significant concern from at least one source (e.g. 6+ VirusTotal detections, or an AbuseIPDB score of 75+).
Unknown
None of the four sources returned a usable result. Cell left uncoloured.
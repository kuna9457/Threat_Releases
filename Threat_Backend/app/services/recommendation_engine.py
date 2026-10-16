def generate_recommendations(request_types: list[str], residual_risk: int) -> dict:
    threat_analysis = []
    suggested_controls = []
    
    if "Allow Upload" in request_types:
        threat_analysis.extend(["Possible data exfiltration", "Malware upload risk"])
        suggested_controls.extend(["Restrict uploads to approved users", "Restrict allowed file types", "Monitor upload activity in SIEM"])
        
    if "Disable SSL Inspection" in request_types:
        threat_analysis.extend(["Hidden encrypted traffic", "Malware hidden in encrypted traffic", "Phishing bypass"])
        suggested_controls.extend(["Restrict domains", "Enable endpoint EDR", "Enable network monitoring"])

    if "Sandbox Bypass" in request_types:
        threat_analysis.extend(["Zero-day malware execution", "Unanalyzed malicious payloads"])
        suggested_controls.extend(["Endpoint AV", "Enable session logging"])
        
    if "Remove Browser Isolation" in request_types:
        threat_analysis.extend(["Malicious code execution in browser", "Phishing vulnerability"])
        suggested_controls.extend(["URL Filtering", "DNS Security"])
        
    if "Allow External Sharing" in request_types:
        threat_analysis.extend(["Data exfiltration", "Unauthorized data access"])
        suggested_controls.extend(["DLP", "CASB", "MFA"])
        
    if "Allow Executable Download" in request_types:
        threat_analysis.extend(["Malware infection", "Ransomware"])
        suggested_controls.extend(["Endpoint AV", "EDR", "File Type Restriction"])
        
    if "Allow Remote Access Tool" in request_types:
        threat_analysis.extend(["Unauthorized access", "Lateral movement"])
        suggested_controls.extend(["MFA", "SIEM Monitoring", "Logging Enabled"])
        
    if "Allow Browser Extension" in request_types:
        threat_analysis.extend(["Data theft", "Browser hijacking"])
        suggested_controls.extend(["Endpoint AV", "Logging Enabled"])
        
    if "Allow Download" in request_types:
        threat_analysis.extend(["Malware download", "Phishing"])
        suggested_controls.extend(["Endpoint AV", "URL Filtering"])
        
    # Deduplicate
    threat_analysis = list(set(threat_analysis))
    suggested_controls = list(set(suggested_controls))
    
    if residual_risk > 60:
        final_rec = "BLOCK - RISK TOO HIGH"
    elif residual_risk > 40:
        final_rec = "ALLOW WITH COMPENSATING CONTROLS"
    else:
        final_rec = "ALLOW"
        
    return {
        "threat_analysis": threat_analysis,
        "suggested_mitigation_controls": suggested_controls,
        "final_recommendation": final_rec
    }

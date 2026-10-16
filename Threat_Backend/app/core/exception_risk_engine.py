def calculate_inherent_risk(request_types: list[str], url_scan_result: dict) -> int:
    score = 0
    
    if "Allow Upload" in request_types: score += 20
    if "Allow Download" in request_types: score += 15
    if "Disable SSL Inspection" in request_types: score += 40
    if "Sandbox Bypass" in request_types: score += 35
    if "Remove Browser Isolation" in request_types: score += 30
    if "Allow External Sharing" in request_types: score += 25
    if "Allow Executable Download" in request_types: score += 30
    if "Allow Remote Access Tool" in request_types: score += 40
    if "Allow Browser Extension" in request_types: score += 20
    
    vt_malicious = url_scan_result.get("data", {}).get("virustotal", {}).get("malicious", 0)
    if vt_malicious > 0:
        score += 40
        
    domain_age = url_scan_result.get("data", {}).get("domain_age")
    if domain_age is None or domain_age == "Unknown":
        score += 20
    elif isinstance(domain_age, (int, float)) and domain_age < 30:
        score += 25
        
    return min(100, score)

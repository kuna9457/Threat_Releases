CONTROL_REDUCTION_MATRIX = {
    "DLP": 15,
    "EDR": 10,
    "CASB": 15,
    "MFA": 5,
    "SIEM Monitoring": 10,
    "Logging Enabled": 5,
    "URL Filtering": 10,
    "File Type Restriction": 15,
    "Endpoint AV": 5,
    "DNS Security": 10,
    "SSL Inspection": 20
}

def apply_controls(inherent_risk: int, controls: list[str]) -> tuple[int, list[dict]]:
    residual_risk = inherent_risk
    applied = []
    for c in controls:
        if c in CONTROL_REDUCTION_MATRIX:
            reduction = CONTROL_REDUCTION_MATRIX[c]
            residual_risk -= reduction
            applied.append({"control": c, "risk_reduction": reduction})
    
    return max(0, residual_risk), applied

def classify_risk(score: int) -> str:
    if score <= 20:
        return "Low"
    elif score <= 40:
        return "Moderate"
    elif score <= 60:
        return "High"
    else:
        return "Critical"

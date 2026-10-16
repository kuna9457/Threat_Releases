def decide_verdict(score: int):
    if score >= 80:
        return "BLOCK"
    elif score >= 40:
        return "REVIEW"
    return "ALLOW"

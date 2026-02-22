RISK_BASE_SCORES = {
    "LOW": 3.0,
    "MEDIUM": 5.0,
    "HIGH": 7.5,
    "CRITICAL": 9.0,
    "CRITICAL_CHAINED": 9.8
}


def calculate_service_score(service):
    base = RISK_BASE_SCORES.get(service.get("base_risk"), 1.0)

    # Small boost if externally confirmed
    if service.get("exposure", {}).get("level") == "EXTERNAL_CONFIRMED":
        base += 0.3

    # Cap at 10
    return min(round(base, 1), 10.0)


def score_services(services):
    for svc in services:
        svc["numeric_score"] = calculate_service_score(svc)
        svc["risk_label"] = risk_label_from_score(svc["numeric_score"])
    return services


def calculate_overall_risk(services):
    if not services:
        return 0.0

    highest = max(svc.get("numeric_score", 0) for svc in services)

    # Weighted average
    avg = sum(svc.get("numeric_score", 0) for svc in services) / len(services)

    # Blend highest impact + overall exposure
    overall_score = round((highest * 0.6) + (avg * 0.4), 2)

    return min(overall_score, 10.0)


def compromise_probability(score):
    """
    Convert 0-10 score into % probability model.
    """
    return round((score / 10) * 100, 1)

def risk_label_from_score(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "INFO"
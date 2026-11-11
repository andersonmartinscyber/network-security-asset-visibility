"""Contextual security risk prioritization."""

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}

CRITICALITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}


def calculate_risk_score(severity, asset_criticality):
    """Calculate a contextual risk score from 0 to 100."""

    if severity not in SEVERITY_WEIGHTS:
        raise ValueError(f"Invalid finding severity: {severity}")

    if asset_criticality not in CRITICALITY_WEIGHTS:
        raise ValueError(
            f"Invalid asset criticality: {asset_criticality}"
        )

    return round(
        SEVERITY_WEIGHTS[severity] * 0.60
        + CRITICALITY_WEIGHTS[asset_criticality] * 0.40,
        2,
    )


def classify_risk_priority(score):
    """Classify a validated contextual risk score."""

    if isinstance(score, bool) or not isinstance(
        score, (int, float)
    ):
        raise ValueError("Risk score must be numeric")

    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")

    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def prioritize_findings(findings):
    """Return findings sorted by contextual risk score."""

    prioritized = []

    for finding in findings:
        score = calculate_risk_score(
            finding["severity"],
            finding["asset_criticality"],
        )

        enriched = {
            **finding,
            "risk_score": score,
            "risk_priority": classify_risk_priority(score),
        }

        prioritized.append(enriched)

    return sorted(
        prioritized,
        key=lambda item: (
            -item["risk_score"],
            item["asset_id"],
            item["rule_id"],
        ),
    )
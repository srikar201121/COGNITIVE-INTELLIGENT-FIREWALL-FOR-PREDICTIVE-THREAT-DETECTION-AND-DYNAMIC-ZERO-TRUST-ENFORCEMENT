def calculate_risk(anomaly_score):
    """
    Converts anomaly score into risk score (0–100)
    Lower anomaly score → higher risk
    """

    # Normalize score (Isolation Forest scores are usually negative)
    risk_score = abs(anomaly_score) * 1000

    if risk_score < 30:
        risk_level = "LOW"
    elif risk_score < 70:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return round(risk_score, 2), risk_level

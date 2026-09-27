def calculate_risk(features):
    score = 0
    reasons = []

    # 1. HTTPS check
    if not features["uses_https"]:
        score += 10
        reasons.append("URL does not use HTTPS")

    # 2. IP address check
    if features["uses_ip_address"]:
        score += 30
        reasons.append("URL uses an IP address instead of a domain")

    # 3. @ symbol check
    if features["contains_at_symbol"]:
        score += 25
        reasons.append("URL contains an @ symbol")

    # 4. URL length check
    if features["url_length"] > 75:
        score += 10
        reasons.append("URL is unusually long")

    # 5. Suspicious keyword check
    keyword_count = features["suspicious_keyword_count"]

    if keyword_count > 0:
        keyword_score = min(keyword_count * 5, 25)
        score += keyword_score

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(features["suspicious_keywords"])
        )

    # Never allow score above 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }
def calculate_iso_risk_score(ttp_count, country_count, source_count, regional_focus=False):
    regional_multiplier = 1.2 if regional_focus else 1.0
    threat_frequency = min(ttp_count / 50, 1.0) * 30 * regional_multiplier
    geographic_spread = min(country_count / 20, 1.0) * 25 * regional_multiplier
    source_diversity = min(source_count / 10, 1.0) * 20
    base_threat = 25
    total_score = threat_frequency + geographic_spread + source_diversity + base_threat
    return min(total_score, 100)

def calculate_nist_risk_score(ttp_count, country_count, unique_techniques, regional_focus=False):
    regional_multiplier = 1.15 if regional_focus else 1.0
    likelihood = min(len(unique_techniques) / 30, 1.0) * 40 * regional_multiplier
    impact = min(country_count / 15, 1.0) * 35 * regional_multiplier
    vulnerability = min(ttp_count / 40, 1.0) * 25
    total_score = likelihood + impact + vulnerability
    return min(total_score, 100)

def get_risk_level(score):
    if score >= 75:
        return "HIGH", "#ff4444"
    elif score >= 50:
        return "MEDIUM", "#ffaa00"
    else:
        return "LOW", "#44ff44"

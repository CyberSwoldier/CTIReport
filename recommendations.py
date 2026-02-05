"""
Course Recommendation Engine
----------------------------
Uses TF‑IDF, frequency analysis, and trend forecasting
to recommend training courses, simulations, and zero‑day briefings.
"""

from collections import Counter
import streamlit as st

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False


def recommend_courses(trend_data, ttp_columns, forecast_trend):
    """
    ML-powered course recommendations using TF-IDF and pattern analysis.
    """

    recommendations = {
        'priority_courses': [],
        'priority_simulations': [],
        'priority_zero_day': [],
        'ml_confidence': 0.0
    }

    if trend_data.empty:
        return recommendations

    # Extract TTPs
    all_ttps = []
    for col in ttp_columns:
        if col in trend_data.columns:
            ttps = trend_data[col].dropna()
            for ttp_val in ttps:
                if isinstance(ttp_val, (list, tuple, set)):
                    all_ttps.extend([str(x).lower() for x in ttp_val if x not in [None, "None"]])
                elif str(ttp_val) != "None":
                    all_ttps.append(str(ttp_val).lower())

    if not all_ttps:
        return recommendations

    # TF-IDF scoring
    if ML_AVAILABLE and len(all_ttps) > 5:
        try:
            vectorizer = TfidfVectorizer(max_features=20)
            tfidf_matrix = vectorizer.fit_transform(all_ttps)
            feature_names = vectorizer.get_feature_names_out()
            tfidf_scores = tfidf_matrix.sum(axis=0).A1

            top_keywords = sorted(
                zip(feature_names, tfidf_scores),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            recommendations['ml_confidence'] = 0.90

        except Exception:
            top_keywords = []
            recommendations['ml_confidence'] = 0.65
    else:
        top_keywords = []
        recommendations['ml_confidence'] = 0.65

    # Frequency analysis
    ttp_counter = Counter(all_ttps)
    top_ttps = ttp_counter.most_common(15)

    # Category mapping
    threat_categories = {
        'phishing': ['phishing', 'email', 'spear', 'social engineering', 'credential'],
        'malware': ['malware', 'ransomware', 'trojan', 'virus', 'payload'],
        'exploitation': ['exploit', 'vulnerability', 'zero-day', 'cve', 'patch'],
        'lateral': ['lateral', 'movement', 'privilege', 'escalation', 'persistence'],
        'data': ['exfiltration', 'data theft', 'extraction', 'stealing'],
        'ai': ['ai', 'deepfake', 'machine learning', 'automated', 'generated'],
        'supply_chain': ['supply chain', 'third party', 'vendor', 'partner'],
        'cloud': ['cloud', 'saas', 'azure', 'aws', 'o365'],
        'mobile': ['mobile', 'smartphone', 'app', 'byod'],
        'iot': ['iot', 'smart device', 'connected']
    }

    # Weighted scoring
    category_scores = {cat: 0.0 for cat in threat_categories}

    for ttp, count in top_ttps:
        for category, keywords in threat_categories.items():
            if any(keyword in ttp for keyword in keywords):
                importance_boost = 1.5 if any(k in ttp for k, _ in top_keywords) else 1.0
                category_scores[category] += count * importance_boost

    sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)

    trend_modifier = "Advanced" if forecast_trend and forecast_trend > 0 else "Foundational"
    urgency = "Priority" if forecast_trend and forecast_trend > 5 else "Standard"

    # Generate recommendations
    for category, score in sorted_categories[:4]:
        if score <= 0:
            continue

        if category == 'phishing':
            recommendations['priority_courses'].append(f"{trend_modifier} Phishing Defense")
            recommendations['priority_simulations'].append(f"{urgency}: Executive Impersonation Campaign")
            recommendations['priority_zero_day'].append("AI-Generated Phishing Detection")

        elif category == 'malware':
            recommendations['priority_courses'].append(f"{trend_modifier} Malware Threat Landscape")
            recommendations['priority_simulations'].append(f"{urgency}: Ransomware Crisis Simulation")
            recommendations['priority_zero_day'].append("Fileless Malware Techniques")

        elif category == 'exploitation':
            recommendations['priority_courses'].append("Zero-Day Vulnerability Response")
            recommendations['priority_simulations'].append(f"{urgency}: Patch Management Crisis")
            recommendations['priority_zero_day'].append("Critical CVE Briefing")

        elif category == 'lateral':
            recommendations['priority_courses'].append("Insider Threat Recognition")
            recommendations['priority_simulations'].append(f"{urgency}: Network Compromise Simulation")
            recommendations['priority_zero_day'].append("APT Movement Patterns")

        elif category == 'ai':
            recommendations['priority_courses'].append(f"{trend_modifier} AI-Powered Threat Recognition")
            recommendations['priority_simulations'].append(f"{urgency}: Deepfake Executive Simulation")
            recommendations['priority_zero_day'].append("LLM-Generated Social Engineering")

        elif category == 'supply_chain':
            recommendations['priority_courses'].append("Supply Chain Security Fundamentals")
            recommendations['priority_simulations'].append(f"{urgency}: Vendor Compromise Response")
            recommendations['priority_zero_day'].append("Third-Party Risk Briefing")

        elif category == 'cloud':
            recommendations['priority_courses'].append(f"{trend_modifier} Cloud Security Awareness")
            recommendations['priority_simulations'].append(f"{urgency}: SaaS Credential Harvesting")
            recommendations['priority_zero_day'].append("Multi-Cloud Misconfiguration Risks")

    # Baseline fallback
    if not recommendations['priority_courses']:
        recommendations['priority_courses'] = [
            "Cybersecurity Fundamentals",
            "Email Security Best Practices",
            "Identity Protection & MFA"
        ]

    if not recommendations['priority_simulations']:
        recommendations['priority_simulations'] = [
            "Baseline Phishing Assessment",
            "Social Engineering Awareness",
            "Credential Security Simulation"
        ]

    if not recommendations['priority_zero_day']:
        recommendations['priority_zero_day'] = [
            "2025 Threat Landscape Overview",
            "Emerging Attack Vector Briefing",
            "Geopolitical Cyber Threat Analysis"
        ]

    return recommendations

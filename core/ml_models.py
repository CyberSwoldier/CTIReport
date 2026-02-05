import numpy as np
import pandas as pd
import streamlit as st
from collections import Counter

try:
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler, PolynomialFeatures
    from sklearn.linear_model import LinearRegression
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

from .geo_utils import get_nordic_baltic_countries


# ============================================================
#  CLUSTERING
# ============================================================

def ml_cluster_threat_patterns(all_ttps):
    if not ML_AVAILABLE or len(all_ttps) < 5:
        return None, None
    try:
        vectorizer = TfidfVectorizer(max_features=50, ngram_range=(1, 2))
        X = vectorizer.fit_transform(all_ttps)

        best_score = -1
        best_k = 0
        best_model = None

        for k in range(2, min(6, len(all_ttps))):
            model = KMeans(n_clusters=k, random_state=42, n_init=10)
            labels = model.fit_predict(X)
            score = silhouette_score(X, labels)
            if score > best_score:
                best_score = score
                best_k = k
                best_model = model

        if best_model is None:
            return None, None

        labels = best_model.labels_
        clusters = {i: [] for i in range(best_k)}
        for idx, label in enumerate(labels):
            clusters[label].append(all_ttps[idx])

        cluster_info = {}
        total = len(all_ttps)
        for cid, items in clusters.items():
            cluster_info[cid] = {
                "size": len(items),
                "percentage": (len(items) / total) * 100,
            }

        return clusters, cluster_info
    except Exception as e:
        st.warning(f"Clustering analysis unavailable: {e}")
        return None, None


# ============================================================
#  ANOMALY DETECTION
# ============================================================

def ml_detect_anomalies(threat_vectors):
    if not ML_AVAILABLE or len(threat_vectors) < 10:
        return None, None
    try:
        scaler = StandardScaler()
        X = scaler.fit_transform(threat_vectors)

        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X)
        anomaly_scores = iso_forest.score_samples(X)

        anomalies = np.where(anomaly_labels == -1)[0]
        return anomaly_scores, anomalies
    except Exception as e:
        st.warning(f"Anomaly detection unavailable: {e}")
        return None, None


# ============================================================
#  TIME SERIES FORECASTING
# ============================================================

def ml_forecast_time_series(historical_data, periods=4):
    if not ML_AVAILABLE or len(historical_data) < 3:
        return None, None
    try:
        daily_counts = historical_data.groupby('report_date').size().reset_index(name='count')
        daily_counts = daily_counts.sort_values('report_date')
        if len(daily_counts) < 2:
            return None, None

        daily_counts['days_since_start'] = (daily_counts['report_date'] - daily_counts['report_date'].min()).dt.days
        X = daily_counts['days_since_start'].values.reshape(-1, 1)
        y = daily_counts['count'].values

        poly = PolynomialFeatures(degree=2)
        X_poly = poly.fit_transform(X)

        model = LinearRegression()
        model.fit(X_poly, y)

        predictions = model.predict(X_poly)
        residuals = y - predictions
        std_error = np.std(residuals)

        last_date = daily_counts['report_date'].max()
        last_days = daily_counts['days_since_start'].max()

        forecast_dates = pd.date_range(start=last_date + pd.Timedelta(days=7), periods=periods, freq='7D')
        forecast_days = np.array([last_days + 7 * (i + 1) for i in range(periods)]).reshape(-1, 1)

        forecast_poly = poly.transform(forecast_days)
        forecast_values = model.predict(forecast_poly)
        forecast_values = np.maximum(forecast_values, 0)

        confidence_margin = 1.96 * std_error

        forecast_df = pd.DataFrame({
            'report_date': forecast_dates,
            'count': forecast_values,
            'lower_bound': np.maximum(forecast_values - confidence_margin, 0),
            'upper_bound': forecast_values + confidence_margin,
            'type': 'forecast'
        })

        trend = forecast_values[-1] - y[-1]
        return forecast_df, trend
    except Exception as e:
        st.warning(f"Time series forecasting unavailable: {e}")
        return None, None


# ============================================================
#  ATTACK-TYPE FORECASTING
# ============================================================

def ml_forecast_by_attack_type(trend_data, ttp_columns, top_n=5, periods=4):
    if not ML_AVAILABLE or trend_data.empty or len(trend_data) < 3:
        return None
    try:
        melted = trend_data.melt(id_vars=['report_date'], value_vars=ttp_columns,
                                 var_name="ttp_col", value_name="TTP")
        if any(melted["TTP"].apply(lambda x: isinstance(x, (list, tuple, set)))):
            melted = melted.explode("TTP")
        melted = melted.dropna(subset=["TTP"])
        melted = melted[melted["TTP"] != "None"]

        top_ttps = (melted.groupby("TTP").size()
                    .sort_values(ascending=False)
                    .head(top_n).index.tolist())

        forecasts = {}
        for ttp in top_ttps:
            ttp_data = melted[melted["TTP"] == ttp]
            ttp_counts = ttp_data.groupby('report_date').size().reset_index(name='count')
            ttp_counts = ttp_counts.sort_values('report_date')
            if len(ttp_counts) < 2:
                continue

            ttp_counts['days_since_start'] = (ttp_counts['report_date'] - ttp_counts['report_date'].min()).dt.days
            X = ttp_counts['days_since_start'].values.reshape(-1, 1)
            y = ttp_counts['count'].values

            poly = PolynomialFeatures(degree=2)
            X_poly = poly.fit_transform(X)

            model = LinearRegression()
            model.fit(X_poly, y)

            predictions = model.predict(X_poly)
            residuals = y - predictions
            std_error = np.std(residuals) if len(residuals) > 1 else np.std(y) * 0.3

            last_date = ttp_counts['report_date'].max()
            last_days = ttp_counts['days_since_start'].max()

            forecast_dates = pd.date_range(start=last_date + pd.Timedelta(days=7), periods=periods, freq='7D')
            forecast_days = np.array([last_days + 7 * (i + 1) for i in range(periods)]).reshape(-1, 1)

            forecast_poly = poly.transform(forecast_days)
            forecast_values = model.predict(forecast_poly)
            forecast_values = np.maximum(forecast_values, 0)

            trend = forecast_values[-1] - y[-1]
            avg_forecast = forecast_values.mean()
            avg_historical = y.mean()

            forecasts[ttp] = {
                'historical': ttp_counts[['report_date', 'count']],
                'forecast_dates': forecast_dates,
                'forecast_values': forecast_values,
                'confidence_lower': np.maximum(forecast_values - 1.96 * std_error, 0),
                'confidence_upper': forecast_values + 1.96 * std_error,
                'trend': trend,
                'trend_direction': 'increasing' if trend > 0 else 'decreasing' if trend < 0 else 'stable',
                'avg_forecast': avg_forecast,
                'avg_historical': avg_historical,
                'change_percentage': ((avg_forecast - avg_historical) / avg_historical * 100) if avg_historical > 0 else 0
            }
        return forecasts
    except Exception as e:
        st.warning(f"Attack-specific forecasting unavailable: {e}")
        return None


# ============================================================
#  EXECUTIVE SUMMARY
# ============================================================

def ml_generate_executive_summary(report_data, ttp_columns, country_columns, iso_score, nist_score):
    if report_data is None or report_data.empty:
        return {
            "threat_level": "UNKNOWN",
            "ml_confidence": 0.0,
            "key_insights": [],
            "attack_patterns": [],
            "recommendations": []
        }, "#888888"

    avg_risk = (iso_score + nist_score) / 2 if iso_score and nist_score else 0

    if avg_risk >= 80:
        threat_level, color = "CRITICAL", "#ff4444"
    elif avg_risk >= 60:
        threat_level, color = "HIGH", "#ffaa00"
    elif avg_risk >= 40:
        threat_level, color = "ELEVATED", "#ffff00"
    elif avg_risk > 0:
        threat_level, color = "MODERATE", "#44ff44"
    else:
        threat_level, color = "LOW", "#888888"

    ml_confidence = min(0.95, max(0.3, len(report_data) / 50))

    # TTP extraction
    all_ttps = []
    for col in ttp_columns:
        vals = report_data[col].dropna()
        for v in vals:
            if isinstance(v, (list, tuple, set)):
                all_ttps.extend([str(x) for x in v if x not in [None, "None"]])
            elif str(v) != "None":
                all_ttps.append(str(v))

    ttp_counter = Counter(all_ttps)
    top_ttps = [t for t, _ in ttp_counter.most_common(5)]

    attack_patterns = []
    if top_ttps:
        attack_patterns.append(f"Most frequently observed techniques: {', '.join(top_ttps)}")

    # Country exposure
    all_countries = []
    for col in country_columns:
        vals = report_data[col].dropna()
        all_countries.extend([str(v) for v in vals if str(v) != "None"])

    unique_countries = sorted(set(all_countries))
    nordic_baltic = set(get_nordic_baltic_countries())
    nb_overlap = nordic_baltic.intersection(unique_countries)

    key_insights = []
    if nb_overlap:
        key_insights.append(f"Active targeting observed in Nordic/Baltic region: {', '.join(sorted(nb_overlap))}.")
    if unique_countries:
        key_insights.append(f"Geographic spread across {len(unique_countries)} countries.")

    # Recommendations
    recommendations = []
    if threat_level in ["CRITICAL", "HIGH"]:
        recommendations.append("Escalate to executive briefing and increase monitoring of high-risk geographies.")
        recommendations.append("Run targeted phishing and ransomware simulations.")
    elif threat_level in ["ELEVATED", "MODERATE"]:
        recommendations.append("Reinforce security awareness training in exposed regions.")
        recommendations.append("Review access controls and MFA coverage.")
    else:
        recommendations.append("Maintain baseline monitoring and periodic awareness campaigns.")

    summary = {
        "threat_level": threat_level,
        "ml_confidence": ml_confidence,
        "key_insights": key_insights,
        "attack_patterns": attack_patterns,
        "recommendations": recommendations,
    }

    return summary, color


# ============================================================
#  THREAT ACTOR PROFILING
# ============================================================

def ml_threat_actor_profiling(report_data, ttp_columns):
    if report_data is None or report_data.empty or not ttp_columns:
        return None

    all_ttps = []
    for col in ttp_columns:
        vals = report_data[col].dropna()
        for v in vals:
            if isinstance(v, (list, tuple, set)):
                all_ttps.extend([str(x) for x in v if x not in [None, "None"]])
            elif str(v) != "None":
                all_ttps.append(str(v))

    if not all_ttps:
        return None

    counter = Counter(all_ttps)
    top = counter.most_common(12)

    actors = {
        "Actor Cluster A": top[0:4],
        "Actor Cluster B": top[4:8],
        "Actor Cluster C": top[8:12],
    }

    profiles = {}
    total_incidents = len(all_ttps)

    for name, ttps in actors.items():
        if not ttps:
            continue
        incident_count = sum(c for _, c in ttps)
        percentage = (incident_count / total_incidents) * 100 if total_incidents else 0

        sophistication = (
            "High" if incident_count >= 10 else
            "Medium" if incident_count >= 5 else
            "Low"
        )

        profiles[name] = {
            "type": "Clustered Threat Activity",
            "sophistication": sophistication,
            "incident_count": incident_count,
            "percentage": percentage,
            "signature_ttps": [t for t, _ in ttps],
        }

    return profiles


# ============================================================
#  AUTOMATED THREAT PRIORITIZATION
# ============================================================

def ml_automated_threat_prioritization(report_data, ttp_columns, country_columns, iso_score, nist_score):
    if report_data is None or report_data.empty or not ttp_columns:
        return []

    all_ttps = []
    ttp_geo = {}

    for _, row in report_data.iterrows():
        row_ttps = []
        for col in ttp_columns:
            val = row.get(col)
            if isinstance(val, (list, tuple, set)):
                row_ttps.extend([str(x) for x in val if x not in [None, "None"]])
            elif pd.notna(val) and str(val) != "None":
                row_ttps.append(str(val))

        row_countries = []
        for ccol in country_columns:
            cval = row.get(ccol)
            if isinstance(cval, (list, tuple, set)):
                row_countries.extend([str(x) for x in cval if x not in [None, "None"]])
            elif pd.notna(cval) and str(cval) != "None":
                row_countries.append(str(cval))

        for t in row_ttps:
            all_ttps.append(t)
            ttp_geo.setdefault(t, set()).update(row_countries)

    if not all_ttps:
        return []

    counter = Counter(all_ttps)
    nordic_baltic = set(get_nordic_baltic_countries())

    prioritized = []
    for ttp, freq in counter.most_common():
        countries = ttp_geo.get(ttp, set())
        geo_spread = len(countries)
        nb_impact = bool(nordic_baltic.intersection(countries))

        base_score = freq * 10 + geo_spread * 5
        if nb_impact:
            base_score *= 1.3
        if iso_score:
            base_score *= (0.5 + iso_score / 200)
        if nist_score:
            base_score *= (0.5 + nist_score / 200)

        if base_score >= 150:
            priority, color = "CRITICAL", "#ff4444"
        elif base_score >= 100:
            priority, color = "HIGH", "#ffaa00"
        elif base_score >= 60:
            priority, color = "ELEVATED", "#ffff00"
        else:
            priority, color = "MODERATE", "#44ff44"

        prioritized.append({
            "ttp": ttp,
            "frequency": freq,
            "countries": list(countries),
            "nordic_impact": nb_impact,
            "score": base_score,
            "priority": priority,
            "color": color,
        })

    prioritized.sort(key=lambda x: x["score"], reverse=True)
    return prioritized


# ============================================================
#  NORDIC GEOGRAPHIC RISK FORECAST
# ============================================================

def ml_nordic_geographic_risk_forecast(historical_data, country_columns, periods=4):
    if historical_data is None or historical_data.empty or not country_columns:
        return None

    nordic_baltic = set(get_nordic_baltic_countries())
    country_counts = Counter()

    for _, row in historical_data.iterrows():
        for col in country_columns:
            val = row.get(col)
            if isinstance(val, (list, tuple, set)):
                country_counts.update([str(x) for x in val if x not in [None, "None"]])
            elif pd.notna(val) and str(val) != "None":
                country_counts.update([str(val)])

    forecasts = {}
    for country, count in country_counts.items():
        if country not in nordic_baltic:
            continue

        if count >= 20:
            level = "CRITICAL"
        elif count >= 10:
            level = "ELEVATED"
        elif count >= 5:
            level = "MODERATE"
        else:
            level = "LOW"

        forecasts[country] = {
            "risk_level": level,
            "confidence": "high" if count >= 10 else "medium" if count >= 5 else "low",
            "trend": "increasing" if count >= 10 else "stable" if count >= 5 else "uncertain",
            "forecast_avg": max(1.0, count / 4),
        }

    return forecasts


# ============================================================
#  RESOURCE ALLOCATION OPTIMIZER
# ============================================================

def ml_resource_allocation_optimizer(prioritized_threats, iso_score, nist_score):
    if not prioritized_threats:
        return None

    total_score = sum(t["score"] for t in prioritized_threats)
    if total_score == 0:
        return None

    phishing_score = sum(t["score"] for t in prioritized_threats if "phish" in t["ttp"].lower())
    ransomware_score = sum(t["score"] for t in prioritized

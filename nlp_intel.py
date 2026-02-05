"""
NLP Intelligence Extraction Module
----------------------------------
Extracts keywords, attack vectors, techniques, targets, malware families,
and emerging patterns from TTP descriptions using TF‑IDF.
"""

import pandas as pd
import numpy as np
from collections import Counter
import streamlit as st

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False


def extract_nlp_intelligence(report_data, ttp_columns):
    """
    Extract key intelligence using NLP techniques.
    Returns:
        dict with:
            - top_keywords
            - attack_vectors
            - targets
            - techniques
            - malware_families
            - emerging_patterns
            - total_terms_analyzed
    """

    if not ML_AVAILABLE or report_data.empty or not ttp_columns:
        return None

    try:
        # Collect all TTP text
        all_text = []
        for col in ttp_columns:
            texts = report_data[col].dropna()
            for text in texts:
                if isinstance(text, (list, tuple, set)):
                    all_text.extend([str(x) for x in text if x not in [None, "None"]])
                elif str(text) != "None":
                    all_text.append(str(text))

        if not all_text:
            return None

        # TF-IDF keyword extraction
        vectorizer = TfidfVectorizer(max_features=30, stop_words='english', ngram_range=(1, 2))
        tfidf_matrix = vectorizer.fit_transform(all_text)

        feature_names = vectorizer.get_feature_names_out()
        tfidf_scores = tfidf_matrix.sum(axis=0).A1

        keyword_scores = sorted(
            zip(feature_names, tfidf_scores),
            key=lambda x: x[1],
            reverse=True
        )

        # Categorization
        attack_vectors = []
        targets = []
        techniques = []
        malware_families = []

        for keyword, score in keyword_scores[:20]:
            k = keyword.lower()

            if any(term in k for term in ['phishing', 'malware', 'ransomware', 'exploit', 'ddos']):
                attack_vectors.append((keyword, score))

            elif any(term in k for term in ['server', 'network', 'database', 'cloud', 'system']):
                targets.append((keyword, score))

            elif any(term in k for term in ['lateral', 'privilege', 'persistence', 'execution']):
                techniques.append((keyword, score))

            elif any(term in k for term in ['trojan', 'backdoor', 'rat', 'loader']):
                malware_families.append((keyword, score))

        # Emerging patterns
        text_counter = Counter(all_text)
        emerging_terms = [
            term for term, count in text_counter.most_common(40)
            if 2 <= count <= 5
        ]

        return {
            'top_keywords': keyword_scores[:10],
            'attack_vectors': attack_vectors[:5],
            'targets': targets[:5],
            'techniques': techniques[:5],
            'malware_families': malware_families[:3],
            'emerging_patterns': emerging_terms[:5],
            'total_terms_analyzed': len(all_text)
        }

    except Exception as e:
        st.warning(f"NLP intelligence extraction unavailable: {e}")
        return None

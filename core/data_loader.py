import os
import glob
import pandas as pd
import streamlit as st
import requests
from config import REPORTS_FOLDER, API_URL

def fetch_reports_from_github(local_folder=REPORTS_FOLDER):
    os.makedirs(local_folder, exist_ok=True)
    if not API_URL:
        return []
    try:
        r = requests.get(API_URL, timeout=10)
        r.raise_for_status()
        files = r.json()
    except Exception as e:
        st.error(f"Failed to list files from GitHub: {e}")
        return []

    downloaded = []
    for file in files:
        name = file.get("name", "")
        download_url = file.get("download_url", "")
        if name.startswith("ttp_reports_") and name.endswith((".xlsx", ".csv")):
            local_path = os.path.join(local_folder, name)
            if not os.path.exists(local_path):
                try:
                    fr = requests.get(download_url, timeout=15)
                    fr.raise_for_status()
                    with open(local_path, "wb") as f:
                        f.write(fr.content)
                    st.sidebar.success(f"Fetched {name}")
                except Exception as e:
                    st.sidebar.warning(f"Failed {name}: {e}")
                    continue
            downloaded.append(local_path)
    return downloaded

def load_local_reports(folder=REPORTS_FOLDER):
    files = glob.glob(os.path.join(folder, "ttp_reports_*.*"))
    all_data = []
    for f in files:
        try:
            if f.lower().endswith(".xlsx"):
                xls = pd.ExcelFile(f)
                sheet_name = "Human_Attacks" if "Human_Attacks" in xls.sheet_names else xls.sheet_names[0]
                df = pd.read_excel(xls, sheet_name=sheet_name)
            else:
                df = pd.read_csv(f)

            date_str = os.path.basename(f).replace("ttp_reports_", "").split(".")[0]
            df["report_date"] = pd.to_datetime(date_str, format="%d%m%y", errors="coerce")
            all_data.append(df)
        except Exception as e:
            st.warning(f"Could not read {f}: {e}")
            continue

    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        combined = combined.dropna(subset=["report_date"])
        if combined.empty:
            st.error("No valid data after combining reports.")
            st.stop()
        return combined
    else:
        st.error("No report files found in 'reports/'.")
        st.stop()

def get_ttp_and_country_columns(df):
    ttp_columns = [c for c in df.columns if c.lower().startswith("ttp_desc")]
    country_columns = [c for c in df.columns if c.lower().startswith("country_")]
    return ttp_columns, country_columns

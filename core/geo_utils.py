import pycountry
import maxminddb
import os
import streamlit as st

from config import ML_AVAILABLE

def get_nordic_baltic_countries():
    return [
        "Sweden", "Norway", "Denmark", "Finland", "Iceland",
        "Estonia", "Latvia", "Lithuania", "Poland", "Vietnam"
    ]

def country_to_iso3(name):
    try:
        return pycountry.countries.lookup(name).alpha_3
    except LookupError:
        return None

def ip_to_country(ip, mmdb_path="data/GeoLite2-Country.mmdb"):
    if not os.path.exists(mmdb_path):
        return None
    try:
        with maxminddb.open_database(mmdb_path) as reader:
            resp = reader.get(ip)
            if not resp:
                return None
            return resp.get("country", {}).get("names", {}).get("en")
    except Exception as e:
        st.warning(f"GeoIP lookup failed: {e}")
        return None

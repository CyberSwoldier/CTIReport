# Data Directory

This folder contains static data files used by the ML‑Powered Threat Intelligence Platform.

## 📁 Contents

### **1. GeoLite2-Country.mmdb**
This MaxMind database is used for IP‑to‑country geolocation.  
It enables the platform to enrich threat intelligence data with geographic context.

- File: `GeoLite2-Country.mmdb`
- Source: MaxMind GeoLite2
- License: Requires acceptance of MaxMind EULA  
  https://www.maxmind.com/en/geolite2/eula

### **2. Additional Static Data (Optional)**
You may store other reference datasets here, such as:

- Country mappings  
- Threat taxonomy files  
- MITRE ATT&CK reference tables  
- Custom enrichment datasets  

These files are not required but can extend platform capabilities.

---

## 🔄 Updating the GeoLite2 Database

MaxMind updates GeoLite2 databases weekly.

To update:

1. Create a MaxMind account (free)
2. Download the latest **GeoLite2-Country.mmdb**
3. Replace the existing file in this folder
4. Restart the Streamlit app

The platform will automatically use the updated database.

---

## 🔧 How the Application Uses This Folder

The `core/geo_utils.py` module loads the database:

```python
from core.geo_utils import ip_to_country

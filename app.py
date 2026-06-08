import streamlit as st
import requests
import re
import base64
from datetime import datetime

# ====== CONFIG ======
VT_API_KEY = st.secrets["VT_API_KEY"]

# ====== VIRUSTOTAL CHECK ======
def check_virustotal(ioc, ioc_type):
    headers = {"x-apikey": VT_API_KEY}
    
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        country = attrs.get("country", "Unknown")
        reputation = attrs.get("reputation", "N/A")
        return malicious, suspicious, total, country, reputation
    except:
        return 0, 0, 0, "Unknown", "N/A"

# ====== DETECT IOC TYPE ======
def detect_type(ioc):
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return "ip"
    elif ioc.startswith("http"):
        return "url"
    else:
        return "domain"

# ====== UI ======
st.set_page_config(
    page_title="Phishing Investigation Tool",
    page_icon="🔍",
    layout="centered"
)

st.title("🔍 Phishing Investigation Tool")
st.markdown("Paste any suspicious **IP address**, **domain**, or **URL** to instantly check if it's a threat.")
st.markdown("---")

ioc = st.text_input(
    "",
    placeholder="e.g. 185.220.101.34  or  malicious-site.com  or  http://suspicious.com/login"
)

if st.button("🔍 Investigate", use_container_width=True):
    if ioc.strip():
        ioc_type = detect_type(ioc.strip())
        
        with st.spinner("Analyzing threat intelligence..."):
            malicious, suspicious, total, country, reputation = check_virustotal(ioc.strip(), ioc_type)
        
        st.markdown("---")
        st.subheader("📊 Investigation Report")
        
        # Metrics row
        col1, col2, col3 = st.columns(3)
        col1.metric("Type Detected", ioc_type.upper())
        col2.metric("Malicious Engines", f"{malicious}/{total}")
        col3.metric("Suspicious Engines", f"{suspicious}/{total}")
        
        # Country and reputation for IPs
        if ioc_type == "ip":
            col4, col5 = st.columns(2)
            col4.metric("Country", country)
            col5.metric("Reputation Score", reputation)
        
        st.markdown("---")
        
        # Final verdict
        if malicious >= 10:
            st.error("🚨 VERDICT: MALICIOUS — Do not interact with this. High threat confirmed.")
        elif malicious >= 3 or suspicious >= 5:
            st.warning("⚠️ VERDICT: SUSPICIOUS — Treat with caution. Moderate threat detected.")
        else:
            st.success("✅ VERDICT: CLEAN — No significant threats detected.")
        
        # What this means section
        st.markdown("---")
        st.subheader("ℹ️ What does this mean?")
        if malicious >= 10:
            st.markdown("""
- This IP/domain/URL has been flagged by multiple security engines
- It may be associated with phishing, malware, or C2 servers
- **Do not click, visit, or interact with it**
- Report it to your security team immediately
            """)
        elif malicious >= 3:
            st.markdown("""
- This has been flagged by some security engines
- Exercise caution before interacting
- Consider blocking it as a precaution
            """)
        else:
            st.markdown("""
- No major security engines flagged this
- Still exercise normal caution online
- When in doubt, don't click
            """)
        
        st.caption(f"Powered by VirusTotal Threat Intelligence | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        st.error("Please enter an IP, domain, or URL to investigate.")

st.markdown("---")
st.markdown(
    "<div style='text-align:center; color:gray;'>Built by Mohammed Basith | "
    "<a href='https://linkedin.com/in/mohammedbasith05'>LinkedIn</a> | "
    "<a href='https://github.com/Mdbasith05'>GitHub</a></div>",
    unsafe_allow_html=True
)
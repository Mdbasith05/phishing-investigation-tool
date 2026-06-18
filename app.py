import streamlit as st
import requests
import re
import base64
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

# =========================
# CONFIG
# =========================
VT_API_KEY = st.secrets["VT_API_KEY"]

# =========================
# VALIDATION FUNCTIONS
# =========================
def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_valid_url(value):
    try:
        parsed = urlparse(value)
        return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
    except:
        return False

def is_valid_domain(value):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.fullmatch(pattern, value))

# =========================
# DETECT IOC TYPE
# =========================
def detect_type(ioc):
    if is_valid_ip(ioc):
        return "ip"

    if is_valid_url(ioc):
        return "url"

    if is_valid_domain(ioc):
        return "domain"

    return None

# =========================
# VIRUSTOTAL LOOKUP
# =========================
def check_virustotal(ioc, ioc_type):
    headers = {
        "x-apikey": VT_API_KEY
    }

    if ioc_type == "ip":
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"

    elif ioc_type == "domain":
        vt_url = f"https://www.virustotal.com/api/v3/domains/{ioc}"

    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(
            ioc.encode()
        ).decode().strip("=")

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    else:
        return None

    try:
        response = requests.get(
            vt_url,
            headers=headers,
            timeout=15
        )

        if response.status_code != 200:
            return None

        data = response.json()

        if "data" not in data:
            return None

        attrs = data["data"]["attributes"]

        stats = attrs.get(
            "last_analysis_stats",
            {}
        )

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "country": attrs.get("country", "Unknown"),
            "reputation": attrs.get("reputation", "N/A"),
            "total": sum(stats.values()) if stats else 0
        }

    except:
        return None

# =========================
# PAGE SETTINGS
# =========================
st.set_page_config(
    page_title="Phishing Investigation Tool",
    page_icon="🔍",
    layout="centered"
)

# =========================
# UI
# =========================
st.title("🔍 Phishing Investigation Tool")

st.markdown(
    """
Paste any suspicious **IP Address**, **Domain**, or **URL**
to instantly check its reputation using VirusTotal.
"""
)

st.markdown("---")

ioc = st.text_input(
    "",
    placeholder="e.g. 8.8.8.8 or google.com or https://example.com"
)

# =========================
# BUTTON
# =========================
if st.button("🔍 Investigate", use_container_width=True):

    ioc = ioc.strip()

    if not ioc:
        st.error("Please enter an IP, Domain, or URL.")
        st.stop()

    ioc_type = detect_type(ioc)

    if not ioc_type:
        st.error(
            "Invalid input. Please enter a valid IP Address, Domain, or URL."
        )
        st.stop()

    with st.spinner("Analyzing threat intelligence..."):
        result = check_virustotal(ioc, ioc_type)

    if result is None:
        st.error(
            "Unable to retrieve VirusTotal data. The IOC may not exist, the API limit may be reached, or the service may be unavailable."
        )
        st.stop()

    malicious = result["malicious"]
    suspicious = result["suspicious"]
    total = result["total"]
    country = result["country"]
    reputation = result["reputation"]

    st.markdown("---")
    st.subheader("📊 Investigation Report")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "IOC Type",
        ioc_type.upper()
    )

    col2.metric(
        "Malicious",
        f"{malicious}/{total}"
    )

    col3.metric(
        "Suspicious",
        f"{suspicious}/{total}"
    )

    if ioc_type == "ip":
        col4, col5 = st.columns(2)

        col4.metric(
            "Country",
            country
        )

        col5.metric(
            "Reputation",
            reputation
        )

    st.markdown("---")

    # =========================
    # VERDICT
    # =========================
    if total == 0:
        st.warning(
            "⚠️ No analysis data available for this IOC."
        )

    elif malicious >= 10:
        st.error(
            "🚨 VERDICT: MALICIOUS — High confidence threat detected."
        )

    elif malicious >= 3 or suspicious >= 5:
        st.warning(
            "⚠️ VERDICT: SUSPICIOUS — Exercise caution."
        )

    else:
        st.success(
            "✅ VERDICT: CLEAN — No significant threats detected."
        )

    st.markdown("---")

    st.subheader("ℹ️ Threat Intelligence Summary")

    if malicious >= 10:
        st.markdown("""
- Multiple security engines flagged this IOC.
- Potential phishing, malware, or malicious activity detected.
- Avoid interacting with this resource.
- Consider blocking and reporting it.
""")

    elif malicious >= 3:
        st.markdown("""
- Some security engines reported suspicious activity.
- Proceed with caution.
- Additional investigation is recommended.
""")

    else:
        st.markdown("""
- No significant detections found.
- Continue following normal security practices.
- A clean result does not guarantee complete safety.
""")

    st.markdown("---")

    report = f"""
IOC: {ioc}
Type: {ioc_type}

Malicious Engines: {malicious}
Suspicious Engines: {suspicious}
Total Engines: {total}

Country: {country}
Reputation: {reputation}

Generated:
{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

    st.download_button(
        "📄 Download Report",
        report,
        file_name="ioc_report.txt",
        mime="text/plain"
    )

    st.caption(
        f"Powered by VirusTotal | Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

st.markdown("---")

st.markdown(
    """
<div style='text-align:center;color:gray'>
Built by Mohammed Basith
</div>
""",
    unsafe_allow_html=True
)
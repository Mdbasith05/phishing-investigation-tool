import requests
import json
import re
import email
import dns.resolver
from colorama import Fore, Style, init
from datetime import datetime

init()

# ====== CONFIG ======
VT_API_KEY = "49a180546aaf781ab88181136f36c60b90c9baae155b9125e64dd23b6728545b"
OTX_API_KEY = "02542c03ea62654acf97d257a34f89ff4ab5f60d826ee274966b21c51c3bc2f2"

# ====== IOC EXTRACTOR ======
def extract_iocs(text):
    urls = re.findall(r'https?://[^\s<>"]+', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
    return urls, ips, domains

# ====== VIRUSTOTAL CHECK ======
def check_virustotal(ioc, ioc_type):
    headers = {"x-apikey": VT_API_KEY}
    
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return malicious, total
    except:
        return 0, 0

# ====== PRINT RESULT ======
def print_result(ioc, ioc_type, malicious, total):
    if malicious >= 10:
        verdict = f"{Fore.RED}MALICIOUS{Style.RESET_ALL}"
    elif malicious >= 3:
        verdict = f"{Fore.YELLOW}SUSPICIOUS{Style.RESET_ALL}"
    else:
        verdict = f"{Fore.GREEN}CLEAN{Style.RESET_ALL}"
    
    print(f"""
{'='*50}
IOC ANALYSIS REPORT
{'='*50}
Input      : {ioc}
Type       : {ioc_type.upper()}
Detections : {malicious}/{total} engines flagged
Verdict    : {verdict}
{'='*50}
    """)

# ====== MAIN ======
def main():
    print(f"\n{Fore.CYAN}=== PHISHING INVESTIGATION TOOL ==={Style.RESET_ALL}")
    print("Enter suspicious IP, domain, or URL to investigate\n")
    
    ioc = input("Enter IOC: ").strip()
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        ioc_type = "ip"
    elif ioc.startswith("http"):
        ioc_type = "url"
    else:
        ioc_type = "domain"
    
    print(f"\n{Fore.YELLOW}Analyzing {ioc}...{Style.RESET_ALL}")
    malicious, total = check_virustotal(ioc, ioc_type)
    print_result(ioc, ioc_type, malicious, total)

main()
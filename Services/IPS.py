from scapy.all import sniff, IP, DNS, TCP, DNSQR, Raw, send
from scapy.layers.http import HTTPRequest
import redis
import re
import base64
import subprocess
from netfilterqueue import NetfilterQueue

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
QUEUE_NUM = 1

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

def manage_iptables(action):
    cmds = [
        f"sudo iptables {action} OUTPUT -j NFQUEUE --queue-num {QUEUE_NUM}",
        f"sudo iptables {action} INPUT -j NFQUEUE --queue-num {QUEUE_NUM}"
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd.split(), check=True, capture_output=True)
        except subprocess.CalledProcessError:
            if action == "-I":
                print(f"[!] Erreur configuration iptables (Action {action})")

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
    print("[DEBUG] Checking if IP is PV: ", ip, end="")
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

def timeout_ip(ip):
    # Send command to filter service to timeout IP
    r.setex(f"blocked:{ip}", BLOCK_DURATION, "true")

def count_ip(src_ip, dest_ip):
    current_count = r.incr(dest_ip)

    if current_count == 1:
        r.expire(dest_ip, SNIFF_WINDOW)

    if current_count > THRESHOLD:
        print(f"[!!] Threshold exceeded for IP {dest_ip}. Blocking for {BLOCK_DURATION} seconds.")
        timeout_ip(dest_ip)

def is_exfiltration(pkt, src_ip, dest_ip):
    is_malicious = False

    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        print("DNS query detected")
        qname = pkt[DNSQR].qname.decode(errors='ignore')
        subdomain = qname.split('.')[0]
        if is_suspicious("DNS", subdomain):
            is_malicious = True

    if pkt.haslayer(HTTPRequest):
        print("HTTP query detected")
        headers = pkt[HTTPRequest].fields
        ua = headers.get('User-Agent', b'').decode(errors='ignore')
        cookie = headers.get('Cookie', b'').decode(errors='ignore')

        if is_suspicious("USER-AGENT", ua) or is_suspicious("COOKIE", cookie):
            is_malicious = True

        if pkt.haslayer(Raw):
            data = pkt[Raw].load.decode(errors='ignore')
            if is_suspicious("POST", data):
                is_malicious = True

    if is_malicious:
        print(f"[DROP] Malicious activity from {src_ip} to {dest_ip}")

        current_count = r.incr(dest_ip)
        if current_count == 1: r.expire(dest_ip, SNIFF_WINDOW)
        if current_count > THRESHOLD:
            timeout_ip(dest_ip)
            print(f"[!!!] IP {dest_ip} BLOCKED for {BLOCK_DURATION}s")

        return True
    return False

def process_packet(nf_packet):
    pkt = IP(nf_packet.get_payload())
    src_ip = pkt.src
    dest_ip = pkt.dst

    if r.exists(f"blocked:{src_ip}"):
        nf_packet.drop()
        return

    if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
        nf_packet.accept()
        return

    # Detect exfiltration
    if is_pv_ip(src_ip):
        print(" yes")
        pkt.summary()
        if is_exfiltration(pkt, src_ip, dest_ip):
            nf_packet.drop()
            return
    else:
        print(" no")
    nf_packet.accept()


if __name__ == "__main__":
    print("[+] Configuration des règles iptables...")
    manage_iptables("-I")

    try:
        print("[+] Monitoring en cours (NFQUEUE)...")
        nfqueue = NetfilterQueue()
        nfqueue.bind(QUEUE_NUM, process_packet)
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Interruption détectée.")
    finally:
        print("[+] Nettoyage des règles iptables...")
        manage_iptables("-D")
        print("[+] Terminé.")
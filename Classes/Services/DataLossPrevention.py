from ..Servicev2 import BaseService
from ..Logging import log

import re
import redis
import base64

from scapy.all import DNS, DNSQR, Raw
from scapy.layers.http import HTTPRequest

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

class DataLossPrevention(BaseService):
    def _setup(self):
        self.threshold = self.config["threshold"]
        self.timeout = self.config["timeout"]
        self.sniff_window = self.config["window"]
        self.dbindex = self.config["db_index"]
        self.dbport = self.config["db_port"]

        self.redis = redis.Redis(host='localhost', port=self.dbport, db=self.dbindex, decode_responses=True)

        self.ua_pattern = re.compile("|".join(map(re.escape, suspicious_user_agents)), re.IGNORECASE)
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{10,}=*', re.ASCII | re.MULTILINE)
        self.leak_pattern = {
            "Email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
            "Phone": re.compile(r'(?:\+|00)([1-9]\d{0,3})[.\-\s]?\(?\d{1,4}\)?(?:[.\-\s]?\d{2,4}){3,4}'),
            "Credit_Card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b')
        }

    def _process(self, pkt):
        log(f"<bold>[DLP] pkt received {pkt.src} -> {pkt.dst}:</bold> {pkt.summary()}")
        if self.redis.exists(f"blocked:{pkt.dst}"):
            return False

        if self.is_exfiltration(pkt, pkt.dst):
            log("<info>[DLP] exfiltration detected</info>")
            return False
        return True

    def safe_b64_decode(self, payload):
        if isinstance(payload, str):
            payload = payload.strip().encode('utf-8')

        for pad_len in range(0, 4):
            try:
                padding = b'=' * pad_len
                decoded_bytes = base64.b64decode(payload + padding)
                return decoded_bytes.decode(errors='ignore')
            except Exception:
                continue
        return None

    def is_base64(self, payload):
        return [m.group() for m in self.base64_pattern.finditer(payload)]

    def is_d_leak(self, payload):
        if not payload:
            return False

        for pattern in self.leak_pattern:
            matches = pattern.findall(payload)
            if matches:
                return True

    def is_suspicious(self, type, payload):
        if not payload:
            return False

        if type == "DNS":
            if self.is_base64(payload):
                return True
            if self.is_d_leak(payload):
                return True

        if type == "COOKIE" or type == "POST" or type == "USER-AGENT":
            if type == "USER-AGENT":
                if self.ua_pattern.search(payload):
                    return True
            if self.is_d_leak(payload):
                return True
            if self.is_base64(payload):
                if self.is_d_leak(self.safe_b64_decode(payload)):
                    return True
                return False
        return False

    def is_exfiltration(self, pkt, dest_ip):
        is_malicious = False

        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            log("[DNS] query")
            qname = pkt[DNSQR].qname.decode(errors='ignore')
            subdomain = qname.split('.')[0]
            if self.is_suspicious("DNS", subdomain):
                is_malicious = True

        if pkt.haslayer(HTTPRequest):
            log("[HTTP] query")
            headers = pkt[HTTPRequest].fields
            ua = headers.get('User-Agent', b'').decode(errors='ignore')
            cookie = headers.get('Cookie', b'').decode(errors='ignore')

            if self.is_suspicious("USER-AGENT", ua) or self.is_suspicious("COOKIE", cookie):
                is_malicious = True

            if pkt.haslayer(Raw):
                data = pkt[Raw].load.decode(errors='ignore')
                if self.is_suspicious("POST", data):
                    is_malicious = True

        if is_malicious:
            current_count = self.redis.incr(dest_ip)
            if current_count == 1:
                self.redis.expire(dest_ip, self.sniff_window)
            if current_count > self.threshold:
                redis.setex(f"blocked:{dest_ip}", self.timeout, "true")
                self.firewall.set_timeout(dest_ip, self.timeout)
            log(f"<info>[DEBUG] MALICIOUS: {pkt.src} -> {dest_ip} : {pkt.summary()}</info>")
            return True
        return False
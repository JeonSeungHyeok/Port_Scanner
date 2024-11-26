from scapy.all import IP, TCP, sr1
import random

def scan_null_port(targetIp, port, timeout, maxTries):
    """단일 포트에 대해 TCP Null 스캔 수행"""
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535)
        nullPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags="")
        response = sr1(nullPacket, timeout=timeout, verbose=0)
        if response is None:
            continue
        else:
            break

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "RA":
            return port, "Closed"
    return port, "Open or Filtered"


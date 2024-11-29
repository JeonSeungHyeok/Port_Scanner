from scapy.all import IP, TCP, sr1
import random

def scan_xmas_port(targetIp, port,timeout,maxTries):
    """단일 포트에 대해 TCP Xmas 스캔 수행"""
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535)
        xmasPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags="FPU")
        response = sr1(xmasPacket, timeout=timeout, verbose=0)
        if response is None:
            continue
        else:
            break

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "R":
            return port, "Closed"
    else:
        return port, "Open or Filtered"
    return "None"
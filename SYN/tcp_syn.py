from scapy.all import IP, TCP, sr1, send
import random

def scan_syn_port(targetIp, port,timeout,maxTries):
    """단일 포트에 대해 TCP SYN 스캔 수행"""
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535)
        synPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags="S")
        response = sr1(synPacket, timeout=timeout, verbose=0)
        if response is None:
            continue
        else:
            break

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "SA":
            send(IP(dst=targetIp) / TCP(dport=port, flags="R"), verbose=0)  # 세션 종료
            return port, "Open"
        elif response.haslayer(TCP) and response[TCP].flags == "RA":
            return port, "Closed"
    return port, "Filtered"
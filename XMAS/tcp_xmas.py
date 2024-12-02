from scapy.all import IP, TCP, sr1
import random

def scan_xmas_port(targetIp, port,timeout,maxTries):
    """특정 포트에 대해 XMAS 스캔 수행"""
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535)
        xmasPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags="FPU") # Xmas 패킷 생성 (Fin, Push, URG 플래그 설정)
        response = sr1(xmasPacket, timeout=timeout, verbose=0)
        if response is None:
            continue
        else:
            break

    # 스캔 결과 
    if response:
        if response.haslayer(TCP) and response[TCP].flags == "R":
            return port, "Closed"
    else:
        return port, "Open or Filtered"
    return "None"
from scapy.all import IP, TCP, sr1, send

def scan_null_port(targetIp, port):
    """단일 포트에 대해 TCP Null 스캔 수행"""
    nullPacket = IP(dst=targetIp) / TCP(dport=port, flags="")  # 플래그 없음
    response = sr1(nullPacket, timeout=1, verbose=0)

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "RA":
            return port, "Closed"
    else:
        return port, "Open or Filtered"  # 응답 없음
    return port, "Filtered"
from scapy.all import IP, TCP, sr1, send

def scan_null_port(targetIp, port):
    """단일 포트에 대해 TCP Null 스캔 수행"""
    nullPacket = IP(dst=targetIp) / TCP(dport=port, flags="")
    response = sr1(nullPacket, timeout=1, verbose=0)

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "R":
            return port, "Closed"
    return port, "Open or Filtered"


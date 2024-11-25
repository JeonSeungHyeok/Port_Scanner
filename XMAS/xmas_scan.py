from scapy.all import IP, TCP, sr1, send


def scan_xmas_port(targetIp, port):
    """단일 포트에 대해 TCP Xmas 스캔 수행"""
    xmasPacket = IP(dst=targetIp) / TCP(dport=port, flags="FPU")
    response = sr1(xmasPacket, timeout=1, verbose=0)

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "R":
            return port, "Closed"
    return port, "Open or Filtered"

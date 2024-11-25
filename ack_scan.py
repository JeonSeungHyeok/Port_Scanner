from scapy.all import IP, TCP, sr1

def scan_ack_port(targetIp, port):
    """단일 포트에 대해 TCP ACK 스캔 수행"""
    ackPacket = IP(dst=targetIp) / TCP(dport=port, flags="A")
    response = sr1(ackPacket, timeout=1, verbose=0)

    if response is None:
        return port, "Filtered (No Response)"
    elif response.haslayer(TCP) and response[TCP].flags == "R":
        return port, "Unfiltered (RST Received)"
    else:
        return port, "Unknown"
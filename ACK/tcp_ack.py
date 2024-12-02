from scapy.all import IP, TCP, sr1, conf
import random

def scan_ack_port(targetIp, port, timeout,maxTries):
    """특정 포트에 대해 TCP ACK 스캔 수행"""
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535) # 랜덤 소스 포트 설정
        ipPacket = IP(dst=targetIp) # 대상 IP를 설정한 IP 패킷 생성
        tcpPacket = TCP(sport=srcPort, dport=port, flags='A')  # ACK 플래그를 설정한 TCP 패킷 생성
        response = sr1(ipPacket / tcpPacket, timeout=timeout, verbose=0)  # 패킷 전송 및 응답 대기
        if response is None:
            continue
        else:
            break

    # 스캔 결과
    if response is None:
        return port, "Filtered"
    elif response.haslayer(TCP) and response[TCP].flags == "R":
        return port, "Unfiltered (RST received)"
    elif response.haslayer(IP) and response[IP].proto == 1:  # ICMP 메시지
        return port, "Filtered (ICMP message received)"
    else:
        return port, "Unknown"
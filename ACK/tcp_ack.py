import socket
from scapy.all import IP, TCP, sr1, conf
import random

def get_service_name(port):
    """
    주어진 포트 번호에 대한 서비스 이름을 반환.
    알 수 없는 포트의 경우 'unknown' 반환.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"
    
def get_banner(ip, port, timeout=2):
    """
    특정 IP와 포트에서 배너 정보를 가져옴
    """
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            # 서비스 응답을 읽음
            sock.sendall(b"\r\n")  # 간단한 핑 신호 전송
            banner = sock.recv(1024).decode().strip()
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "No Banner"


def scan_port_ack(ip, port, timeout,maxTries, service_version=False):
    """특정 포트에 대해 TCP ACK 스캔 수행"""
    for i in range(maxTries):
        srcPort = random.randint(10000, 65535)  # 랜덤 소스 포트 설정
        ipPacket = IP(dst=ip)  # 대상 IP를 설정한 IP 패킷 생성
        tcpPacket = TCP(sport=srcPort, dport=port, flags='A')  # ACK 플래그를 설정한 TCP 패킷 생성
        response = sr1(ipPacket / tcpPacket, timeout=timeout, verbose=0)  # 패킷 전송 및 응답 대기
        if response is None:
            continue
        else:
            break

    if not response:
        return port, "Filtered", None, None
    elif response.haslayer(TCP) and response[TCP].flags == "R":
        service = get_service_name(port) if service_version else None
        banner = get_banner(ip, port, timeout) if service_version else None
        return port, "Unfiltered (RST received)", service, banner
    elif response.haslayer(IP) and response[IP].proto == 1:
        return port, "Filtered (ICMP message received)", None, None
    else:
        return port, "Unknown", None, None
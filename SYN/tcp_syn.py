import socket
from scapy.all import IP, TCP, sr1, send

def get_service_name(port):
    """
    주어진 포트 번호에 대한 서비스 이름을 반환.
    알 수 없는 포트의 경우 'unknown' 반환.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"
    
def get_banner(targetIp, port, timeout=2):
    """
    특정 IP와 포트에서 배너 정보를 가져옴
    """
    try:
        with socket.create_connection((targetIp, port), timeout) as sock:
            # 서비스 응답을 읽음
            sock.sendall(b"\r\n")  # 간단한 핑 신호 전송
            banner = sock.recv(1024).decode().strip()
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "No Banner"

def scan_syn_port(targetIp, port,timeout,max_tries, service_version=False):
    """단일 포트에 대해 TCP SYN 스캔 수행"""
    synPacket = IP(dst=targetIp) / TCP(dport=port, flags="S")
    response = sr1(synPacket, timeout=timeout, verbose=0)

    if response:
        if response.haslayer(TCP) and response[TCP].flags == "SA":
            send(IP(dst=targetIp) / TCP(dport=port, flags="R"), verbose=0)
            service = get_service_name(port) if service_version else None
            banner = get_banner(targetIp, port, timeout) if service_version else None
            return port, "Open", service, banner
        elif response.haslayer(TCP) and response[TCP].flags == "RA":
            return port, "Closed", None, None
    return port, "Filtered", None, None
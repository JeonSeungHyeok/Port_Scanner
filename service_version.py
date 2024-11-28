import socket
from scapy.all import IP, TCP, sr1, send
from SYN.tcp_syn import *

def get_service_name(targetIp, port, timeout):

    srcPort = random.randint(10000, 65535) # 랜덤 소스 포트 설정
    synPacket = IP(dst=targetIp) / TCP(sport=srcPort, dport=port, flags="S")
    response = sr1(synPacket, timeout=timeout, verbose=0)
    ackPacket = IP(dst=targetIp)/TCP(sport=srcPort, dport=port, flags='A', seq=response[TCP].ack, ack=response[TCP].seq+1)
    send(ackPacket, verbose=False)

    with socket.create_connection((targetIp, port), timeout=timeout) as sock:
        sock.sendall(b"\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
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
    
def scan_service_version(targetIp, port, timeout, maxTries):
    result = scan_syn_port(targetIp, port, timeout, maxTries)
    if result[1] == "Open":

        return result[0], result[1], get_service_name(targetIp, port, timeout), get_banner(targetIp, port, timeout)
    return result[0], result[1], None, None
import socket
from SYN.tcp_syn import *
import ssl

def get_service_name(port):
    """
    주어진 포트 번호에 대한 서비스 이름을 반환.
    알 수 없는 포트의 경우 'unknown' 반환.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"
    
def get_basic_banner(targetIp, port, timeout):
    """
    특정 IP와 포트에서 배너 정보를 가져옴
    """
    try:
        with socket.create_connection((targetIp, port), timeout) as sock:
            # 서비스 응답을 읽음
            banner = sock.recv(1024).decode(errors="ignore").strip()
            if not banner:
                sock.sendall(b"\r\n")  # 간단한 핑 신호 전송
                banner = sock.recv(1024).decode(errors="ignore").strip()

            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "No Banner"
    
def get_ssl_banner(targetIp, port, timeout):
    """
    특정 IP와 web 포트에서 배너 정보를 가져옴
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
        if port == 80 or port == 443:
            pass
        else:
            return result[0], result[1], get_service_name(port), get_basic_banner(targetIp, port, timeout)
    return result[0], result[1], None, None
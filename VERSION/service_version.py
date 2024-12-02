import socket
from SYN.tcp_syn import *
import ssl

def get_service_name(port):    # 포트 번호로 서비스 이름 반환
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return 'unknown'
    
def get_basic_banner(targetIp, port, timeout):    # TCP 연결 후 배너 수집
    try:
        with socket.create_connection((targetIp, port), timeout) as sock:  # 서비스 응답을 읽음
            sock.sendall(b'\r\n')  # 간단한 핑 신호 전송
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return 'No Banner'
    
def get_ssl_banner(targetIp, port, timeout):    # SSL 연결로 배너 수집
    try:
        with socket.create_connection((targetIp, port), timeout) as sock:
            if port == 443:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=targetIp) as sslConn:
                    sslConn.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % targetIp.encode())
                    banner = sslConn.recv(1024).decode(errors='ignore').strip()
                    return banner
            # 서비스 응답을 읽음
            sock.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % targetIp.encode())  # 간단한 핑 신호 전송
            response = sock.recv(1024).decode(errors='ignore').strip()
            banner = extract_server_header(response)
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return 'No Banner'
def extract_server_header(response):    # 응답에서 "Server" 헤더 추출
    headers = response.split('\r\n')
    for header in headers:
        if header.lower().startswith('server:'):
            return header
    return None
    
def scan_service_version(targetIp, port, timeout, maxTries):    # SYN 스캔 후 서비스 이름과 배너 정보 반환
    result = scan_syn_port(targetIp, port, timeout, maxTries)
    if result[1] == 'Open':
        if port == 80 or port == 443:
            return result[0], result[1], get_service_name(port), get_ssl_banner(targetIp, port, timeout)
        else:
            return result[0], result[1], get_service_name(port), get_basic_banner(targetIp, port, timeout)
    return result[0], result[1], None, None
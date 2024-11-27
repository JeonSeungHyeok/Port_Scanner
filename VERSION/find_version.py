import socket
import ssl
import time
import random

wellKnownPort = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
}

def get_service_version(targetIp, port, timeout=5):
    
    try:
        startTime = time.perf_counter()
        srcPort = random.randint(10000, 65535)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if srcPort:
                sock.bind(("", srcPort))  # 소스 포트 지정
            sock.settimeout(timeout)
            sock.connect((targetIp, port))

            endTime = time.perf_counter()
            connectionTime = endTime - startTime

            print(f"{targetIp}:{port} ({wellKnownPort.get(port, 'Unknown Service')}) 연결 성공")
            print(f"연결 시간: {connectionTime:.4f}초")

            if port == 21:  # FTP
                response = sock.recv(1024).decode(errors="ignore").strip()
                print("FTP 버전 정보:", response)
            elif port == 22:  # SSH
                response = sock.recv(1024).decode(errors="ignore").strip()
                print("SSH 버전 정보:", response)
            elif port == 23:  # Telnet
                response = sock.recv(1024).decode(errors="ignore").strip()
                print("Telnet 버전 정보:", response)
            elif port == 25:  # SMTP
                response = sock.recv(1024).decode(errors="ignore").strip()
                print("SMTP 버전 정보:", response)
            elif port == 110:  # POP3
                response = sock.recv(1024).decode(errors="ignore").strip()
                print("POP3 버전 정보:", response)
            elif port == 143:  # IMAP
                response = sock.recv(1024).decode(errors="ignore").strip()
                print("IMAP 버전 정보:", response)
            elif port == 443:  # HTTPS
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=targetIp) as sslConn:
                    sslConn.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % targetIp.encode())
                    response = sslConn.recv(1024).decode(errors="ignore").strip()
                print("HTTPS 응답 헤더:\n", response)
            elif port in [465, 993, 995]:  # SMTPS, IMAPS, POP3S
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=targetIp) as sslConn:
                    response = sslConn.recv(1024).decode(errors="ignore").strip()
                    serviceName = wellKnownPort[port]
                    print(f"{serviceName} 버전 정보:", response)
            elif port == 80:  # HTTP
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % targetIp.encode())
                response = sock.recv(1024).decode(errors="ignore").strip()
                serverHeader = extract_server_header(response)
                print("HTTP Server 헤더:", serverHeader if serverHeader else "없음")
            else:
                print(f"{port}번 포트는 알려진 서비스가 아니거나 특별한 처리가 필요하지 않습니다.")

    except socket.timeout:
        print(f"{targetIp}:{port} 연결 실패 - 연결 시간 초과")
    except Exception as e:
        print(f"{targetIp}:{port} 연결 실패 - {e}")
    print('\n')

def extract_server_header(response):
    """
    HTTP 응답에서 Server 헤더만 추출하는 함수
    """
    headers = response.split("\r\n")
    for header in headers:
        if header.lower().startswith("server:"):
            return header
    return None

# 사용 예시
targetIp = "54.180.158.188"  # 스캔할 서버 IP 또는 도메인
#portsToScan = [21, 22, 23, 25, 80, 110, 143, 443, 465, 993, 995]  # 스캔할 포트 목록
portsToScan = [21, 22, 80]  # 스캔할 포트 목록
for port in portsToScan:
    get_service_version(targetIp, port)

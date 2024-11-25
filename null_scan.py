from scapy.all import IP, TCP, sr1, send

def scan_null_port(targetIp, port):
    """단일 포트에 대해 TCP Null 스캔 수행"""
    print(f"[LOG] 시작: {targetIp}:{port} 스캔 중...")  
    nullPacket = IP(dst=targetIp) / TCP(dport=port, flags="")  
    print(f"[LOG] 패킷 생성 완료: {nullPacket.summary()}")  

    try:
        response = sr1(nullPacket, timeout=1, verbose=0)
        if response:
            print(f"[LOG] 응답 수신: {response.summary()}")  
            if response.haslayer(TCP) and response[TCP].flags == "RA":
                print(f"[LOG] 포트 {port}: Closed")  
                return port, "Closed"
        else:
            print(f"[LOG] 포트 {port}: Open or Filtered (응답 없음)")  
            return port, "Open or Filtered"
    except Exception as e:
        print(f"[ERROR] 포트 {port} 스캔 중 오류 발생: {e}")  
        return port, "Error"

    print(f"[LOG] 포트 {port}: Filtered")  
    return port, "Filtered"
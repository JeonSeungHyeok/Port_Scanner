from scapy.all import *
import time

def tcp_syn_scan(target, portRange):
    print(f"Scanning target: {target} on ports: {portRange}")
    for port in portRange:
        # TCP SYN 패킷 생성
        syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
        # 패킷 전송 및 응답 수신
        response = sr1(syn_packet, timeout=0.01, verbose=0)

        # 응답 분석
        if response:
            if response.haslayer(TCP) and response[TCP].flags == "SA":  # SYN+ACK
                print(f"Port {port} is open!")
                # RST 패킷 보내기 (세션 종료)
                rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                send(rst_packet, verbose=0)
            elif response.haslayer(TCP) and response[TCP].flags == "RA":  # RST+ACK
                print(f"Port {port} is closed.")
            else:
                print(f"Port {port} is filtered or no response.")
        else:
            print(f"Port {port} is filtered or no response.")

start_time = time.time()
# 스캔 대상 및 포트 범위
targetIP = "210.117.181.247"
portsToScan = range(1,444)  # 20번부터 29번까지 포트

tcp_syn_scan(targetIP, portsToScan)

end_time = time.time()

print(f"Execution time: {end_time - start_time:.6f} seconds")
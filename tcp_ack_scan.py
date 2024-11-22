from scapy.all import IP, TCP, sr1, conf
import random
import time  # 시간 측정
import threading  # 속도 향상

# 공유 데이터를 위한 리스트
results = []
results_lock = threading.Lock()  # 스레드 안전성을 위한 Lock 객체

def parsePorts(port_input):
    """
    입력된 포트를 숫자로 변환한 후, 중복 제거하여 오름차순으로 정렬된 포트 번호 리스트를 반환.
    """
    ports = set()
    port_parts = port_input.split(",")  # 문자열 분리

    # 포트 범위를 리스트로 변환 후 집합에 추가
    for part in port_parts:
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part.strip()))

    return sorted(ports)


def tcpAckScanThreaded(target_ip, ports, timeout=1, num_threads=10):
    """
    TCP ACK 스캔을 스레드를 활용하여 실행.
    """
    print("스캔 시작...\n")
    conf.verb = 0  # scapy의 상세 출력 비활성화
    start_time = time.time()  # 시작 시간 기록

    chunk_size = len(ports) // num_threads + 1  # 전체 포트를 스레드 수로 나누기
    threads = []

    # 스레드 생성 및 시작
    for i in range(0, len(ports), chunk_size):
        thread = threading.Thread(
            target=scanPortsChunk, args=(target_ip, ports[i:i + chunk_size], timeout)
        )
        threads.append(thread)
        thread.start()

    # 모든 스레드가 완료될 때까지 대기
    for thread in threads:
        thread.join()

    # 필터링되지 않은 결과만 출력
    filtered_results = [result for result in results if result[1] != "필터링됨 (응답 없음)"]

    # 정렬된 결과 출력
    sorted_results = sorted(filtered_results, key=lambda x: x[0])  # 포트 번호 기준 정렬
    
    print("\nScannaing..:")
    for port, state in sorted_results:
        print(f"Port {port}: {state}")

    # 소요 시간 출력
    elapsed_time = time.time() - start_time
    print(f"\n스캔 완료. 소요 시간: {elapsed_time:.2f}초")


def scanPortsChunk(target_ip, ports, timeout):
    """
    주어진 포트 리스트를 스캔하여 필터링 상태를 확인.
    """
    for port in ports:
        state = scanPortAck(target_ip, port, timeout)
        # 결과를 공용 리스트에 추가 (스레드 안전하게 처리)
        with results_lock:
            results.append((port, state))
def scanPortAck(ip, port, timeout):
    """
    개별 포트의 TCP ACK 스캔 수행.
    """
    src_port = random.randint(1024, 65535)  # 랜덤 소스 포트 설정
    ip_packet = IP(dst=ip)  # 대상 IP를 설정한 IP 패킷 생성
    tcp_packet = TCP(sport=src_port, dport=port, flags='A')  # ACK 플래그를 설정한 TCP 패킷 생성

    response = sr1(ip_packet / tcp_packet, timeout=timeout, verbose=0)  # 패킷 전송 및 응답 대기

    if response is None:
        return "필터링됨 (응답 없음)"
    elif response.haslayer(TCP) and response[TCP].flags == "R":
        return "필터링되지 않음 (RST 수신)"
    elif response.haslayer(IP) and response[IP].proto == 1:  # ICMP
        return "필터링됨 (ICMP 메시지 수신)"
    else:
        return "상태 확인 불가"


if __name__ == "__main__":
    # 사용자 입력 처리
    target = input("IP를 입력하시오: ")  # 스캔할 대상 IP
    port_input = input("스캔할 포트 번호를 입력하시오 (e.g., '22,80,443' or '20-30'): ")  # 포트 설정
    timeout = float(input("응답 대기 시간을 입력하시오 (초 단위, 기본값 1): ") or 1)  # 응답 대기 시간 (기본 1초)
    num_threads = int(input("스레드 개수를 입력하시오 (기본값 10): ") or 10)  # 스레드 개수

    ports = parsePorts(port_input)
    tcpAckScanThreaded(target, ports, timeout=timeout, num_threads=num_threads)

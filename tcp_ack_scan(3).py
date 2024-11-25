import socket
from scapy.all import IP, TCP, sr1, conf
import random
import time
from threading_utils import ThreadPool  # 스레드 관련 모듈

# 공유 데이터를 위한 리스트
results = []


def parse_ports(port_input):
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


def get_service_name(port):
    """
    주어진 포트 번호에 대한 서비스 이름을 반환.
    알 수 없는 포트의 경우 'unknown' 반환.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port_ack(ip, port, timeout):
    """
    개별 포트의 TCP ACK 스캔 수행.
    """
    src_port = random.randint(1024, 65535)  # 랜덤 소스 포트 설정
    ip_packet = IP(dst=ip)  # 대상 IP를 설정한 IP 패킷 생성
    tcp_packet = TCP(sport=src_port, dport=port, flags="A")  # ACK 플래그를 설정한 TCP 패킷 생성

    response = sr1(ip_packet / tcp_packet, timeout=timeout, verbose=0)  # 패킷 전송 및 응답 대기

    if response is None:
        return port, "filtered", get_service_name(port)
    elif response.haslayer(TCP) and response[TCP].flags == "R":
        return port, "unfiltered", get_service_name(port)
    elif response.haslayer(IP) and response[IP].proto == 1:  # ICMP
        return port, "filtered", get_service_name(port)
    else:
        return port, "unknown", get_service_name(port)


def tcp_ack_scan_threaded(target_ip, ports, timeout=1, num_threads=10):
    """
    TCP ACK 스캔을 스레드를 활용하여 실행.
    """
    print("스캔 시작...\n")
    conf.verb = 0  # scapy의 상세 출력 비활성화
    start_time = time.time()  # 시작 시간 기록

    pool = ThreadPool(num_threads=num_threads)  # 스레드 풀 생성

    # 스레드 작업 추가
    for port in ports:
        pool.add_task(scan_task, target_ip, port, timeout)

    pool.wait_completion()  # 모든 작업이 완료될 때까지 대기

    # Unfiltered 결과만 필터링
    unfiltered_results = [result for result in results if result[1] == "unfiltered"]

    # 정렬된 결과 출력
    sorted_results = sorted(unfiltered_results, key=lambda x: x[0])  # 포트 번호 기준 정렬

    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE'}")
    for port, state, service in sorted_results:
        print(f"{port}/tcp   {state:<12}{service}")

    # 소요 시간 출력
    elapsed_time = time.time() - start_time
    print(f"\n스캔 완료. 소요 시간: {elapsed_time:.2f}초")


def scan_task(ip, port, timeout):
    """
    스레드에서 실행할 스캔 작업.
    """
    result = scan_port_ack(ip, port, timeout)
    results.append(result)


if __name__ == "__main__":
    # 사용자 입력 처리
    target = input("IP를 입력하시오: ")  # 스캔할 대상 IP
    port_input = input("스캔할 포트 번호를 입력하시오 (e.g., '22,80,443' or '20-30'): ")  # 포트 설정
    timeout = float(input("응답 대기 시간을 입력하시오 (초 단위, 기본값 1): ") or 1)  # 응답 대기 시간 (기본 1초)
    num_threads = int(input("스레드 개수를 입력하시오 (기본값 10): ") or 10)  # 스레드 개수

    ports = parse_ports(port_input)
    tcp_ack_scan_threaded(target, ports, timeout=timeout, num_threads=num_threads)
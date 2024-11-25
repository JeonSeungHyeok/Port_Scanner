from ack_scan import scan_ack_port
from syn_scan import scan_syn_port
import argparse
from concurrent.futures import ThreadPoolExecutor

def parse_ports(portInput):
    """입력된 포트를 숫자로 변환한 후, 중복 제거하여 오름차순으로 정렬된 포트 번호 리스트 반환."""
    ports = set()
    for part in portInput.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part.strip()))
    return sorted(ports)

def add_options(parser):
    """명령줄 인자를 추가하는 함수"""
    parser.add_argument('-S', action='store_true', dest='syn', help="TCP SYN scan")
    parser.add_argument('-A', action='store_true', dest='ack', help="TCP ACK scan")
    parser.add_argument('-N', action='store_true', dest='Null', help="TCP Null scan")
    parser.add_argument('-X', action='store_true', dest='Xmas', help="TCP X-mas scan")
    
    parser.add_argument('-IP', required=True, default='54.180.158.188', dest='ip', help="Specify target IP")
    parser.add_argument('-P', required=True, dest='port', help="Specify port range (e.g., '22,80,443' or '20-30')")
    
    parser.add_argument('-T', type=int, default=1, dest='threads', help="Specify number of threads (default: 1)")

    parser.add_argument('-OS', action='store_true', dest='os', help="Detection OS")
    
    parser.add_argument('-oj', action='store_true', dest='output_json', help="Output JSON")
    parser.add_argument('-ox', action='store_true', dest='output_xml', help="Output XML")

def perform_scan(scanFunction, targetIp, ports, numThreads, filterStatus):
    """스캔을 쓰레드를 활용해 병렬로 수행"""
    results = []
    with ThreadPoolExecutor(max_workers=numThreads) as executor:
        futures = {executor.submit(scanFunction, targetIp, port): port for port in ports}
        for future in futures:
            result = future.result()
            if result[1] == filterStatus:  # 원하는 상태만 출력
                results.append(result)

    results.sort(key=lambda x: x[0])
    for port, state in results:
        print(f"PORT {port} IS {state.upper()}")

def main():
    parser = argparse.ArgumentParser()
    add_options(parser)
    options = parser.parse_args()

    targetIp = options.ip
    ports = parse_ports(options.port)
    numThreads = options.threads

    if options.ack:
        print(f"Starting TCP ACK scan on {targetIp} with ports {options.port} using {numThreads} threads.")
        perform_scan(scan_ack_port, targetIp, ports, numThreads, "Unfiltered")
    if options.syn:
        print(f"Starting TCP SYN scan on {targetIp} with ports {options.port} using {numThreads} threads.")
        perform_scan(scan_syn_port, targetIp, ports, numThreads, "Open")
    else:
        print("Please specify a scan type using -A (ACK) or -S (SYN).")

if __name__ == '__main__':
    main()
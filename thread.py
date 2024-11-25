from concurrent.futures import ThreadPoolExecutor
from ACK.tcp_ack import *
from SYN.tcp_syn import *
from null_scan import *
from xmas_scan import *
import time

class Thread:
    def __init__(self, ip: str, port: str, timeout: int, numThread: int, maxTries: int, scanMethod) -> None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.numThread = numThread
        self.maxTries = maxTries
        self.scanMethod = scanMethod

    def parse_ports(self, portInput: str) -> set:
        """입력된 포트를 숫자로 변환한 후, 중복 제거하여 오름차순으로 정렬된 포트 번호 리스트를 반환."""
        print(f"[LOG] 포트 파싱 시작: {portInput}")
        ports = set()
        for part in portInput.split(","):  # 문자열 분리
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip()))
        sorted_ports = sorted(ports)
        print(f"[LOG] 포트 파싱 완료: {sorted_ports}")
        return sorted_ports

    def start_thread(self) -> list:
        results = []
        conf.verb = 0
        startTime = time.time()
        ports = self.parse_ports(self.port)
        scanMethods = {
            "syn": scan_syn_port,
            "ack": scan_port_ack,
            "Null": scan_null_port,
            "Xmas": scan_xmas_port
        }
        scanFunction = scanMethods.get(self.scanMethod)
        print(f"[LOG] 스캔 방법: {self.scanMethod}, 포트 목록: {ports}")

        with ThreadPoolExecutor(max_workers=self.numThread,) as executor:
            print("[LOG] 스캔 시작: 여러 쓰레드로 포트 스캔 중...")
            if self.scanMethod == "Null" or self.scanMethod == "Xmas":
                futures = [executor.submit(scanFunction, self.ip, port) for port in ports]
            else:
                futures = [executor.submit(scanFunction, self.ip, port, self.timeout, self.maxTries) for port in ports]
            for future in futures:
                result = future.result()
                print(f"[LOG] 결과 수신: {result}")
                results.append(result)
        elapsed_time = time.time() - startTime
        print(f"[LOG] 스캔 완료. 소요 시간: {elapsed_time:.2f}초")
        return results, startTime

    def print_result(self, results: list, startTime: time) -> None:
        # 결과 정렬 및 출력
        filteredResults = [result for result in results if result[1] == "필터링되지 않음 (RST 수신)" or result[1] == 'Open']
        filteredResults.sort(key=lambda x: x[0])

        print("\n[LOG] 스캔 결과 출력:")
        for port, state in filteredResults:
            print(f"Port {port}: {state}")

        # 소요 시간 출력
        elapsedTime = time.time() - startTime
        print(f"\n스캔 완료. 소요 시간: {elapsedTime:.2f}초")
        print("[LOG] 결과 출력 완료")

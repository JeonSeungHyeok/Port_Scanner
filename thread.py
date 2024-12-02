from concurrent.futures import ThreadPoolExecutor
from service_version import *
from NULL.tcp_null import *
from XMAS.tcp_xmas import *
from ACK.tcp_ack import *
from SYN.tcp_syn import * 
from OS.p0f import * 
from colors import *
from json_handler import *
import os

class Thread:
    # 클래스 초기화, 주요 매개변수를 설정
    def __init__(self, ip: str, port: str, timeout: int, numThread: int, maxTries: int, os: bool, scanMethod, outputFile: str) -> None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.numThread = numThread
        self.maxTries = maxTries 
        self.os = os 
        self.scanMethod = scanMethod 
        self.outputFile = outputFile 

    # 입력된 포트 문자열을 파싱하여 정렬된 세트로 반환
    def parse_ports(self, portInput: list) -> set:
        ports = set()
        for part in portInput.split(","):
            if "-" in part: 
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports) 

    # 스캔 작업을 병렬로 실행
    def start_thread(self) -> list:
        results = []
        conf.verb = 0 
        if self.os: 
            print(f'{BLUE}[*]{RESET}OS detected : {YELLOW}{run_docker_p0f(os.getcwd(), self.ip)}{RESET}')
        ports = self.parse_ports(self.port) 
        scanMethods = {
            "syn": scan_syn_port, 
            "ack": scan_ack_port,  
            "Null": scan_null_port,  
            "Xmas": scan_xmas_port,
            "version": scan_service_version 
        }
        scanFunction = scanMethods.get(self.scanMethod)  
        with ThreadPoolExecutor(max_workers=self.numThread) as executor: 
            futures = [
                executor.submit(scanFunction, self.ip, port, self.timeout, self.maxTries)
                for port in ports
            ]  
            for future in futures: 
                results.append(future.result())
        return results 

    # 스캔 결과를 출력 및 저장
    def print_result(self, results: list) -> None:
        filteredResults = [
            result for result in results
            if result[1] in ["Unfiltered (RST received)", "Open", "Open or Filtered"]
        ]
        filteredResults.sort(key=lambda x: x[0]) 
        print(f"\n{self.scanMethod.upper()} 스캔 결과:")
        
        if self.scanMethod == "version": 
            print(f"{'PORT':<10}{'STATE':<20}{'SERVICE':<20}{'BANNER'}")
            for port, state, service, banner in filteredResults:
                print(f"Port {port}: {state:<20}{service or 'N/A':<20}{banner or 'N/A'}")
        else: 
            for port, state in filteredResults:
                print(f"Port {port}: {state}")
        
        # 결과를 JSON 파일로 저장
        if self.outputFile:
            save_result_as_json(filteredResults, self.scanMethod, self.outputFile)

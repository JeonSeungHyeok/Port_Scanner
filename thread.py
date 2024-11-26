from concurrent.futures import ThreadPoolExecutor
from ACK.tcp_ack import *
from SYN.tcp_syn import *
import time

class Thread:
    def __init__(self,ip:str,port:str,timeout:int,numThread:int,maxTries:int,scanMethod,serviceVersion)->None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.numThread = numThread
        self.maxTries = maxTries
        self.scanMethod = scanMethod
        self.serviceVersion = serviceVersion

    def parse_ports(self,portInput:list)->set:
        """입력된 포트를 숫자로 변환한 후, 중복 제거하여 오름차순으로 정렬된 포트 번호 리스트를 반환."""
        ports = set()
        for part in portInput.split(","):  # 문자열 분리
            # 포트 범위를 리스트로 변환 후 집합에 추가
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports)

    def start_thread(self) -> list:
        results=[]
        conf.verb=0
        startTime = time.time()
        ports = self.parse_ports(self.port)
        scanMethods = {
            "syn":scan_syn_port,
            "ack":scan_port_ack,
            #"Null":,
            #"Xmas":
        }
        scanFunction = scanMethods.get(self.scanMethod)
        with ThreadPoolExecutor(max_workers=self.numThread,) as executor:
            futures = [executor.submit(scanFunction, self.ip, port, self.timeout,self.maxTries, self.serviceVersion) for port in ports]
            for future in futures:
                results.append(future.result())
        return results, startTime

    def print_result(self,results:list,startTime:time)->None:
        # 결과 정렬 및 출력
        filteredResults = [result for result in results if result[1] == "필터링되지 않음 (RST 수신)" or result[1]=='Open']
        filteredResults.sort(key=lambda x: x[0])

        print("\n스캔 결과:")

        if self.serviceVersion:  # -sV 옵션이 있는 경우
            print(f"{'PORT':<10}{'STATE':<20}{'SERVICE':<20}{'BANNER'}")
            for port, state, service, banner in filteredResults:
                print(f"{port:<10}{state:<20}{service or 'N/A':<20}{banner or 'N/A'}")
        else:  # -sV 옵션이 없는 경우
            print(f"{'PORT':<10}{'STATE':<20}")
            for port, state, _, _ in filteredResults:
                print(f"{port:<10}{state:<20}")

        # 소요 시간 출력
        elapsedTime = time.time() - startTime
        print(f"\n스캔 완료. 소요 시간: {elapsedTime:.2f}초")
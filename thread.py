from concurrent.futures import ThreadPoolExecutor
from ACK.tcp_ack import *
from SYN.tcp_syn import *
from NULL.tcp_null import *
from XMAS.tcp_xmas import *
<<<<<<< HEAD
from VERSION.find_version import *
import time
=======
from VERSION.service_version import *
>>>>>>> c56f333515358e5fde14d96ec41e503708b53dd5

class Thread:
    def __init__(self,ip:str,port:str,timeout:int,numThread:int,maxTries:int,scanMethod)->None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.numThread = numThread
        self.maxTries = maxTries
        self.scanMethod = scanMethod

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
        ports = self.parse_ports(self.port)
        scanMethods = {
            "syn":scan_syn_port,
<<<<<<< HEAD
            "ack":scan_port_ack,
            "Null":scan_null_port,
            "Xmas":scan_xmas_port
=======
            "ack":scan_ack_port,
            "Null":scan_null_port,
            "Xmas":scan_xmas_port,
            "version":scan_service_version
>>>>>>> c56f333515358e5fde14d96ec41e503708b53dd5
        }
        scanFunction = scanMethods.get(self.scanMethod)
        with ThreadPoolExecutor(max_workers=self.numThread,) as executor:
            futures = [executor.submit(scanFunction, self.ip, port, self.timeout,self.maxTries) for port in ports]
            for future in futures:
                results.append(future.result())
        return results

    def print_result(self,results:list)->None:
        # 결과 정렬 및 출력
<<<<<<< HEAD
        if self.scanMethod in ['Xmas','Null']:
            filteredResults = [result for result in results]
        else:   
            filteredResults = [result for result in results if result[1] == "필터링되지 않음 (RST 수신)" or result[1]=='Open']
        filteredResults.sort(key=lambda x: x[0])
        #input('2')
        print(f"\n{self.scanMethod} 스캔 결과:")
        for port, state in filteredResults:
            print(f"Port {port}: {state}")
            if self.scanMethod == 'syn':
                get_service_version(self.ip, port)

        # 소요 시간 출력
        elapsedTime = time.time() - startTime
        print(f"\n스캔 완료. 소요 시간: {elapsedTime:.2f}초")
=======
        filteredResults = [result for result in results if result[1] == "Unfiltered (RST received)" or result[1]=='Open' or result[1]=="Open or Filtered"]
        filteredResults.sort(key=lambda x: x[0])

        print("\n스캔 결과:")
        
        if self.scanMethod == "version":
            print(f"{'PORT':<10}{'STATE':<20}{'SERVICE':<20}{'BANNER'}")
            for port, state, service, banner in filteredResults:
                print(f"Port {port}: {state:<20}{service or 'N/A':<20}{banner or 'N/A'}")
        else:
            for port, state in filteredResults:
                print(f"Port {port}: {state}")
>>>>>>> c56f333515358e5fde14d96ec41e503708b53dd5

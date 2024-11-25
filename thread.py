from concurrent.futures import ThreadPoolExecutor
from ACK.tcp_ack import *
from SYN.tcp_syn import *
import time

class Thread:
    def __init__(self,ip:str,port:str,_time:int,num_thread:int,max_tries:int,scan_method)->None:
        self.ip = ip
        self.port = port
        self._time = _time
        self.num_thread = num_thread
        self.max_tries = max_tries
        self.scan_method = scan_method

    def parsePorts(self,port_input:list)->set:
        """입력된 포트를 숫자로 변환한 후, 중복 제거하여 오름차순으로 정렬된 포트 번호 리스트를 반환."""
        ports = set()
        for part in port_input.split(","):  # 문자열 분리
            # 포트 범위를 리스트로 변환 후 집합에 추가
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports)

    def startThread(self) -> list:
        results=[]
        conf.verb=0
        start_time = time.time()
        ports = self.parsePorts(self.port)
        scan_methods = {
            "syn":scan_syn_port,
            "ack":scanPortAck,
            #"Null":,
            #"Xmas":
        }
        scan_function = scan_methods.get(self.scan_method)
        with ThreadPoolExecutor(max_workers=self.num_thread,) as executor:
            futures = [executor.submit(scan_function, self.ip, port, self._time,self.max_tries) for port in ports]
            for future in futures:
                results.append(future.result())
        return results, start_time

    def printResult(self,results:list,start_time:time)->None:
        # 결과 정렬 및 출력
        filtered_results = [result for result in results if result[1] == "필터링되지 않음 (RST 수신)" or result[1]=='Open']
        filtered_results.sort(key=lambda x: x[0])

        print("\n스캔 결과:")
        for port, state in filtered_results:
            print(f"Port {port}: {state}")

        # 소요 시간 출력
        elapsed_time = time.time() - start_time
        print(f"\n스캔 완료. 소요 시간: {elapsed_time:.2f}초")
from concurrent.futures import ThreadPoolExecutor, as_completed
from VERSION.service_version import *
from SYN.tcp_syn import *
from ACK.tcp_ack import *
from NULL.tcp_null import *
from XMAS.tcp_xmas import *
from OS.p0f import *
from CVE.shodan import *
from OUTPUT.output_handler import *
import ipaddress
from colors import *

class Thread:
    def __init__( # Thread 클래스 초기화 메서드
            self,
            ip: str,
            port: str,
            timeout: int,
            numThread: int,
            maxTries: int,
            os: bool,
            scanMethod: str,
            cve: bool,
            outputFile: str,
            outputXml: str
        )->None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.numThread = numThread
        self.maxTries = maxTries
        self.os = os
        self.scanMethod = scanMethod
        self.cve = cve
        self.outputFile = outputFile
        self.outputXml = outputXml


    def ip_range_to_list(self, ip):
        if ',' in ip:
            ipList = []
            ipListTmp = ip.split(',')
            
            for ips in ipListTmp:
                funcedIp = self.ip_range_to_list(ips)
                ipList.extend(funcedIp)
            return ipList
        
        if '-' in ip:
            try:
                startIpStr, endIpStr = ip.split('-')
                startIp = ipaddress.IPv4Address(startIpStr.strip())
                endIp = ipaddress.IPv4Address(endIpStr.strip())
                ipList = []

                if startIp > endIp:
                    raise ValueError('Start IP must be less than or equal to End IP.')
                
                for ipInt in range(int(startIp), int(endIp) + 1):
                    ipList.append(str(ipaddress.IPv4Address(ipInt)))
                return ipList
            except Exception as e:
                print(f'Error: {e}')
                return []
        elif '/' in ip:
            net4 = ipaddress.ip_network(ip)  
            ipList = [str(x) for x in net4.hosts()]
            return ipList
        else:
            return [str(ipaddress.IPv4Address(ip))]
                
    def parse_ports(self, portInput: str) -> list:  # 포트 범위를 파싱하여 섞인 포트 목록 반환
        ports = []
        
        for part in portInput.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))  # range 결과를 리스트에 추가
            else:
                ports.append(int(part.strip()))  # 개별 포트를 리스트에 추가

        random.shuffle(ports)  # shuffle을 통해 보안 시스템의 연속적인 포트 스캔 탐지를 우회
        return ports
    
    def start_thread(self) -> list:     #멀티 스레드를 실행하여 스캔 시작
        conf.verb=0
        ipList = self.ip_range_to_list(self.ip)

        osResult={}
        if self.os: 
            with ThreadPoolExecutor(max_workers=self.numThread) as executor:
                futures = [executor.submit(run_docker_p0f, os.getcwd(), ip) for ip in ipList]
                for future in as_completed(futures):
                    osResult.update(future.result())
            #print_os_info(osResult)
        ports = self.parse_ports(self.port)
        scanMethods = {
            'syn':scan_syn_port,
            'ack':scan_ack_port,
            'Null':scan_null_port,
            'Xmas':scan_xmas_port,
            'version':scan_service_version
        }

        for ip in ipList:
            results=[]
            with ThreadPoolExecutor(max_workers=self.numThread) as executor:
                futures = [executor.submit(scanMethods.get(self.scanMethod), ip, port, self.timeout, self.maxTries) for port in ports]
                for future in as_completed(futures):
                    results.append(future.result())
            filteredResults = [result for result in results if result[1] == 'Unfiltered (RST received)' or result[1]=='Open' or result[1]=='Open or Filtered']
            filteredResults.sort(key=lambda x: x[0])
                    
            portCveList = {}
            if self.cve:
                for port, state, *_ in filteredResults:
                    cveData = shodan_api(self.ip, port, self.timeout, self.maxTries).process()
                    portCveList[port] = cveData if cveData else []

            self.print_result(ip=ip,results=filteredResults,osResult=osResult, portCveList=portCveList)

    def print_result(self, ip: str, results: list,osResult, portCveList)->None:      # 스캔 결과를 출력하는 메서드
        if self.os:
            print(f"\n{YELLOW}{self.scanMethod.upper()} Scan{RESET} Result of {YELLOW}{ip}{RESET}: {osResult['OS']}")
        else:
            print(f"\n{YELLOW}{self.scanMethod.upper()} Scan{RESET} Result of {YELLOW}{ip}{RESET}: ")

        if self.scanMethod == 'version':
            print(f"\n{'Result':^82}")
            print('='*82)
            print(f"{'PORT':<10}{'STATE':<20}{'SERVICE':<20}{'BANNER'}")
            
            for port, state, service, banner in results:
                print(f"Port {port}: {state:<20}{service or 'N/A':<20}{banner or 'N/A'}")
        else:
            for port, state in results:
                print(f'Port {port}: {state}')
        
        if self.cve:
            for port in results:
                print(f'CVE List at Port {port[0]}: {shodan_api(ip, port[0], self.timeout, self.maxTries).process()}')

        if self.outputFile:        
            save_result_as_json(ip, results, self.scanMethod, self.outputFile, osResult, portCveList)
        if self.outputXml:
            save_result_as_xml(ip, results, self.scanMethod, self.outputXml, osResult, portCveList)
from concurrent.futures import ThreadPoolExecutor
from VERSION.service_version import *
from SYN.tcp_syn import *
from ACK.tcp_ack import *
from NULL.tcp_null import *
from XMAS.tcp_xmas import *
from OS.p0f import *
from CVE.shodan import *
from OUTPUT.output_handler import *
from colors import *

class Thread:
    def __init__(self, ip, port, timeout, numThread, maxTries, os, scanMethod, cve, outputFile, outputXml):
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

    def parse_ports(self, portInput):
        ports = set()
        for part in portInput.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports)

    def start_thread(self):
        results = []
        conf.verb = 0

        os_info = None
        if self.os:
            os_info = run_docker_p0f(os.getcwd(), self.ip)
            print(f'{BLUE}[*]{RESET}OS detected: {YELLOW}{os_info}{RESET}')

        ports = self.parse_ports(self.port)
        scanMethods = {
            'syn': scan_syn_port,
            'ack': scan_ack_port,
            'Null': scan_null_port,
            'Xmas': scan_xmas_port,
            'version': scan_service_version
        }

        scan_func = scanMethods.get(self.scanMethod)
        if not scan_func:
            raise ValueError(f"Invalid scan method: {self.scanMethod}")

        with ThreadPoolExecutor(max_workers=self.numThread) as executor:
            futures = [executor.submit(scan_func, self.ip, port, self.timeout, self.maxTries) for port in ports]
            for future in futures:
                results.append(future.result())

        port_cve_list = {}
        if self.cve:
            for port, state, *_ in results:
                if state.lower() not in ['filtered', 'closed']:
                    cve_data = shodan_api(self.ip, port, self.timeout, self.maxTries).process()
                    port_cve_list[port] = cve_data if cve_data else []

        if self.outputFile:
            save_result_as_json(results, self.scanMethod, self.outputFile, os_info=os_info, port_cve_list=port_cve_list)

        if self.outputXml:
            save_result_as_xml(results, self.scanMethod, self.outputXml, os_info=os_info, port_cve_list=port_cve_list)

        return results, port_cve_list

    def print_result(self, results, port_cve_list):
        """
        스캔 결과를 출력하는 메서드
        - filtered 및 closed 상태를 제외하고 출력
        - 스캔 방식에 따라 출력 형식 변경
        """
        filteredResults = [
            result for result in results
            if result[1].lower() not in ['filtered', 'closed']
        ]
        filteredResults.sort(key=lambda x: x[0])  # 포트를 기준으로 정렬

        print(f"\n{self.scanMethod.upper()} Scan Result:")
        print(f"{'=' * 82}")
        if self.scanMethod == 'version':  # -sV 옵션
            print(f"{'PORT':<10}{'STATE':<20}{'SERVICE':<20}{'BANNER'}")
            for port, state, service, banner in filteredResults:
                print(f"Port {port}: {state:<20}{service or 'N/A':<20}{banner or 'N/A'}")
                cve_list = port_cve_list.get(port, [])
                print(f"CVE List at Port {port}: {cve_list}")
        else:  # -S (SYN 스캔) 옵션
            print(f"{'PORT':<10}{'STATE':<20}")
            for port, state in filteredResults:
                print(f"Port {port}: {state}")
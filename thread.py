from concurrent.futures import ThreadPoolExecutor
from VERSION.service_version import *
from NULL.tcp_null import *
from XMAS.tcp_xmas import *
from ACK.tcp_ack import *
from SYN.tcp_syn import *
from OS.p0f import *
from json_handler import *
from colors import *

class Thread:
    def __init__(self,ip:str,port:str,timeout:int,numThread:int,maxTries:int,os:bool,scanMethod,outputFile:str)->None:
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.numThread = numThread
        self.maxTries = maxTries
        self.os = os
        self.scanMethod = scanMethod
        self.outputFile = outputFile

    def parse_ports(self,portInput:list)->set:
        ports = set()
        for part in portInput.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports)

    def start_thread(self) -> list:
        results=[]
        conf.verb=0

        if self.os: 
            print(f'{BLUE}[*]{RESET}OS detected : {YELLOW}{run_docker_p0f(os.getcwd(), self.ip)}{RESET}')

        ports = self.parse_ports(self.port)
        scanMethods = {
            "syn":scan_syn_port,
            "ack":scan_ack_port,
            "Null":scan_null_port,
            "Xmas":scan_xmas_port,
            "version":scan_service_version
        }
        scanFunction = scanMethods.get(self.scanMethod)
        with ThreadPoolExecutor(max_workers=self.numThread,) as executor:
            futures = [executor.submit(scanFunction, self.ip, port, self.timeout,self.maxTries) for port in ports]
            for future in futures:
                results.append(future.result())
        return results

    def print_result(self,results:list)->None:
        filteredResults = [result for result in results if result[1] == "Unfiltered (RST received)" or result[1]=='Open' or result[1]=="Open or Filtered"]
        filteredResults.sort(key=lambda x: x[0])

        if self.scanMethod == "version":
            print("\n"+" "*38+"Result")
            print('='*82)
            print(f"{'PORT':<10}{'STATE':<20}{'SERVICE':<20}{'BANNER'}")
            for port, state, service, banner in filteredResults:
                print(f"Port {port}: {state:<20}{service or 'N/A':<20}{banner or 'N/A'}")
        else:
            for port, state in filteredResults:
                print(f"Port {port}: {state}")
        
        if self.outputFile:        
            save_result_as_json(filteredResults, self.scanMethod, self.outputFile)
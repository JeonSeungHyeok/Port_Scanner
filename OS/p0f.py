from pathlib import Path
from colors import *
import subprocess
import time
import sys
import os

def run_docker_p0f(logDir, targetIp):
    logDirPath = Path(logDir).resolve()
    logDirDocker = str(logDirPath).replace('\\', '/')
    
    docker_command = [
        'docker', 'run', '--rm', '--cap-add=NET_ADMIN',
        '-v', f'{logDirDocker}:/var/log/p0f',
        'p0f',targetIp
    ]
    
    print(f'{BLUE}[*]{RESET} Executing  Docker Container {YELLOW}p0f{RESET} for {YELLOW}{targetIp}{RESET}')
    
    try:  # 도커 실행
        subprocess.Popen(docker_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, universal_newlines=True)
    except FileNotFoundError:
        print(f'{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}')
        return 'Unknown'
    except Exception as e:
        print(f'{RED}[-]{RESET} Error while ececuting Docker Container: {e}')
        return 'Unknown'
    time.sleep(3)
    #max_retries = 3
    #for attempt in range(max_retries):
    #    try:
    #        subprocess.run(['curl', f'{targetIp}:80'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #        print(f'{BLUE}[*]{RESET} HTTP Request sent successfully to {YELLOW}{targetIp}{RESET}')
    #        break
    #    except subprocess.CalledProcessError as e:
    #        if attempt < max_retries - 1:
    #            print(f'{RED}[-]{RESET} Retry {attempt + 1}/{max_retries}')
    #            time.sleep(2)
    #        else:
    #            print(f'{RED}[-]{RESET} HTTP Request failed: {e}')
    #    finally:
    #        stdout, stderr = p0fProc.communicate(timeout=10)
    #        if stdout:
    #            print(f'Docker stdout:\n{stdout}')
    #        if stderr:
    #            print(f'Docker stderr:\n{stderr}')
    logFile = logDirPath / f'{targetIp}_p0f_output.log'
    osInfo = extract_os_info(logFile)
    return dict(ip=targetIp, OS=osInfo)

def extract_os_info(logFilePath):
    osInfo = 'Unknown'
    try:
        with open(logFilePath, 'r') as logFile:
            lines = logFile.readlines()
            count = 0
            for line in lines:
                if '|os' in line:
                    count += 1
                    if count == 2:
                        osInfo = line.split('=')[5].strip().split('|')[0]
                        break
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't find log file: {YELLOW}{logFilePath}{RESET}")
    except Exception as e:
        print(f'{RED}[-]{RESET} Error while reading log file: {e}')
    try:
        os.remove(logFilePath)
        print(f'{BLUE}[*]{RESET} {YELLOW}{logFilePath}{RESET} deleted')
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't delete log file: {YELLOW}{logFilePath}{RESET}")
    
    return osInfo

def print_os_info(osInfo:list):
    for OS in osInfo:
        print(f"{BLUE}[*]{RESET} OS detected at {YELLOW}{OS['ip']}{RESET} : {YELLOW}{OS['OS']}{RESET}")
from pathlib import Path
from colors import *
import subprocess
import time
import sys
import os

def run_docker_p0f(log_dir, target_ip):
    log_dir_path = Path(log_dir).resolve()
    log_dir_docker = str(log_dir_path).replace("\\", "/")
    
    docker_command = [
        'docker', 'run', '--rm', '--cap-add=NET_ADMIN',
        '-v', f'{log_dir_docker}:/var/log/p0f',
        'p0f',target_ip
    ]
    
    print(f"{BLUE}[*]{RESET} Executing  Docker Container {YELLOW}p0f{RESET} for {YELLOW}{target_ip}{RESET}")
    try:
        p0f_proc = subprocess.Popen(docker_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, universal_newlines=True)
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}")
        return "Unknown"
    except Exception as e:
        print(f"{RED}[-]{RESET} Error while ececuting Docker Container: {e}")
        return "Unknown"
    time.sleep(3)
    #max_retries = 3
    #for attempt in range(max_retries):
    #    try:
    #        subprocess.run(['curl', f'{target_ip}:80'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #        print(f"{BLUE}[*]{RESET} HTTP Request sent successfully to {YELLOW}{target_ip}{RESET}")
    #        break
    #    except subprocess.CalledProcessError as e:
    #        if attempt < max_retries - 1:
    #            print(f"{RED}[-]{RESET} Retry {attempt + 1}/{max_retries}")
    #            time.sleep(2)
    #        else:
    #            print(f"{RED}[-]{RESET} HTTP Request failed: {e}")
    #    finally:
    #        stdout, stderr = p0f_proc.communicate(timeout=10)
    #        if stdout:
    #            print(f"Docker stdout:\n{stdout}")
    #        if stderr:
    #            print(f"Docker stderr:\n{stderr}")
    log_file = log_dir_path / f'{target_ip}_p0f_output.log'
    osInfo = extract_os_info(log_file)
    return dict(ip=target_ip,OS=osInfo)

def extract_os_info(log_file_path):
    osInfo = "Unknown"
    try:
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
            count = 0
            for line in lines:
                if '|os' in line:
                    count += 1
                    if count == 2:
                        osInfo = line.split('=')[5].strip().split('|')[0]
                        break
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't find log file: {YELLOW}{log_file_path}{RESET}")
    except Exception as e:
        print(f"{RED}[-]{RESET} Error while reading log file: {e}")
    try:
        os.remove(log_file_path)
        print(f"{BLUE}[*]{RESET} {YELLOW}{log_file_path}{RESET} deleted")
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't delete log file: {YELLOW}{log_file_path}{RESET}")
    
    return osInfo

def print_os_info(osInfo:list):
    for OS in osInfo:
        print(f"{BLUE}[*]{RESET} OS detected at {YELLOW}{OS['ip']}{RESET} : {YELLOW}{OS['OS']}{RESET}")
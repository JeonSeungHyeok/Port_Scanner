from pathlib import Path
from colors import *
import subprocess
import time
import os

def run_docker_p0f(log_dir, target_ip):
    log_dir_path = Path(log_dir).resolve()
    log_dir_docker = str(log_dir_path).replace("\\", "/")
    
    docker_command = [
        'docker', 'run', '--rm', '--cap-add=NET_ADMIN',
        '-v', f'{log_dir_docker}:/var/log/p0f',
        'p0f',target_ip
    ]
    
    print(f"{BLUE}[*]{RESET} Ececuting Docker Container {YELLOW}p0f{RESET}")
    try:
        p0f_proc = subprocess.Popen(docker_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, universal_newlines=True)
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}")
        return "Unknown"
    except Exception as e:
        print(f"{RED}[-]{RESET} Error while ececuting Docker Container: {e}")
        return "Unknown"
    
    try:
        time.sleep(2)
        print(f"{BLUE}[*]{RESET} Sending HTTP Request to {YELLOW}{target_ip}{RESET}")
        subprocess.run(['curl', target_ip], check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        print(f"{BLUE}[*]{RESET} HTTP Request sended")
        time.sleep(3)
        
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]{RESET} Error while sending HTTP Request: {e}")
    finally:
        stdout, stderr = p0f_proc.communicate()
        if stdout:
            print(f"Docker stdout:\n{stdout}")
        if stderr:
            print(f"Docker stderr:\n{stderr}")
    log_file = log_dir_path / 'p0f_output.log'
    os_info = extract_os_info(log_file)
    return os_info

def extract_os_info(log_file_path):
    os_info = "Unknown"
    try:
        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
            count = 0
            for line in lines:
                if '|os' in line:
                    count += 1
                    if count == 2:
                        os_info = line.split('=')[5].strip().split('|')[0]
                        break
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} Can't find log file: {YELLOW}{log_file_path}{RESET}")
    except Exception as e:
        print(f"{RED}[-]{RESET} Error while reading log file: {e}")
    os.remove(log_file_path)
    print(f"{BLUE}[*]{RESET} {YELLOW}{log_file_path}{RESET} deleted")
    
    return os_info
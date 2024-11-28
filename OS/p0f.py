from pathlib import Path
from colors import *
import subprocess
import platform
import time
import sys
import os


def build_image(tag='p0f', path='/OS'):
    try:
        print(f"{BLUE}[*]{RESET} Building Docker image '{YELLOW}{tag}{RESET}' from '{YELLOW}{os.getcwd()+path}{RESET}'")
        result = subprocess.run(
            ['docker', 'build', '-t', tag, '.'+path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"{GREEN}[+]{RESET} Docker image '{YELLOW}{tag}{RESET}' built successfully.")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]{RESET} Error during building Docker image:\n{e.stderr}")
        sys.exit(e.returncode)
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}")
        sys.exit(1)

def remove_image(tag='p0f'):
    try:
        print(f"{BLUE}[*]{RESET} Removing Docker image '{YELLOW}{tag}{RESET}'")
        result = subprocess.run(
            ['docker', 'rmi', tag],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"{GREEN}[+]{RESET} Docker image '{YELLOW}{tag}{RESET}' removed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]{RESET} Error during removing Docker image:\n{e.stderr}")
        sys.exit(e.returncode)
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}")
        sys.exit(1)

def run_docker_p0f(log_dir, target_ip):
    build_image()
    log_dir_path = Path(log_dir).resolve()
    log_dir_docker = str(log_dir_path).replace("\\", "/")
    
    docker_command = [
        'docker', 'run', '--rm', '--cap-add=NET_ADMIN',
        '-v', f'{log_dir_docker}:/var/log/p0f',
        'p0f',target_ip
    ]
    
    print(f"{BLUE}[*]{RESET} Ececuting Docker Container {YELLOW}p0f{RESET}")
    try:
        p0f_proc = subprocess.Popen(docker_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    except FileNotFoundError:
        print(f"{RED}[-]{RESET} There is no Docker or Not included in {RED}$PATH{RESET}")
        return "Unknown"
    except Exception as e:
        print(f"{RED}[-]{RESET} Error while ececuting Docker Container: {e}")
        return "Unknown"
    
    try:
        time.sleep(2)
        print(f"{BLUE}[*]{RESET} Sending HTTP Request to {YELLOW}{target_ip}{RESET}")
        subprocess.run(['curl', target_ip], check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
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
    remove_image()
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
    # if 'Windows' in platform.platform():
    #     rmCommand = ['del',f'{log_file_path}']
    # else: 
    #     rmCommand = ['rm',f'{log_file_path}']
    # subprocess.run(rmCommand,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    print(f"{BLUE}[*]{RESET} {YELLOW}{log_file_path}{RESET} deleted")
    
    return os_info

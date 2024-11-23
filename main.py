from scanner import *
import optparse
import sys
from color import *

def option_help():
    help = f'''
{GREEN}Usage{RESET}: port scanner
    
{GREEN}Option help{RESET}:
    -h      scan option
{GREEN}Scan method{RESET}:
    -S      TCP SYN scan
    -A      TCP ACK scan
    -N      TCP Null scan
    -X      TCP X-mas scan
{GREEN}IP & Port{RESET}:
    -IP     Specify IP range 
    -P      Specify Port range
{GREEN}Speed{RESET}:
    -T      Specify Thread 0~10
    '''
    print(help)
def parser():
    pass



def main():
    option_help()
    command = 'a'#input("'scanner' 및 'scanner -h' 및 'scanner --help'를 입력해주세요!")
    if command in ('scan', 'scan -h', 'scan --help'):
        option_help()
    else:
        print('다시 입력해주세요')
    
    

if __name__ == '__main__':
    main()
    
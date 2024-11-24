from scanner import *
import argparse

def add_options(parser):
    parser.add_argument('-stl', action='store_true', dest='stealth', help="stealth scan")
    
    parser.add_argument('-S', action='store_true', dest='SYN', help="TCP SYN scan")
    parser.add_argument('-A', action='store_true', dest='ACK', help="TCP ACK scan")
    parser.add_argument('-N', action='store_true', dest='Null', help="TCP Null scan")
    parser.add_argument('-X', action='store_true', dest='Xmas', help="TCP X-mas scan")
    
    parser.add_argument('-IP', action='append', dest='ip', default=socket.gethostbyname(socket.getfqdn()), help="Specify IP range(basic IP is self)")
    parser.add_argument('-P', action='append', dest='port', default=range(1024), help="Specify Port range")
    
    parser.add_argument('-T', action='count', dest='thread', default=0, help="Specify Thread 0~10")
    
    parser.add_argument('-OS', action='store_true', dest='os', help="Detection OS")
    
    parser.add_argument('-oj', action='store_true', dest='output_json', help="Output JSON")
    parser.add_argument('-ox', action='store_true', dest='output_xml', help="Output XML")
    

def main():
    parser = argparse.ArgumentParser()
    add_options(parser)
    options, args = parser.parse_args()
    print(options, args)


if __name__ == '__main__':
    main()
    
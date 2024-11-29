def usage_msg():
    return "python3 main.py <ip> [-S] [-A] [-N] [-X] -P PORT [-T THREADS] [-t TIME] [-M TRIES] [-OS] [-oj] [-ox]"

def add_options(parser):
    """명령줄 인자를 추가하는 함수"""
    parser.add_argument('-S', action='store_true', dest='syn', help="TCP SYN scan")
    parser.add_argument('-A', action='store_true', dest='ack', help="TCP ACK scan")
    parser.add_argument('-N', action='store_true', dest='Null', help="TCP Null scan")
    parser.add_argument('-X', action='store_true', dest='Xmas', help="TCP X-mas scan")
    parser.add_argument('-sV', action='store_true', dest='service_version', help="Service version scan")
    parser.add_argument('ip', help="Target IP address")
    parser.add_argument('-P', required=True, dest='port', help="Specify port range (e.g., '22,80,443' or '20-30')")
    parser.add_argument('-T', type=int, default=1, dest='threads', help="Specify number of threads (default: 1)")
    parser.add_argument('-t', type=float, default=1, dest='time', help="Response Time")
    parser.add_argument('-M', type=int, default=1, dest='tries', help="Maximum tries")
    parser.add_argument('-OS', action='store_true', dest='os', help="Detection OS")
    parser.add_argument('-oj', type=str, dest='output_json', help="Output JSON file")  # 수정
    parser.add_argument('-ox', type=str, dest='output_xml', help="Output XML file")  # 수정

def option(options):
    if options.service_version:
        return 'version'
    elif options.syn:
        return 'syn'
    elif options.ack:
        return 'ack'
    elif options.Null:
        return 'Null'
    elif options.Xmas:
        return 'Xmas'
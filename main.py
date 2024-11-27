from option import *
from thread import *
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(usage=usage_msg())
    add_options(parser)
    if hasattr(parser, 'parse_intermixed_args'):
        options = parser.parse_intermixed_args()
    else:
        options = parser.parse_args()
    thread = Thread(ip=options.ip,port=options.port,timeout=options.time,numThread=options.threads,maxTries=options.tries,scanMethod=option(options))
    result, time = thread.start_thread()
    thread.print_result(result,time)

if __name__=="__main__":
    main()
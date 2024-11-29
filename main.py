from option import *
from thread import *
import argparse
import sys
import time

def main():
    parser = argparse.ArgumentParser(usage=usage_msg())
    add_options(parser)
    if hasattr(parser, 'parse_intermixed_args'):
        options = parser.parse_intermixed_args()
    else:
        options = parser.parse_args()

   
    output_json = options.output_json and options.service_version
    thread = Thread(ip=options.ip,port=options.port,timeout=options.time,numThread=options.threads,maxTries=options.tries,os=options.os,scanMethod=option(options),output_json=options.output_json)
    result, time = thread.start_thread()
    thread.print_result(result)

if __name__=="__main__":
    main()
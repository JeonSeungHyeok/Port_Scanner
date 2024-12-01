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
    thread = Thread(ip=options.ip,port=options.port,timeout=options.time,numThread=options.threads,maxTries=options.tries,os=options.os,scanMethod=option(options),outputFile=options.output_json)
    
    startTime = time.time()
    result = thread.start_thread()
    thread.print_result(result)
    elapsedTime = time.time() - startTime
    print(f"\nComplete scan. Time taken: {elapsedTime:.2f}s")

if __name__=="__main__":
    main()
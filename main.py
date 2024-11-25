from option import *
from thread import *
import argparse

def main():
    parser = argparse.ArgumentParser()
    add_options(parser)
    options = parser.parse_args()
    thread = Thread(ip=options.ip,port=options.port,_time=options.time,num_thread=options.threads,max_tries=options.tries,scan_method=option(options))
    result, time = thread.startThread()
    thread.printResult(result,time)

if __name__=="__main__":
    main()
from option import *
from thread import *
import argparse

def main():
    parser = argparse.ArgumentParser()
    add_options(parser)
    options = parser.parse_args()
    thread = Thread(ip=options.ip,port=options.port,timeout=options.time,numThread=options.threads,maxTries=options.tries,scanMethod=option(options))
    result, time = thread.start_thread()
    thread.print_result(result,time)
    ######commit test#####

if __name__=="__main__":
    main()

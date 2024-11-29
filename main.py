from option import *
from thread import *
import argparse
import sys
import time
# from json_utils import save_to_json
# from output_handler import OutputHandler

def main():
    parser = argparse.ArgumentParser(usage=usage_msg())
    add_options(parser)
    if hasattr(parser, 'parse_intermixed_args'):
        options = parser.parse_intermixed_args()
    else:
        options = parser.parse_args()
    thread = Thread(ip=options.ip,port=options.port,
                    timeout=options.time,
                    numThread=options.threads,
                    maxTries=options.tries,
                    scanMethod=option(options),
                    outputFile=options.output_json)  ####### output_json 값을 Thread 객체에 전달
    
    startTime = time.time()
    result = thread.start_thread()
    thread.print_result(result)
    elapsedTime = time.time() - startTime
    print(f"\n스캔 완료. 소요 시간: {elapsedTime:.2f}초")
    


if __name__=="__main__":
    main()
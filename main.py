from option import *
from thread import *
from output_handler import OutputHandler #추가
from cpe_mapper import CPEMapper #추가
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
    thread = Thread(ip=options.ip,port=options.port,timeout=options.time,numThread=options.threads,maxTries=options.tries,scanMethod=option(options))
    
    startTime = time.time()
    result = thread.start_thread()
    thread.print_result(result)
    elapsedTime = time.time() - startTime
    print(f"\n스캔 완료. 소요 시간: {elapsedTime:.2f}초")
  ##########################################################################추가  
   # JSON 저장 및 CPE 처리
    if options.output_json:
        print(f"[INFO] 결과를 JSON 파일로 저장 중: {options.output_json}")
    OutputHandler.process_results_with_cpe(
        results=result,
        target_ip=options.ip,
        output_file=options.output_json
    )
if __name__=="__main__":
    main()
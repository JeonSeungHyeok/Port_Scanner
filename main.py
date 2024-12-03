from OPTION.option import *
from thread import *
import argparse
import time

def main():
    parser = argparse.ArgumentParser(usage=usage_msg())     #명령줄 파서 생성
    add_options(parser)
    if hasattr(parser, 'parse_intermixed_args'):        # 파서가 parse_intermixed_args 메서드를 지원하는지 확인
        options = parser.parse_intermixed_args()
    else:
        options = parser.parse_args()

    thread = Thread(
        ip=options.ip,
        port=options.port,
        timeout=options.time,
        numThread=options.threads,
        maxTries=options.tries,
        os=options.os,
        scanMethod=option(options),
        cve = options.cve,
        outputFile=options.output_json,
        outputXml=options.output_xml)
    
    startTime = time.time()
    results, port_cve_list = thread.start_thread()  # 두 개의 값을 반환받음
    thread.print_result(results, port_cve_list)     # 두 개의 값을 print_result에 전달
    elapsedTime = time.time() - startTime
    print(f'\nScan Completed. Elapsed Time: {elapsedTime:.2f}s')

if __name__=='__main__':
    main()
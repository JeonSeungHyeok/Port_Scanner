import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from colors import *
def save_result_as_json(results, scanMethod, outputFile):
    """스캔 결과를 JSON으로 저장하는 함수"""
    if scanMethod == 'version': # -sV 옵션 사용 시 service, banner 출력
        resultsJson = [
            {'port': port, 'state': state, 'service': service, 'banner': banner}
            for port, state, service, banner in results
        ]
    else:
        resultsJson = [
            {'port': port, 'state': state} for port, state in results
        ]

    data = {
        'scanMethod': scanMethod,
        'results': resultsJson
    }

    with open(outputFile, 'w', encoding='utf-8') as f:  # utf-8로 파일 쓰기
        json.dump(data, f, indent=4)
    print(f'{GREEN}[INFO]{RESET} Results saved as JSON to {YELLOW}{outputFile}{RESET}')  
    
def save_result_as_xml(results, scanMethod, outputFile):  # 루트 엘리먼트 생성
    """스캔 결과를 XML로 저장하는 함수"""
    root = ET.Element('ScanResults', scanMethod=scanMethod)

    # 결과 데이터를 XML로 추가
    for result in results:
        resultElement = ET.SubElement(root, 'Result')
        ET.SubElement(resultElement, 'Port').text = str(result[0])
        ET.SubElement(resultElement, 'State').text = result[1]
        
        if scanMethod == 'version':
            ET.SubElement(resultElement, 'Service').text = result[2]
            ET.SubElement(resultElement, 'Banner').text = result[3]

    # XML 문자열 생성 (Pretty Print)
    rough_string = ET.tostring(root, encoding='utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent='    ')

    # XML 파일 저장
    with open(outputFile, 'w', encoding='utf-8') as f:
        f.write(pretty_xml)
    print(f'{GREEN}[INFO]{RESET} Results saved as XML to {YELLOW}{outputFile}{RESET}')
    
    ###########minidom.parseString 사용: ET.tostring으로 생성된 XML 문자열을 minidom으로 포맷팅.
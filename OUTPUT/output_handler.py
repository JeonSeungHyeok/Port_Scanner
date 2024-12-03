import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from colors import *

def save_result_as_json(results, scanMethod, outputFile, os_info=None, port_cve_list=None):
    """
    스캔 결과를 JSON으로 저장하는 함수
    - filtered 및 closed 상태를 제외
    - scanMethod에 따라 결과 필드 조정
    """
    filteredResults = [
        result for result in results
        if result[1].lower() not in ['filtered', 'closed']
    ]

    if scanMethod == 'version':  # 서비스와 배너 정보를 포함
        resultsJson = [
            {
                'port': port,
                'state': state,
                'service': service,
                'banner': banner,
                'cve_list': port_cve_list.get(port, []) if port_cve_list else None
            }
            for port, state, service, banner in filteredResults
        ]
    else:  # SYN 스캔 또는 다른 스캔 옵션의 경우
        resultsJson = [
            {
                'port': port,
                'state': state
            }
            for port, state in filteredResults
        ]

    data = {
        'scanMethod': scanMethod,
        'results': resultsJson
    }

    if os_info:
        data['os_info'] = os_info

    with open(outputFile, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    print(f'{GREEN}[INFO]{RESET} Results saved as JSON to {YELLOW}{outputFile}{RESET}')


def save_result_as_xml(results, scanMethod, outputFile, os_info=None, port_cve_list=None):
    """
    스캔 결과를 XML로 저장하는 함수
    - port_cve_list: 각 포트별 CVE 리스트
    - os_info: OS 정보
    """
    filteredResults = [
        result for result in results
        if result[1].lower() not in ['filtered', 'closed']
    ]

    root = ET.Element('ScanResults', scanMethod=scanMethod)

    for result in filteredResults:
        port = result[0]
        state = result[1]

        resultElement = ET.SubElement(root, 'Result')
        ET.SubElement(resultElement, 'Port').text = str(port)
        ET.SubElement(resultElement, 'State').text = state

        if scanMethod == 'version':  # -sV 옵션일 때만 서비스와 배너 추가
            service = result[2] if len(result) > 2 else None
            banner = result[3] if len(result) > 3 else None
            if service:
                ET.SubElement(resultElement, 'Service').text = service
            if banner:
                ET.SubElement(resultElement, 'Banner').text = banner

        # CVE 리스트 추가
        if port_cve_list:
            cveListElement = ET.SubElement(resultElement, 'CVEList')
            for cve in port_cve_list.get(port, []):
                ET.SubElement(cveListElement, 'CVE').text = cve

    if os_info:
        osElement = ET.SubElement(root, 'OSInfo')
        ET.SubElement(osElement, 'OS').text = os_info

    rough_string = ET.tostring(root, encoding='utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent='    ')

    with open(outputFile, 'w', encoding='utf-8') as f:
        f.write(pretty_xml)
    print(f'{GREEN}[INFO]{RESET} Results saved as XML to {YELLOW}{outputFile}{RESET}')

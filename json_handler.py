import json

def save_result_as_json(results, scanMethod, outputFile=None):  ####### outputFile 파라미터 추가
    """
    스캔 결과를 JSON으로 저장하는 함수
    """
    if scanMethod == "version":
        resultsJson = [
            {"port": port, "state": state, "service": service, "banner": banner}
            for port, state, service, banner in results
        ]
    else:
        resultsJson = [
            {"port": port, "state": state} for port, state in results
        ]

    data = {
        "scanMethod": scanMethod,
        "results": resultsJson
    }

    outputFile = outputFile or "scanResults.json"  ####### outputFile이 None일 경우 기본값 설정

    with open(outputFile, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[INFO] Results saved as JSON to {outputFile}")  ####### 저장된 파일 이름 출력
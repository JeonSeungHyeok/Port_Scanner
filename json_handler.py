import json
from datetime import datetime

def save_to_json(data, prefix="data"):
    """
    데이터를 JSON 파일로 저장. 파일 이름은 날짜와 시간 기반으로 자동 생성.
    """
    # 날짜 기반 파일 이름 생성
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"{prefix}_{timestamp}.json"
    
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"데이터가 '{file_name}' 파일에 성공적으로 저장되었습니다.")
    except Exception as e:
        print(f"JSON 저장 중 오류 발생: {e}")

def load_from_json(file_name):
    """
    JSON 파일에서 데이터 불러옴.
    """
    try:
        with open(file_name, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"'{file_name}' 파일에서 데이터를 성공적으로 불러왔습니다.")
        return data
    except FileNotFoundError:
        print(f"파일 '{file_name}'이(가) 존재하지 않습니다.")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON 디코딩 오류 발생: {e}")
        return None

# 사용 예시
if __name__ == "__main__":
    data = {"status": "success", "details": "Scan completed"}
    
    # 파일 저장 (prefix는 기본값 'data'로 설정됨)
    save_to_json(data, prefix="scan_results")
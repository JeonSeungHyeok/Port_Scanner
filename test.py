import subprocess

def run_test(command):
    """Subprocess를 통해 명령어를 실행하고 결과를 출력합니다."""
    print(f"Running command: {command}")
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        print("Output:")
        print(result.stdout)
        if result.stderr:
            print("Error:")
            print(result.stderr)
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    ip = "54.180.158.188"
    
    test_cases = [
        f"python main.py {ip} -P 20-50,80 -S -T 10 -t 0.1",
        f"python main.py {ip} -P 20-50,80 -A -T 10 -t 0.1",
        f"python main.py {ip} -P 20-50,80 -X -T 10 -t 0.1",
        f"python main.py {ip} -P 20-50,80 -N -T 10 -t 0.1",
        f"python main.py {ip} -P 20-50,80 -sV -T 10 -t 0.1",
        f"python main.py {ip} -P 20-50,80 -S -v -T 10 -t 0.1",
        f"python main.py {ip} -P 20-50,80 -S -v -T 10 -t 0.1 -oj result.json",
        f"python main.py {ip} -P 20-50,80 -S -v -T 10 -t 0.1 -ox result.xml",
        f"python main.py {ip} -P 20-50,80 -S -v -O -T 10 -t 0.1 -oj result.json"
    ]

    for command in test_cases:
        run_test(command)
        print("-" * 80)

if __name__ == "__main__":
    main()

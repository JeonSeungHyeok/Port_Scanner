from scapy.all import IP, TCP, sr1

def fingerprint_database(ttl, window_size):
    db = [
        {"ttl": 64, "window_size": 5840, "os": "Linux 2.x/3.x/4.x"},
        {"ttl": 64, "window_size": 87380, "os": "Linux 5.x/6.x"},
        {"ttl": 64, "window_size": 65535, "os": "Darwin"},
        {"ttl": 128, "window_size": 8192, "os": "Windows 7, Vista and Server 2008"},
        {"ttl": 128, "window_size": 65535, "os": "Windows XP"},
        {"ttl": 255, "window_size": 4128, "os": "Cisco Router"},
    ]

    for entry in db:
        if ttl <= entry["ttl"] and window_size <= entry["window_size"]:
            return entry["os"]
        elif ttl==128:
            return 'Windows ( Unknown Version )'
        elif ttl==64:
            return 'Linux ( Unknown Version)'
    return "Unknown OS"


def detect_os_with_db(target_ip):
    packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
    response = sr1(packet, timeout=2, verbose=0)

    if response:
        ttl = response[IP].ttl
        window = response[TCP].window
        os_guess = fingerprint_database(ttl, window)
        return f"TTL: {ttl}, Window Size: {window}, Expected OS: {os_guess}"
    else:
        return "None Response"

# 사용 예시
target_ip = "54.180.158.188"#"192.168.140.133"
print(detect_os_with_db(target_ip))

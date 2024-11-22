import socket

class port_scanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        
    def port_scanner(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREM)
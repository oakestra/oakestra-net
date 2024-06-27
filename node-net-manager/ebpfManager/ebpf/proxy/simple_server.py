import socket
import time

# Server settings
host = '0.0.0.0'  # Server IP address
port = 1234  # Port to listen on

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((host, port))
    print(f"Server: listening on {host}:{port}")
    while True:
        data, address = s.recvfrom(4096)
        print(
            f"Server Received: {data.decode()} from {address[0]} with destination port {port} and source port {address[1]}")

        time.sleep(5)
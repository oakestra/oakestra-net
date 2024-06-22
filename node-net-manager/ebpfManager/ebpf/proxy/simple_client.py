import socket
import time

# Client settings
host = '10.30.0.2'  # Server IP address
port = 1234  # Port to connect to
source_port = 49679
time.sleep(5)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(("", source_port))
    i = 0
    while True:
        # Sending a message to the simple_server
        message = f"{i}".encode('utf-8')
        s.sendto(message, (host, port))
        print(f"Client: Sent message {message}")
        i += 1

        time.sleep(5)
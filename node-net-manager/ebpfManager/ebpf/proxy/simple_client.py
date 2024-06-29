import socket
import time

# Client settings
host = '10.30.0.2'  # Server Service IP address
port = 1234  # Port to connect to
source_port = 4967
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

# import socket
# import time
#
# host = '10.30.0.2'  # Server Service IP address
# port = 1234  # Port to connect to
#
# time.sleep(5)
#
# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#     s.connect((host, port))
#     number = 1
#     while True:
#         s.sendall(str(number).encode())
#         print(f'Sent: {number}')
#         number += 1
#         time.sleep(5)

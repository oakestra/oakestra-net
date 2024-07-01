# import time
# import socket
#
# host = '10.30.0.2'  # Server Service IP address
# port = 1234  # Port to connect to
# time.sleep(5)
# def start_client():
#     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#         server_address = (host, port)
#         num = 0
#         while True:
#             s.sendto(str(num).encode(), server_address)
#             data, _ = s.recvfrom(1024)
#             print("Client recieved ", data.decode())
#             time.sleep(5)
#             num = int(data.decode()) + 1
#
#
#
# if __name__ == '__main__':
#     start_client()


import socket
import time

host = '10.30.0.2'  # Server Service IP address
port = 1234  # Port to connect to

time.sleep(5)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.sendall(str(0).encode())
    while True:
        data = s.recv(1024)
        if not data:
            break
        msg = data.decode()
        print('Client received:', msg)
        time.sleep(5)
        s.sendall(str(int(msg) + 1).encode())

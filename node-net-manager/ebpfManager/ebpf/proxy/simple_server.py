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

# import socket
#
# # Server settings
# host = '0.0.0.0'  # Server IP address
# port = 1234  # Port to listen on
#
# def start_server():
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.bind((host, port))
#         s.listen()
#         print(f'Server listening on {host}:{port}')
#     except socket.error as e:
#         print(f"Socket error: {e}")
#         return
#
#     while True:
#         try:
#             conn, addr = s.accept()
#             print('Connected by', addr)
#             with conn:
#                 while True:
#                     data = conn.recv(1024)
#                     if not data:
#                         break
#                     print('Received:', data.decode())
#         except socket.error as e:
#             print(f"Connection error: {e}")
#         finally:
#             conn.close()
#
# if __name__ == '__main__':
#     start_server()
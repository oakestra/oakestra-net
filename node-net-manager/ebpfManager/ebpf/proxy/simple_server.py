# import socket
# import time
#
# # Server settings
# host = '0.0.0.0'  # Server IP address
# port = 1234  # Port to listen on
#
# def start_server():
#     with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#         s.bind((host, port))
#         while True:
#             data, addr = s.recvfrom(1024)
#             print("Server recieved ", data.decode())
#             time.sleep(5)
#             num = int(data.decode()) + 1
#             s.sendto(str(num).encode(), addr)
#
#
# if __name__ == '__main__':
#     start_server()

import socket
import time

# Server settings
host = '0.0.0.0'  # Server IP address
port = 1234  # Port to listen on

def start_server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()
        # print(f'Server listening on {host}:{port}')
    except socket.error as e:
        print(f"Socket error: {e}")
        return

    while True:
        try:
            conn, addr = s.accept()
            # print('Connected by', addr)
            with conn:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    msg = data.decode()
                    print('Server received:', msg)
                    time.sleep(5)
                    conn.sendall(str(int(msg) + 1).encode())
        except socket.error as e:
            print(f"Connection error: {e}")
        finally:
            conn.close()

if __name__ == '__main__':
    start_server()

import socket

HOST = '10.9.65.55'  # Server IP
PORT = 65432         # Same port as server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Hello from client")
    data = s.recv(1024)
    print(f"Received: {data.decode()}")

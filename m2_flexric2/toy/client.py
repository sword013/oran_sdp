# client.py
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 40000))  # bind to specific port
sock.sendto(b"Hello from client", ("127.0.0.1", 50000))

data, addr = sock.recvfrom(1024)
print(f"Received from server: {data.decode()}")

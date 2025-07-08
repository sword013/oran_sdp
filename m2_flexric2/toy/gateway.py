# gateway.py
import socket
import ssl
import threading

SERVER_IP = '127.0.0.1'
SERVER_PORT = 36422

def handle_client(connstream):
    remote = socket.create_connection((SERVER_IP, SERVER_PORT))

    def forward(src, dst):
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)

    t1 = threading.Thread(target=forward, args=(connstream, remote))
    t2 = threading.Thread(target=forward, args=(remote, connstream))
    t1.start()
    t2.start()

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.load_verify_locations("ca.crt")
context.verify_mode = ssl.CERT_REQUIRED

bindsocket = socket.socket()
bindsocket.bind(('0.0.0.0', 4433))
bindsocket.listen(5)

while True:
    newsocket, fromaddr = bindsocket.accept()
    connstream = context.wrap_socket(newsocket, server_side=True)
    threading.Thread(target=handle_client, args=(connstream,)).start()

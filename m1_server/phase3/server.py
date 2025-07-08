# server.py
import socket
import time

SERVER_HOST = '10.9.65.55' # Or specific IP if on another machine
SERVER_PORT_SVC1 = 9999   # Example service 1
SERVER_PORT_SVC2 = 9998   # Example service 2 (run two instances for testing)
BUFFER_SIZE = 4096

def run_service(host, port, service_name="Service"):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[*] {service_name} listening on {host}:{port}")

    while True:
        conn, addr = server_socket.accept()
        print(f"[+] {service_name}: Accepted connection from {addr} (proxied by gateway)")
        try:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                print(f"[-] {service_name}: Client (via gateway) disconnected abruptly.")
                continue
            
            print(f"[+] {service_name}: Received: {data.decode()}")
            response = f"{service_name} processed: {data.decode()}"
            conn.sendall(response.encode())
            print(f"[+] {service_name}: Sent: {response}")
        except ConnectionResetError:
            print(f"[-] {service_name}: Connection reset by peer.")
        except Exception as e:
            print(f"[!] {service_name} Error: {e}")
        finally:
            conn.close()
            print(f"[-] {service_name}: Connection with {addr} closed")

if __name__ == "__main__":
    # For testing, you can run two server instances on different ports
    # In one terminal: python server.py 9999
    # In another terminal: python server.py 9998
    import sys
    if len(sys.argv) > 1:
        try:
            port_to_run = int(sys.argv[1])
            if port_to_run == SERVER_PORT_SVC1:
                 print(f"Starting Service 1 on port {SERVER_PORT_SVC1}")
                 run_service(SERVER_HOST, SERVER_PORT_SVC1, "Service1")
            elif port_to_run == SERVER_PORT_SVC2:
                 print(f"Starting Service 2 on port {SERVER_PORT_SVC2}")
                 run_service(SERVER_HOST, SERVER_PORT_SVC2, "Service2")
            else:
                print(f"Unknown port {port_to_run}. Running default Service1 on {SERVER_PORT_SVC1}")
                run_service(SERVER_HOST, SERVER_PORT_SVC1, "Service1")
        except ValueError:
            print("Invalid port number. Running default Service1.")
            run_service(SERVER_HOST, SERVER_PORT_SVC1, "Service1")
    else:
        print(f"No port specified. Running default Service1 on port {SERVER_PORT_SVC1}")
        print(f"Usage: python server.py <port_number_for_service>")
        run_service(SERVER_HOST, SERVER_PORT_SVC1, "Service1")



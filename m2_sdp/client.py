import socket

def run_client():
    # Create a TCP socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define server IP and port
    server_ip = "10.9.70.17"
    server_port = 12013

    # Establish a connection with the server
    client.connect((server_ip, server_port))
    print(f"Connected to {server_ip}:{server_port}")

    while True:
        # Send message to the server
        message = input("Type message (or 'close' to exit): ")
        client.send(message.encode("utf-8"))

        if message.lower() == "close":
            # Receive confirmation from the server and break the loop
            response = client.recv(1024).decode("utf-8")
            if response == "closed":
                break

        # Receive response from the server
        response = client.recv(1024).decode("utf-8")
        print(f"Received from server: {response}")

    # Close the socket
    client.close()
    print("Connection closed")

# Run the client
run_client()

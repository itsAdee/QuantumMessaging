import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import socket
from utilities.ccakem import kem_keygen1024, kem_encaps1024, kem_decaps1024
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from utilities.util import decode, encode
from Crypto.Hash import SHA512
from man_in_the_middle_attack.helpers import *
import threading
import argparse
import psutil

HOST = "localhost"
PORT = 65432  # Default port
SALT = b'f285df90eef0292d294e94f00ce3a69e'

def port_in_use(port):
    for conn in psutil.net_connections():
        if conn.laddr.port == port:
            return True
    return False

def handle_receive(conn, aes_key):
    while True:
        try:
            ciphertext = conn.recv(8096)
            if not ciphertext:
                break
            tag = conn.recv(16)
            nonce = conn.recv(16)

            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

            try:
                cipher.verify(tag)
                plaintext = plaintext.decode('utf-8')
                if plaintext == 'quit':
                    print("Connection closed by peer.")
                    break
                print("Received:", plaintext)
            except ValueError:
                print("Key incorrect or message corrupted.")
        except Exception as e:
            print(f"Receive error: {e}")
            break

def handle_send(conn, aes_key):
    while True:
        try:
            # Get user input for the message
            message = input("Enter message: ").encode("utf-8")
            check_file()

            # Encrypt the message and obtain the nonce and tag
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(message)
            check_logs(message)
            conn.sendall(ciphertext)
            conn.sendall(tag)
            conn.sendall(cipher.nonce)

            if message.decode('utf-8') == 'quit':
                print("Closing connection.")
                break
        except Exception as e:
            print(f"Send error: {e}")
            break
    conn.close()

def key_exchange(conn, role, priv, pub):
    if role == "send":
        conn.sendall(encode(pub))  # Send public key
        receiver_pub = decode(conn.recv(8096))  # Receive public key
        shared_secret, cipher = kem_encaps1024(receiver_pub)
        conn.sendall(encode(cipher))  # Send cipher
    else:
        sender_pub = decode(conn.recv(8096))  # Receive public key
        conn.sendall(encode(pub))  # Send public key
        cipher = decode(conn.recv(8096))  # Receive cipher
        shared_secret = kem_decaps1024(priv, cipher)

    return encode(shared_secret)

def main(role, port):
    s = None
    try:
        if role == "receive":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, port))
            s.listen()
            print(f"Waiting for a connection on port {port}...")
            conn, addr = s.accept()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, port))
            conn, addr = s, (HOST, port)

        print(f"Connected as {role} by", addr)

        priv, pub = kem_keygen1024()
        root_key = key_exchange(conn, role, priv, pub)
        aes_key = HKDF(root_key, 16, salt=SALT, hashmod=SHA512)

        if role == "send":
            # Start only the send thread for the "send" role
            send_thread = threading.Thread(target=handle_send, args=(conn, aes_key))
            send_thread.start()
            send_thread.join()
        elif role == "receive":
            # Start only the receive thread for the "receive" role
            receive_thread = threading.Thread(target=handle_receive, args=(conn, aes_key))
            receive_thread.start()
            receive_thread.join()

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if s:
            s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quantum Messaging Application')
    parser.add_argument('--role', choices=['send', 'receive'], required=True, help='Role: send or receive')
    parser.add_argument('--port', type=int, default=PORT, help='Port to connect to or bind to (default: 65432)')
    args = parser.parse_args()
    main(args.role, args.port)

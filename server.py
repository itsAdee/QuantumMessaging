import socket
from utilities.ccakem import kem_keygen1024, kem_encaps1024
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from utilities.util import decode, encode
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import threading
import argparse

HOST = "localhost"
PORT = 65432

def handle_receive(conn, aes_key):
    while True:
        try:
            # Receive encrypted message, tag, and nonce from the client
            ciphertext = conn.recv(8096)
            if not ciphertext:
                break
            tag = conn.recv(16)
            nonce = conn.recv(16)

            # Decrypt and verify the message
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

            try:
                cipher.verify(tag)
                plaintext = plaintext.decode('utf-8')
                if plaintext == 'quit':
                    break
                print("Client:", plaintext)
            except ValueError:
                print("Key incorrect or message corrupted")
        except:
            break

def handle_send(conn, aes_key):
    while True:
        try:
            # Send a message to the client
            response = input("Enter message: ").encode('utf-8')
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(response)
            conn.sendall(ciphertext)
            conn.sendall(tag)
            conn.sendall(cipher.nonce)

            if response.decode('utf-8') == 'quit':
                break
        except:
            break

def main(role):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        conn, addr = s.accept()

        with conn:
            print("Connected by", addr)

            priv, pub = kem_keygen1024()
            root_key = None  # Initialize root_key

            # Receive public key from client
            pub = conn.recv(8096)
            pub = decode(pub)

            # Encapsulate the key and send the cipher to the client
            shared_secret, cipher = kem_encaps1024(pub)
            cipher_bytes = encode(cipher)
            shared_secret = encode(shared_secret)
            conn.sendall(cipher_bytes)
            
            # Update root_key using the Double Ratchet Algorithm
            if root_key is None:
                root_key = shared_secret
            else:
                root_key = HKDF(root_key, 32, salt=shared_secret, hashmod=SHA512)

            # Derive AES key from root_key
            salt = get_random_bytes(16)
            aes_key = HKDF(root_key, 16, salt=salt, hashmod=SHA512)
            conn.send(salt)

            # Start threads for sending and receiving messages
            if role == 'send':
                send_thread = threading.Thread(target=handle_send, args=(conn, aes_key))
                send_thread.start()
                send_thread.join()
            else:
                receive_thread = threading.Thread(target=handle_receive, args=(conn, aes_key))
                receive_thread.start()
                receive_thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quantum Messaging Server')
    parser.add_argument('--role', choices=['send', 'receive'], default='send', help='Role of the server: send or receive')
    args = parser.parse_args()
    main(args.role)

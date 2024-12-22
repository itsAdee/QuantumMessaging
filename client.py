from utilities.ccakem import kem_keygen1024, kem_decaps1024
import socket
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from utilities.util import decode, encode
from Crypto.Hash import SHA512
import threading
import argparse

HOST = "localhost"
PORT = 65432

def handle_receive(s, aes_key):
    while True:
        try:
            # Receive encrypted message, tag, and nonce from the server
            ciphertext = s.recv(8096)
            if not ciphertext:
                break
            tag = s.recv(16)
            nonce = s.recv(16)

            # Decrypt and verify the message
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

            try:
                cipher.verify(tag)
                plaintext = plaintext.decode('utf-8')
                if plaintext == 'quit':
                    break
                print("Server:", plaintext)
            except ValueError:
                print("Key incorrect or message corrupted")
        except:
            break

def handle_send(s, aes_key):
    while True:
        try:
            # Get user input for the message
            message = input("Enter message: ").encode("utf-8")

            # Encrypt the message and obtain the nonce and tag
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(message)

            # Send the encrypted message, nonce, and tag to the server
            s.sendall(ciphertext)
            s.sendall(tag)
            s.sendall(cipher.nonce)

            if message.decode('utf-8') == 'quit':
                break
        except:
            break

def main(role):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        priv, pub = kem_keygen1024()
        root_key = None  # Initialize root_key

        # Key Generation
        pub_bytes = encode(pub)
        # Send the public key as bytes
        s.sendall(pub_bytes)

        # Receive the encapsulated key from the server
        cipher = s.recv(8096)
        cipher = decode(cipher)

        # Decapsulate the key
        shared_secret = kem_decaps1024(priv, cipher)
        shared_secret = encode(shared_secret)

        if root_key is None:
            # If it's the first iteration, set the root_key
            root_key = shared_secret
        else:
            # Update root_key using the Double Ratchet Algorithm
            root_key = HKDF(root_key, 32, salt=shared_secret, hashmod=SHA512)

        # Derive AES key from root_key
        salt = s.recv(16)
        aes_key = HKDF(root_key, 16, salt=salt, hashmod=SHA512)

        if role == 'receive':
            # Start thread for receiving messages
            receive_thread = threading.Thread(target=handle_receive, args=(s, aes_key))
            receive_thread.start()
            receive_thread.join()
        else:
            # Start thread for sending messages
            send_thread = threading.Thread(target=handle_send, args=(s, aes_key))
            send_thread.start()
            send_thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Quantum Messaging Client')
    parser.add_argument('--role', choices=['send', 'receive'], default='receive', help='Role of the client: send or receive')
    args = parser.parse_args()
    main(args.role)
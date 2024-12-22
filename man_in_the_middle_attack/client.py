import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


import socket
from utilities.ccakem import kem_keygen1024, kem_decaps1024
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from utilities.util import decode, encode
from Crypto.Hash import SHA512



HOST = "localhost"
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    priv, pub = kem_keygen1024()
    root_key = None  # Initialize root_key

    while True:
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

        cipher = AES.new(aes_key, AES.MODE_EAX)

        # Encrypt the message and obtain the nonce and tag
        nonce = cipher.nonce
        # Get user input for the message
        message = input("Enter message: ")
        message = message.encode("utf-8")

        ciphertext, tag = cipher.encrypt_and_digest(message)

        # Send the encrypted message, nonce, and tag to the server
        s.sendall(ciphertext)
        s.sendall(tag)
        s.sendall(nonce)

       
        if message.decode('utf-8') == 'quit':
            break
       
        # Generate seed for next iteration (Double Ratchet)
        seed = HKDF(shared_secret, 32, salt=b"DoubleRatchetSeed", hashmod=SHA512)

        # Update private and public keys using the new seed
        priv, pub = kem_keygen1024(seed)
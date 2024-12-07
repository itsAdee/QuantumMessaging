import socket
from ccakem import *
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from util import decode, encode
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

HOST = "localhost"
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    conn, addr = s.accept()

    with conn:
        print("Connected by", addr)

        priv, pub = kem_keygen1024()
        root_key = None  # Initialize root_key

        while True:
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

            # Receive encrypted message, tag, and nonce from the client
            ciphertext = conn.recv(8096)
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
                print(ciphertext)
                print("Decrypted Text:", plaintext)
            except ValueError:
                print("Key incorrect or message corrupted")

            # Generate seed for next iteration (Double Ratchet)
            seed = HKDF(shared_secret, 32, salt=b"DoubleRatchetSeed", hashmod=SHA512)

            # Update private and public keys using the new seed
            priv, pub = kem_keygen1024(seed)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext, tag

def brute_force_attack(nonce, ciphertext, tag, known_key_part):
    attempts = 0
    start_time = time.time()
    
    for key_part1 in range(256):  # 1 byte key space
        for key_part2 in range(256):  # 1 byte key space
            for key_part3 in range(256):  # 1 byte key space
                for key_part4 in range(256):  # 1 byte key space
                    for key_part5 in range(256):  # 1 byte key space
                        for key_part6 in range(256):  # 1 byte key space
                            for key_part7 in range(256):  # 1 byte key space
                                for key_part8 in range(256):  # 1 byte key space
                                    for key_part9 in range(256):  # 1 byte key space
                                        for key_part10 in range(256):  # 1 byte key space
                                            for key_part11 in range(256):  # 1 byte key space
                                                attempts += 1
                                                aes_key = bytes([key_part1, key_part2, key_part3, key_part4, key_part5, key_part6, key_part7, key_part8, key_part9, key_part10, key_part11]) + known_key_part
                                                try:
                                                    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                                                    plaintext = cipher.decrypt(ciphertext)
                                                    cipher.verify(tag)
                                                    end_time = time.time()
                                                    print(f"Key found: {aes_key}")
                                                    print(f"Decrypted message: {plaintext.decode('utf-8')}")
                                                    print(f"Attempts taken: {attempts}")
                                                    print(f"Time taken: {end_time - start_time} seconds")
                                                    return
                                                except (ValueError, KeyError):
                                                    continue

    print("Key not found")

if __name__ == "__main__":
    # Generate a random 16-byte key
    key = get_random_bytes(16)
    print(f"Original key: {key}")

    # Encrypt a message
    message = "This is a secret message"
    nonce, ciphertext, tag = encrypt_message(key, message)
    print(f"Ciphertext: {ciphertext}")

    # Known part of the key (last 5 bytes)
    known_key_part = key[-5:]

    # Attempt to brute force the first 11 bytes of the key
    brute_force_attack(nonce, ciphertext, tag, known_key_part)
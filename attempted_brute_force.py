from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import itertools

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext, tag

def brute_force_attack(nonce, ciphertext, tag, known_key_part):
    attempts = 0
    start_time = time.time()

    # Define the key space for the unknown part of the key (first 11 bytes)
    key_space = range(256)  # Each byte has 256 possible values

    # Generate all possible combinations of the unknown key parts
    for unknown_key in itertools.product(key_space, repeat=11):
        attempts += 1
        aes_key = bytes(unknown_key) + known_key_part
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
    end_time = time.time()
    print(f"Total attempts: {attempts}")
    print(f"Total time taken: {end_time - start_time} seconds")

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

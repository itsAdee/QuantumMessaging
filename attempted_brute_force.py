from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time
import itertools
import argparse

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext, tag

def brute_force_attack(nonce, ciphertext, tag, known_key_part, known_bytes_count):
    attempts = 0
    start_time = time.time()

    # Define the key space for the unknown part of the key
    key_space = range(256)  # Each byte has 256 possible values

    # Generate all possible combinations of the unknown key parts
    for unknown_key in itertools.product(key_space, repeat=(16 - known_bytes_count)):
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
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Brute-force AES key attack')
    parser.add_argument('--known_bytes', type=int, default=5, help='Number of known bytes of the key (default: 5)')
    args = parser.parse_args()

    if args.known_bytes < 1 or args.known_bytes > 15:
        print("Error: The number of known bytes must be between 1 and 15.")
    else:
        # Generate a random 16-byte key
        key = get_random_bytes(16)
        print(f"Original key: {key}")

        # Encrypt a message
        message = "This is a secret message"
        nonce, ciphertext, tag = encrypt_message(key, message)
        print(f"Ciphertext: {ciphertext}")

        # Known part of the key
        known_key_part = key[-args.known_bytes:]

        # Attempt to brute force the unknown part of the key
        brute_force_attack(nonce, ciphertext, tag, known_key_part, args.known_bytes)

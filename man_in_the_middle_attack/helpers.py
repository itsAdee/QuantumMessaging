import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from Crypto.Cipher import AES

def decode_utf8(data):
    return data.decode('utf-8')


def encode_utf8(data):
    return data.encode('utf-8')


def check_file():
    message_path = "..//utilities//message.txt"
    if not os.path.exists(message_path):
        os.makedirs(os.path.dirname(message_path), exist_ok=True)
        with open(message_path, "wb") as f:
            f.write(b"")  # Write empty bytes


def check_logs(message):
    message_path = "..//utilities//message.txt"
    with open(message_path, "wb") as f:
        f.write(message)


def parse_logs():
    message_path = "..//utilities//message.txt"
    with open(message_path, "rb") as f:
        message = f.read()
    check_logs(b"")
    return message


def verify_message(tag,nonce,cipher_text,aes_key):
    cipher_text.verify(tag)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
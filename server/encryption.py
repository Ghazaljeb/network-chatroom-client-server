import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64


def hash_password(password: str) -> bytes:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed


def verify_password(password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def generate_aes_key():
    return os.urandom(32)


def encrypt_message(message, key):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(message) % 16)
    padded_message = message + (chr(pad_len) * pad_len)

    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


def decrypt_message(encrypted_message, key):
    encrypted_data = base64.b64decode(encrypted_message)

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = ord(decrypted_padded_message[-1:])
    return decrypted_padded_message[:-pad_len].decode()





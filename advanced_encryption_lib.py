import os
import tempfile
from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from hashlib import sha256

class Encryptor:
    def __init__(self, password: str):
        self.key = sha256(password.encode()).digest()

    def encrypt_aes(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def decrypt_aes(self, data: bytes) -> bytes:
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def encrypt_blowfish(self, data: bytes) -> bytes:
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        plen = 8 - len(data) % 8
        padding = bytes([plen]) * plen
        return cipher.encrypt(data + padding)

    def decrypt_blowfish(self, data: bytes) -> bytes:
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        decrypted = cipher.decrypt(data)
        plen = decrypted[-1]
        return decrypted[:-plen]

    def write_temp_file(self, data: bytes, filename: str) -> str:
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        with open(temp_path, 'wb') as f:
            f.write(data)
        return temp_path

    def load_temp_file(self, filename: str) -> bytes:
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        with open(temp_path, 'rb') as f:
            return f.read()

    def store_in_memory(self, data: bytes) -> bytes:
        return data

def encrypt(message: str, password: str, method: str = "AES") -> bytes:
    enc = Encryptor(password)
    data = message.encode()
    if method.upper() == "AES":
        ciphertext = enc.encrypt_aes(data)
    elif method.upper() == "BLOWFISH":
        ciphertext = enc.encrypt_blowfish(data)
    else:
        raise ValueError("Unsupported encryption method")

    enc.write_temp_file(ciphertext, "encrypted_data.bin")
    enc.store_in_memory(ciphertext)
    return ciphertext

def decrypt(ciphertext: bytes, password: str, method: str = "AES") -> str:
    enc = Encryptor(password)
    if method.upper() == "AES":
        plaintext = enc.decrypt_aes(ciphertext)
    elif method.upper() == "BLOWFISH":
        plaintext = enc.decrypt_blowfish(ciphertext)
    else:
        raise ValueError("Unsupported decryption method")

    enc.write_temp_file(ciphertext, "decrypted_data.bin")
    enc.store_in_memory(plaintext)
    return plaintext.decode()

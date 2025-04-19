import os
from Crypto.Cipher import AES, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import Twofish
from Crypto.Random import get_random_bytes
from hashlib import sha256

class Encryptor:
    def __init__(self, password: str):
        self.key = sha256(password.encode()).digest()
        self.rsa_key = RSA.generate(2048)
        self.rsa_cipher = PKCS1_OAEP.new(self.rsa_key)

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

    def encrypt_twofish(self, data: bytes) -> bytes:
        cipher = Twofish.new(self.key)
        plen = 16 - len(data) % 16
        padding = bytes([plen]) * plen
        return cipher.encrypt(data + padding)

    def decrypt_twofish(self, data: bytes) -> bytes:
        cipher = Twofish.new(self.key)
        decrypted = cipher.decrypt(data)
        plen = decrypted[-1]
        return decrypted[:-plen]

    def encrypt_rsa(self, data: bytes) -> bytes:
        return self.rsa_cipher.encrypt(data)

    def decrypt_rsa(self, data: bytes) -> bytes:
        return self.rsa_cipher.decrypt(data)

    def caesar_cipher(self, data: str, shift: int = 5) -> str:
        result = []
        for char in data:
            if char.isalpha():
                shift_base = 65 if char.isupper() else 97
                result.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
            else:
                result.append(char)
        return ''.join(result)

    def to_lower_case(self, data: str) -> str:
        return data.lower()

    def replace_numbers(self, data: str) -> str:
        symbols = ['#', '$', '%', '&']
        result = []
        for char in data:
            if char.isdigit():
                num = int(char)
                symbol = symbols[num % len(symbols)]
                result.append(symbol * num)
            else:
                result.append(char)
        return ''.join(result)

def encrypt(message: str, password: str) -> str:
    enc = Encryptor(password)
    data = message.encode()
    
    # Layered encryption
    aes_encrypted = enc.encrypt_aes(data)
    rsa_encrypted = enc.encrypt_rsa(aes_encrypted)
    blowfish_encrypted = enc.encrypt_blowfish(rsa_encrypted)
    twofish_encrypted = enc.encrypt_twofish(blowfish_encrypted)

    # Caesar Cipher
    shifted = enc.caesar_cipher(twofish_encrypted.decode('latin-1', errors='ignore'), 5)

    # Lowercase
    lowered = enc.to_lower_case(shifted)

    # Replace numbers
    final = enc.replace_numbers(lowered)

    with open("message.aesy", "w", encoding="utf-8") as f:
        f.write(password + "\n" + final)

    return final

def decrypt(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    password = lines[0].strip()
    ciphertext = ''.join(lines[1:])

    enc = Encryptor(password)

    # Reverse order
    ciphertext = enc.caesar_cipher(ciphertext.upper(), -5)
    ciphertext_bytes = ciphertext.encode('latin-1')

    decrypted_twofish = enc.decrypt_twofish(ciphertext_bytes)
    decrypted_blowfish = enc.decrypt_blowfish(decrypted_twofish)
    decrypted_rsa = enc.decrypt_rsa(decrypted_blowfish)
    decrypted_aes = enc.decrypt_aes(decrypted_rsa)

    return decrypted_aes.decode()

def aesy_encrypt(password: str, text: str) -> str:
    return encrypt(text, password)

def aesy_decrypt(filepath: str) -> str:
    return decrypt(filepath)

import os
from Crypto.Cipher import AES, Blowfish
from hashlib import sha256
import base64

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
        result = []
        for char in data:
            if char.isdigit():
                num = int(char)
                result.append('#' * num)  # Replace the digit with '#' repeated 'num' times
            else:
                result.append(char)
        return ''.join(result)

    def save_to_file(self, filename: str, message: str, password: str):
        with open(filename, 'w') as file:
            file.write(f"Message: {message}\nPassword: {password}\n")

    def read_from_file(self, filename: str) -> tuple:
        with open(filename, 'r') as file:
            lines = file.readlines()
            message = lines[0].strip().split(": ")[1]
            password = lines[1].strip().split(": ")[1]
        return message, password

def aesy_encrypt(password: str, message: str, filename: str = "message.aesy"):
    enc = Encryptor(password)

    # 1. AES encryption
    data = message.encode()
    ciphertext_aes = enc.encrypt_aes(data)

    # 2. Blowfish encryption (input is the AES ciphertext)
    ciphertext_blowfish = enc.encrypt_blowfish(ciphertext_aes)

    # 3. 5 times Caesar cipher shift (input is the Blowfish ciphertext as bytes, so decode it first)
    encrypted_message = enc.caesar_cipher(ciphertext_blowfish.decode('latin-1', errors='ignore'), 5)

    # 4. Convert to lowercase
    encrypted_message = enc.to_lower_case(encrypted_message)

    # 5. Replace numbers with #
    encrypted_message = enc.replace_numbers(encrypted_message)

    # Kaydet
    enc.save_to_file(filename, encrypted_message, password)

    print(f"Şifreli Metin Kaydedildi: {filename}")

def aesy_decrypt(filename: str) -> str:
    enc = Encryptor(password=None)  # Parola dosyadan alınacak

    # Dosyadan mesaj ve parola oku
    saved_message, saved_password = enc.read_from_file(filename)
    
    # Şifreyi çözmek için dosyadaki parola kullanılarak işlemler yapılacak
    enc = Encryptor(saved_password)

    # Reverse number replacement (this step is tricky as '#' doesn't directly map back to a number.
    #    We'll assume the original numbers were single digits for simplicity of reversal.)
    #    For now, we'll skip the exact reversal of this step.

    # 2. Reverse lowercasing
    ciphertext_upper = saved_message.upper()

    # 3. Reverse Caesar cipher
    decrypted_caesar = enc.caesar_cipher(ciphertext_upper, -5)

    # 4. Reverse Blowfish decryption (input needs to be bytes)
    try:
        decrypted_blowfish = enc.decrypt_blowfish(decrypted_caesar.encode('latin-1'))
    except ValueError as e:
        print(f"Blowfish decryption error: {e}")
        return "Decryption error"

    # 5. Reverse AES decryption
    try:
        plaintext = enc.decrypt_aes(decrypted_blowfish)
        return plaintext.decode()
    except ValueError as e:
        print(f"AES decryption error: {e}")
        return "Decryption error"

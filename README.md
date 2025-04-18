# 🔐 Advanced Encryption System

> ⚠️ **Not AES (Advanced Encryption Standard)** in name — but yes, it uses **AES** and **Blowfish** under the hood!

---

## 📚 About

**Advanced-Encryption-System** is a custom encryption framework that uses real cryptographic algorithms like **AES** and **Blowfish** to securely encrypt and decrypt messages.

Unlike a hash, this encryption is **reversible** — with the correct password and settings, you can get back the original message. It’s designed for learning, experimenting, and implementing strong encryption in your own projects.

---

## 🔧 Features

- 🔁 Fully reversible (encrypt → decrypt)
- 💻 GUI
- 🧪 Python library integration

---

## 🧠 How It Works

1. You provide a message and how many times that you want to the message to be encrypt(on low-end pcs max 5 or 7 or app will crash).
2. The system uses AES, Blowfish and Characther Shifting to encrypt the message.
4. You get a encrypted string.
5. To decrypt, the same password and generation number must be used.

---

## 🧪 Example Usage

### Python (Simple Demo)

```python
from advanced_encryption import encrypt, decrypt

# Encrypt the message
ciphertext = encrypt("This is a secret message", password="MyStrongPassword!", method="AES")
print("Encrypted:", ciphertext)

# Decrypt the message
plaintext = decrypt(ciphertext, password="MyStrongPassword!", method="AES")
print("Decrypted:", plaintext)

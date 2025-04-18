# 🔐 Advanced Encryption System

> ⚠️ **Not AES (Advanced Encryption Standard)** in name — but yes, it uses **AES** and **Blowfish** under the hood!

---

## 📚 About

**Advanced-Encryption-System** is a custom encryption framework that uses real cryptographic algorithms like **AES** and **Blowfish** to securely encrypt and decrypt messages.

Unlike a hash, this encryption is **reversible** — with the correct password and settings, you can get back the original message. It’s designed for learning, experimenting, and implementing strong encryption in your own projects.

---

## 🔧 Features

- 🔐 Supports **AES (256-bit)** and **Blowfish** encryption
- 🔁 Fully reversible (encrypt → decrypt)
- 🧂 Random salt generation for added security
- 🔑 Password-based encryption (PBE)
- 📄 Optional file encryption support
- 💻 CLI interface for terminal use
- 🧪 Easy Python API for integration

---

## 🧠 How It Works

1. You provide a message and a password.
2. The system uses your chosen method (AES or Blowfish) to encrypt the message.
3. A random salt (optional) and key derivation are applied to secure the password.
4. You get a base64-encoded encrypted string.
5. To decrypt, the same password and method must be used.

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

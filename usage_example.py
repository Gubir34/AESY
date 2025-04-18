import advanced_encryption_lib

# Get password and message from user
password = "my_strong_password"
message = "Secret 123 Message!"

# Encryption
advanced_encryption_lib.aesy_encrypt(password, message)

# Decryption
decrypted_message = advanced_encryption_lib.aesy_decrypt('message.aesy')
print(f"Unencrypted message: {decrypted_message}")

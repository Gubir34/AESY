# Example usage:

# Create AESY encryption object with predefined password (no input allowed)
aes = AESY()

# Encrypt the message
encrypted_message = aes.encrypt("Secret 123 Message!")

# Print the encrypted message with seed
print(f"Encrypted message with seed: {encrypted_message}")

# Decrypt the message
decrypted_message = aes.decrypt(encrypted_message)
print(f"Decrypted message: {decrypted_message}")

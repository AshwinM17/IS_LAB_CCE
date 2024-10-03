def encrypt(message, n, e):
    """Encrypt the message using RSA."""
    encrypted_message = []
    for char in message:
        # Convert character to ASCII, encrypt and store the ciphertext
        ciphertext = pow(ord(char), e, n)
        encrypted_message.append(ciphertext)
    return encrypted_message

def decrypt(encrypted_message, n, d):
    """Decrypt the message using RSA."""
    decrypted_message = ''
    for cipher in encrypted_message:
        # Decrypt the ciphertext to get ASCII value
        plaintext = pow(cipher, d, n)
        decrypted_message += chr(plaintext)  # Convert ASCII back to character
    return decrypted_message

# RSA parameters
n = 323
e = 5
d = 173

# Message to encrypt
message = "Cryptographic Protocols"

# Encrypt the message
encrypted_message = encrypt(message, n, e)
print("Encrypted message (ciphertext):", encrypted_message)

# Decrypt the ciphertext
decrypted_message = decrypt(encrypted_message, n, d)
print("Decrypted message:", decrypted_message)

# Check if the decrypted message matches the original message
assert decrypted_message == message, "Decryption did not yield the original message!"
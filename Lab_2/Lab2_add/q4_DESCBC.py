from Crypto.Cipher import DES  # Import DES cipher from PyCryptodome
from Crypto.Util.Padding import pad, unpad  # Import padding functions for handling block sizes
import binascii  # Import binascii for hexadecimal conversions

# Message to be encrypted
message = "Secure Communication".encode()  # Convert the message string to bytes for encryption

# DES key (must be 8 bytes)
key = b"A1B2C3D4"  # Define a key for DES encryption (must be exactly 8 bytes)

# Initialization vector (must be 8 bytes for DES)
iv = b"12345678"  # Define an initialization vector (IV) for CBC mode (must also be 8 bytes)

# Create DES cipher in CBC mode
cipher = DES.new(key, DES.MODE_CBC, iv)  # Initialize DES cipher with the key, mode, and IV

# Encrypt the message (pad the message to make its length a multiple of the block size)
ciphertext = cipher.encrypt(pad(message, DES.block_size))  # Pad the message and encrypt it

# Display the ciphertext in hex format
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())  # Print the encrypted message in hexadecimal

# Decrypt the ciphertext to retrieve the original message
cipher_dec = DES.new(key, DES.MODE_CBC, iv)  # Initialize a new DES cipher for decryption with the same key and IV
decrypted_message = unpad(cipher_dec.decrypt(ciphertext), DES.block_size)  # Decrypt and unpad the ciphertext

# Display the decrypted message
print("Decrypted Message:", decrypted_message.decode())  # Print the original message after decryption
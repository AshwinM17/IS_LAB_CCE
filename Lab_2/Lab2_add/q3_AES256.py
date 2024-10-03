from Crypto.Cipher import AES  # Import AES cipher from PyCryptodome
from Crypto.Util.Padding import pad, unpad  # Import padding functions for handling block sizes
import binascii  # Import binascii for hexadecimal conversions

# Message to be encrypted
message = "Encryption Strength".encode()  # Convert the message string to bytes for encryption

# AES-256 key (must be 32 bytes for AES-256)
# The key is defined in hexadecimal format and then converted to bytes
key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

# Initialize AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)  # Create a new AES cipher object with the specified key and mode

# Encrypt the message (pad the message to match the block size)
ciphertext = cipher.encrypt(pad(message, AES.block_size))  # Pad the message and encrypt it

# Display the ciphertext in hex format
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())  # Print the encrypted message in hexadecimal

# Decrypt the ciphertext to retrieve the original message
decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt and unpad the ciphertext

# Display the decrypted message
print("Decrypted Message:", decrypted_message.decode())  # Print the original message after decryption
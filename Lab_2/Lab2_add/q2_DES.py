from Crypto.Cipher import DES  # Import DES cipher from PyCryptodome
from Crypto.Util.Padding import pad, unpad  # Import padding functions for handling block sizes
from binascii import unhexlify, hexlify  # Import functions for hex to bytes conversion

# Hex-encoded blocks of data to be encrypted
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"  # First block (hex)
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"  # Second block (hex)

# Convert hex-encoded strings to bytes using unhexlify
block1 = unhexlify(block1_hex)  # Convert first block from hex to bytes
block2 = unhexlify(block2_hex)  # Convert second block from hex to bytes

# Define DES key (must be 8 bytes long)
key = b"A1B2C3D4"  # The key used for encryption and decryption

# Create a DES cipher object in ECB mode
cipher = DES.new(key, DES.MODE_ECB)  # Initialize DES cipher with the specified key and mode

# Encrypt both blocks (padding to match the block size if necessary)
ciphertext_block1 = cipher.encrypt(pad(block1, DES.block_size))  # Encrypt the first block
ciphertext_block2 = cipher.encrypt(pad(block2, DES.block_size))  # Encrypt the second block

# Display the ciphertext in hex format
print("Ciphertext Block 1 (hex):", hexlify(ciphertext_block1).decode())  # Print ciphertext of block 1
print("Ciphertext Block 2 (hex):", hexlify(ciphertext_block2).decode())  # Print ciphertext of block 2

# Decrypt the ciphertext back to plaintext
decrypted_block1 = unpad(cipher.decrypt(ciphertext_block1), DES.block_size)  # Decrypt and unpad block 1
decrypted_block2 = unpad(cipher.decrypt(ciphertext_block2), DES.block_size)  # Decrypt and unpad block 2

# Display the decrypted plaintext
print("Decrypted Block 1 (plaintext):", decrypted_block1.decode())  # Print decrypted block 1
print("Decrypted Block 2 (plaintext):", decrypted_block2.decode())  # Print decrypted block 2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

BLOCK_SIZE = 16  # AES block size in bytes

def aes_192_encrypt(msg, key):
    """
    Encrypts a message using AES-192 in ECB mode.

    :param msg: The plaintext message to encrypt.
    :param key: The encryption key (must be 24 bytes for AES-192).
    :return: The ciphertext.
    """
    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher object in ECB mode
    padded_msg = pad(msg.encode('utf-8'), BLOCK_SIZE)  # Pad the message to block size
    ciphertext = cipher.encrypt(padded_msg)  # Encrypt the padded message
    return ciphertext  # Return the ciphertext

def aes_192_decrypt(ciphertext, key):
    """
    Decrypts a ciphertext using AES-192 in ECB mode.

    :param ciphertext: The ciphertext to decrypt.
    :param key: The decryption key (must be 24 bytes for AES-192).
    :return: The decrypted plaintext message.
    """
    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher object in ECB mode
    padded_plaintext = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    plaintext = unpad(padded_plaintext, BLOCK_SIZE).decode('utf-8')  # Unpad the plaintext
    return plaintext  # Return the plaintext

# Define a hex key and convert it to bytes
key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
key = binascii.unhexlify(key_hex)  # Convert hex key to bytes

# Check if the key length is appropriate for AES-192 (24 bytes)
if len(key) != 24:
    raise ValueError("Key must be 192 bits (24 bytes) long.")

message = "Top Secret Data"  # Message to encrypt

# Encrypt the message
ciphertext = aes_192_encrypt(message, key)
print(f'Ciphertext (hex): {ciphertext.hex()}')  # Print the ciphertext in hex format

# Decrypt the message
plaintext = aes_192_decrypt(ciphertext, key)
print(f'Plaintext: {plaintext}')  # Print the decrypted plaintext
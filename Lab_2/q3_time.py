import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

def encrypt_aes_256(key, plaintext):
    """
    Encrypts the plaintext using AES-256 in CBC mode with PKCS7 padding.

    :param key: A 32-byte key for AES-256.
    :param plaintext: The plaintext message to be encrypted.
    :return: The ciphertext.
    """
    # Add PKCS7 padding to ensure the plaintext is a multiple of the block size (128 bits = 16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Use an Initialization Vector (IV) of 16 bytes (AES block size); here it's set to all zeros (for simplicity)
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

def decrypt_aes_256(key, ciphertext):
    """
    Decrypts the given AES-256 ciphertext in CBC mode with PKCS7 padding.

    :param key: A 32-byte key for AES-256.
    :param ciphertext: The ciphertext to be decrypted.
    :return: The decrypted plaintext message.
    """
    # Create an AES cipher object in CBC mode using the same key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove the PKCS7 padding to get the original plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')

def encrypt_des(key, plaintext):
    """
    Encrypts the plaintext using DES in CBC mode with PKCS7 padding.

    :param key: A 8-byte key for DES.
    :param plaintext: The plaintext message to be encrypted.
    :return: The ciphertext.
    """
    # Add padding to the plaintext to ensure it fits the block size for DES
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    
    # Create a DES cipher object in CBC mode using the key and a zero IV
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00' * 8)
    
    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext

def decrypt_des(key, ciphertext):
    """
    Decrypts the given DES ciphertext in CBC mode.

    :param key: A 8-byte key for DES.
    :param ciphertext: The ciphertext to be decrypted.
    :return: The decrypted plaintext message.
    """
    # Create a DES cipher object in CBC mode using the same key and IV
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00' * 8)
    
    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Remove the padding to get the original plaintext
    plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
    
    return plaintext


# Example usage
aes_key = b'0123456789ABCDEF0123456789ABCDEF'  # 32 bytes for AES-256
des_key = b'01234567'  # 8 bytes for DES
plaintext = 'Performance Testing of Encryption Algorithms.'

# Timing AES-256
start_time = time.time()
aes_ciphertext = encrypt_aes_256(aes_key, plaintext)
aes_encryption_time = time.time() - start_time

start_time = time.time()
aes_decrypted_message = decrypt_aes_256(aes_key, aes_ciphertext)
aes_decryption_time = time.time() - start_time

# Timing DES
start_time = time.time()
des_ciphertext = encrypt_des(des_key, plaintext)
des_encryption_time = time.time() - start_time

start_time = time.time()
des_decrypted_message = decrypt_des(des_key, des_ciphertext)
des_decryption_time = time.time() - start_time

# Print out the time taken for encryption and decryption
print(f"AES-256 Encryption Time: {aes_encryption_time:.8f} seconds")
print(f"AES-256 Decryption Time: {aes_decryption_time:.6f} seconds")
print(f"DES Encryption Time: {des_encryption_time:.6f} seconds")
print(f"DES Decryption Time: {des_decryption_time:.6f} seconds")

# Ensure that the decryption matches the original plaintext
assert plaintext == aes_decrypted_message, "AES-256 Decryption failed"
assert plaintext == des_decrypted_message, "DES Decryption failed"
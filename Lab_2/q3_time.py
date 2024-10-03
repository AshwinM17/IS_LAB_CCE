import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

def encrypt_aes_256(key, plaintext):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_aes_256(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')

def encrypt_des(key, plaintext):
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00' * 8)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_des(key, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv=b'\x00' * 8)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
    return plaintext

aes_key = b'0123456789ABCDEF0123456789ABCDEF'
des_key = b'01234567'
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

print(f"AES-256 Encryption Time: {aes_encryption_time:.6f} seconds")
print(f"AES-256 Decryption Time: {aes_decryption_time:.6f} seconds")
print(f"DES Encryption Time: {des_encryption_time:.6f} seconds")
print(f"DES Decryption Time: {des_decryption_time:.6f} seconds")

assert plaintext == aes_decrypted_message, "AES-256 Decryption failed"
assert plaintext == des_decrypted_message, "DES Decryption failed"
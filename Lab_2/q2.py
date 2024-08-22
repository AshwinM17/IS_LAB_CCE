#cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import binascii

def encrypt_aes_128(key_hex, plaintext):
    key = binascii.unhexlify(key_hex)
    plaintext_bytes = plaintext.encode('utf-8')
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes_128(key_hex, ciphertext):
    key = binascii.unhexlify(key_hex)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode('utf-8')

key_hex = '0123456789ABCDEF0123456789ABCDEF'
plaintext = 'Sensitive Information'

ciphertext = encrypt_aes_128(key_hex, plaintext)
print(f'Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}')

decrypted_message = decrypt_aes_128(key_hex, ciphertext)
print(f'Decrypted message: {decrypted_message}')

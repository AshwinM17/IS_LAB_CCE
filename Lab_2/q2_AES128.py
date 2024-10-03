from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import binascii
'''
Note:
here we are putting 1st 16 bytes as IV so to avoid that return IV in encryption and send IV in decryption
'''


def encrypt_aes_128(key_hex, plaintext):
    """
    Encrypts the plaintext using AES-128 in CBC mode with PKCS7 padding.

    :param key_hex: A 32-character hexadecimal string (16 bytes) as the key.
    :param plaintext: The plaintext message to be encrypted.
    :return: The ciphertext (IV + encrypted message).
    """
    # Convert the key from hexadecimal to bytes
    key = binascii.unhexlify(key_hex)
    
    # Convert the plaintext string into bytes
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Add PKCS7 padding to ensure the plaintext is a multiple of the block size (128 bits = 16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()
    
    # Use an Initialization Vector (IV) of 16 bytes (AES block size); here it's set to all zeros (for simplicity)
    #alternative iv=get_random_bytes(16)
    iv = b'\x00' * 16
    
    # Create an AES cipher object in CBC mode using the key and the IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    '''
    modes.ECB,CFB(iv),OFB(iv),CTR(iv) for different modes
    '''

    encryptor = cipher.encryptor()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Return the IV followed by the ciphertext
    return iv + ciphertext


def decrypt_aes_128(key_hex, ciphertext):
    """
    Decrypts the given AES-128 ciphertext in CBC mode with PKCS7 padding.

    :param key_hex: A 32-character hexadecimal string (16 bytes) as the key.
    :param ciphertext: The ciphertext (IV + encrypted message).
    :return: The decrypted plaintext message.
    """
    # Convert the key from hexadecimal to bytes
    key = binascii.unhexlify(key_hex)
    
    # Extract the Initialization Vector (IV) from the first 16 bytes of the ciphertext
    iv = ciphertext[:16]
    
    # Extract the actual ciphertext (the remaining part after the IV)
    ciphertext = ciphertext[16:]
    
    # Create an AES cipher object in CBC mode using the same key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove the PKCS7 padding to get the original plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    # Return the plaintext message decoded into a string
    return plaintext.decode('utf-8')


# Example usage
key_hex = '0123456789ABCDEF0123456789ABCDEF'  # 128-bit AES key in hexadecimal form (32 hex digits = 16 bytes)
plaintext = 'Sensitive Information'  # The plaintext message to encrypt

# Encrypt the message
ciphertext = encrypt_aes_128(key_hex, plaintext)
print(f'Ciphertext (hex): {binascii.hexlify(ciphertext).decode()}')

# Decrypt the message back to plaintext
decrypted_message = decrypt_aes_128(key_hex, ciphertext)
print(f'Decrypted message: {decrypted_message}')
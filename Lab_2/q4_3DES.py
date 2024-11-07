from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

def encrypt(msg, iv):
    """
    Encrypts the message using Triple DES in CBC mode.

    :param msg: The plaintext message to encrypt.bytes
    :param iv: Initialization vector for CBC mode.bytes
    :return: A tuple containing the IV and the ciphertext. cipher text is in bytes format
    """
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)  # Create a new DES3 cipher object
    padded_msg = pad(msg.encode('utf-8'), DES3.block_size)  # Pad the message
    ciphertext = cipher.encrypt(padded_msg)  # Encrypt the padded message
    return iv, ciphertext  # Return the IV and ciphertext

def decrypt(iv, ciphertext):
    """
    Decrypts the ciphertext using Triple DES in CBC mode.

    :param iv: The initialization vector used for encryption.byte
    :param ciphertext: The ciphertext to decrypt.byte
    :return: The decrypted plaintext message or False if unpadding fails.string
    """
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)  # Create a new DES3 cipher object
    padded_plaintext = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    try:
        plaintext = unpad(padded_plaintext, DES3.block_size).decode('utf-8')  # Unpad the plaintext
        return plaintext  # Return the plaintext
    except ValueError:
        return False  # Return False if unpadding fails (wrong padding)

# Define a hex key and convert it to bytes
key_hex = "1234567890ABCDEFAAFFFFFFFFFFFFFF1234567890ABCDEF"
key = binascii.unhexlify(key_hex)  # Convert hex key to bytes

message = "Classified Text"  # Message to encrypt
fixed_iv = b'01234567'  # Fixed IV (not recommended for production)

# Encrypt the message
iv, ciphertext = encrypt(message, fixed_iv)
print(f'Ciphertext (hex): {ciphertext.hex()}')  # Print the ciphertext in hex format

# Decrypt the message
plaintext = decrypt(iv, ciphertext)
print(f'Plaintext: {plaintext}')  # Print the decrypted plaintextfrom Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

def encrypt(msg, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_msg = pad(msg.encode('utf-8'), DES3.block_size)
    ciphertext = cipher.encrypt(padded_msg)
    return iv, ciphertext

def decrypt(iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext = unpad(padded_plaintext, DES3.block_size).decode('utf-8')
        return plaintext
    except ValueError:
        return False

key_hex = "1234567890ABCDEFAAFFFFFFFFFFFFFF1234567890ABCDEF"
key = binascii.unhexlify(key_hex)
message = "Classified Text"
fixed_iv = b'01234567' 

iv, ciphertext = encrypt(message, fixed_iv)
print(ciphertext)
print(f'Ciphertext (hex): {ciphertext.hex()}')
plaintext = decrypt(iv, ciphertext)
print(f'Plaintext: {plaintext}')

from Crypto.Cipher import DES  # Import the DES algorithm
from Crypto.Util.Padding import pad, unpad  # Utility functions to pad and unpad data for block ciphers
import binascii  # For encoding the encrypted bytes into a readable hex format

def des_encrypt(message: str, key: str) -> str:
    """
    Encrypts the given message using DES encryption with the provided key.

    :param message: The plaintext message to be encrypted.
    :param key: The encryption key (must be 8 bytes long).ie 64 bits
    :return: The encrypted message in hex format.()
    """
    # Convert the key into bytes
    key_bytes = key.encode('utf-8')
    
    # Ensure that the key is exactly 8 bytes long (DES requires a key of 8 bytes)
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long")
    
    # Create a new DES cipher object in ECB mode
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    '''
    iv = get_random_bytes(8)  # IV for modes requiring it
    nonce = get_random_bytes(8)  # Nonce for CTR mode

    cipher_cbc = DES.new(key_bytes, DES.MODE_CBC, iv)
    cipher_cfb = DES.new(key_bytes, DES.MODE_CFB, iv)
    cipher_ofb = DES.new(key_bytes, DES.MODE_OFB, iv)
    cipher_ctr = DES.new(key_bytes, DES.MODE_CTR, nonce=nonce)
        '''
    
    # Pad the message to make its length a multiple of the block size (8 bytes for DES)
    padded_message = pad(message.encode('utf-8'), DES.block_size)
    
    # Encrypt the padded message
    encrypted_bytes = cipher.encrypt(padded_message)
    
    # Convert the encrypted bytes to a hexadecimal string for readability
    return binascii.hexlify(encrypted_bytes).decode('utf-8')


def des_decrypt(encrypted_message: str, key: str) -> str:
    """
    Decrypts the given encrypted message using DES decryption with the provided key.

    :param encrypted_message: The ciphertext in hex format to be decrypted.
    :param key: The decryption key (must be 8 bytes long).
    :return: The decrypted plaintext message.
    """
    # Convert the key into bytes
    key_bytes = key.encode('utf-8')
    
    # Ensure that the key is exactly 8 bytes long
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long")
    
    # Create a new DES cipher object in ECB mode
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    
    # Convert the hexadecimal encrypted message back into bytes
    encrypted_bytes = binascii.unhexlify(encrypted_message)
    
    # Decrypt the encrypted bytes
    padded_message = cipher.decrypt(encrypted_bytes)
    
    # Unpad the decrypted message to remove any padding added during encryption
    message = unpad(padded_message, DES.block_size)
    
    # Convert the decrypted message back into a string and return it
    return message.decode('utf-8')


# Example usage
key = 'A1B2C3D4'  # Key must be exactly 8 bytes long
message = 'Confidential Data'  # The message to encrypt

# Encrypt the message
encrypted_message = des_encrypt(message, key)
print(f"Encrypted Message: {encrypted_message}")

# Decrypt the message back to plaintext
decrypted_message = des_decrypt(encrypted_message, key)
print(f"Decrypted Message: {decrypted_message}")
#pycryptodome library

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

def des_encrypt(message: str, key: str) -> str:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long")
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    padded_message = pad(message.encode('utf-8'), DES.block_size)
    encrypted_bytes = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_bytes).decode('utf-8')

def des_decrypt(encrypted_message: str, key: str) -> str:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long")
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    encrypted_bytes = binascii.unhexlify(encrypted_message)
    padded_message = cipher.decrypt(encrypted_bytes)
    message = unpad(padded_message, DES.block_size)
    return message.decode('utf-8')

key = 'A1B2C3D4'
message = 'Confidential Data'

encrypted_message = des_encrypt(message, key)
print(f"Encrypted Message: {encrypted_message}")

decrypted_message = des_decrypt(encrypted_message, key)
print(f"Decrypted Message: {decrypted_message}")
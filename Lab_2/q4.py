from Crypto.Cipher import DES3
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
print(f'Ciphertext (hex): {ciphertext.hex()}')
plaintext = decrypt(iv, ciphertext)
print(f'Plaintext: {plaintext}')
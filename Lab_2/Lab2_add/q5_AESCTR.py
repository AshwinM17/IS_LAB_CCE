from Crypto.Cipher import AES  # Import AES cipher from PyCryptodome
from Crypto.Util import Counter  # Import Counter for CTR mode
import binascii  # Import binascii for hexadecimal conversions

# Message to be encrypted
message = "Cryptography Lab Exercise".encode()  # Convert the message string to bytes for encryption

# AES-128 key (must be 16 bytes for AES-128)
key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF")  # Define a 32-byte key for AES-128 (hexadecimal to bytes)

# Nonce (8 bytes for the CTR mode)
nonce = b"00000000"  # Define a nonce (initialization vector) for CTR mode, must be unique but not secret

# Create a counter object with the nonce
ctr = Counter.new(64, prefix=nonce)  # Initialize the counter with a 64-bit value, using the nonce as a prefix

# Create AES cipher in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)  # Initialize the AES cipher with the key and counter

# Encrypt the message
ciphertext = cipher.encrypt(message)  # Encrypt the plaintext message

# Display the ciphertext in hex format
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())  # Print the encrypted message in hexadecimal format

# Decrypt the ciphertext to retrieve the original message
# Create the counter object again for decryption with the same nonce
ctr_dec = Counter.new(64, prefix=nonce)  # Initialize a new counter for decryption, using the same nonce
cipher_dec = AES.new(key, AES.MODE_CTR, counter=ctr_dec)  # Initialize the AES cipher for decryption
decrypted_message = cipher_dec.decrypt(ciphertext)  # Decrypt the ciphertext to get the original message

# Display the decrypted message
print("Decrypted Message:", decrypted_message.decode())  # Print the original message after decryption
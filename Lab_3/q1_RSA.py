from Crypto.PublicKey import RSA  # Import RSA key generation from PyCryptodome
from Crypto.Cipher import PKCS1_OAEP  # Import the PKCS#1 OAEP cipher for RSA
import binascii  # Import binascii for hexadecimal conversions

# Generate a new RSA key pair with a key size of 2048 bits
key = RSA.generate(2048)  # Create a new RSA key object

# Extract the components of the key
n = key.n  # The modulus
e = key.e  # The public exponent
d = key.d  # The private exponent

# Get the public key for encryption
public_key = key.publickey()  # Extract the public key from the key object
private_key = key  # Store the private key for later decryption

# Print the key components
print(f"n={n}")  # Print the modulus
print(f"e={e}")  # Print the public exponent
print(f"d={d}")  # Print the private exponent

# Message to be encrypted
message = "Asymmetric Encryption"  # Define the plaintext message to encrypt

# Encrypt the message using the public key

# Initialize the cipher for encryption with the public key
cipher_encrypt = PKCS1_OAEP.new(public_key) 

# Encrypt the message (convert to bytes)
ciphertext = cipher_encrypt.encrypt(message.encode())  #.encode() converts the message to bytes

# Print the encrypted message in hexadecimal format
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())  


# Decrypt the ciphertext using the private key

# Initialize the cipher for decryption with the private key
cipher_decrypt = PKCS1_OAEP.new(private_key)  

# Decrypt the ciphertext to get the original message
decrypted_message = cipher_decrypt.decrypt(ciphertext)  

# Display the decrypted message
print("Decrypted message:", decrypted_message.decode())  # Print the original message after decryption
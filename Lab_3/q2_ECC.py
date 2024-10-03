from Crypto.PublicKey import ECC  # Import ECC key generation from PyCryptodome
from Crypto.Cipher import AES  # Import AES for symmetric encryption
from Crypto.Hash import SHA256  # Import SHA256 hash function
from Crypto.Protocol.KDF import HKDF  # Import HKDF for key derivation
import random  # Import random for fixed random number generation

# Seed for reproducibility
random.seed(42)

# Fixed random number generator for deterministic behavior
def fixed_rng(seed, length):
    random.seed(seed)  # Set the seed for the random number generator
    return bytes(random.getrandbits(8) for _ in range(length))  # Generate 'length' random bytes

# Generate ECC private key using the fixed RNG for determinism
private_key = ECC.generate(curve='P-256', randfunc=lambda n: fixed_rng(42, n))  # Create ECC private key
public_key = private_key.public_key()  # Get the corresponding public key

# Function to encrypt a message using the recipient's public key
def encrypt_message(public_key, message):
    # Generate an ephemeral private key for the encryption session
    ephemeral_private_key = ECC.generate(curve='P-256', randfunc=lambda n: fixed_rng(123, n))
    ephemeral_public_key = ephemeral_private_key.public_key()  # Get the corresponding public key

    # Compute the shared secret using the recipient's public key
    shared_secret = ephemeral_private_key.d * public_key.pointQ  # ECDH operation
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')  # Convert shared secret to bytes

    # Derive a symmetric key from the shared secret using HKDF
    derived_key = HKDF(master=shared_secret_bytes, key_len=32, salt=None, hashmod=SHA256)  # Key derivation

    # Generate a random initialization vector (IV) for AES GCM
    iv = fixed_rng(999, 16)  # IV length should be 16 bytes for AES GCM

    # Initialize AES cipher in GCM mode with the derived key and IV
    cipher_aes = AES.new(derived_key, AES.MODE_GCM, iv)

    # Encrypt the message and generate the authentication tag
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)  # Encrypt the message
    return ephemeral_public_key, iv, ciphertext, tag  # Return ephemeral public key, IV, ciphertext, and tag

# Function to decrypt a message using the recipient's private key
def decrypt_message(private_key, ephemeral_public_key, iv, ciphertext, tag):
    # Compute the shared secret using the ephemeral public key
    shared_secret = private_key.d * ephemeral_public_key.pointQ  # ECDH operation
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')  # Convert shared secret to bytes

    # Derive the symmetric key from the shared secret using HKDF
    derived_key = HKDF(master=shared_secret_bytes, key_len=32, salt=None, hashmod=SHA256)  # Key derivation

    # Initialize AES cipher in GCM mode for decryption with the derived key and IV
    cipher_aes = AES.new(derived_key, AES.MODE_GCM, iv)

    # Decrypt the ciphertext and verify the authenticity using the tag
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify
    return decrypted_message  # Return the decrypted message

# Message to be encrypted
message = b"Secure Transactions"  # Define the plaintext message to encrypt

# Encrypt the message using the public key
ephemeral_public_key, iv, ciphertext, tag = encrypt_message(public_key, message)  # Encrypt the message
print("Ciphertext (in hex):", ciphertext.hex())  # Print the encrypted message in hexadecimal format

# Decrypt the ciphertext using the private key
decrypted_message = decrypt_message(private_key, ephemeral_public_key, iv, ciphertext, tag)  # Decrypt the message

# Display the decrypted message
print("Decrypted message:", decrypted_message.decode())  # Print the original message after decryption
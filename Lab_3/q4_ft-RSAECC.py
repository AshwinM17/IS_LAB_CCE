from Crypto.PublicKey import RSA, ECC  # Import RSA and ECC for asymmetric key generation
from Crypto.Cipher import PKCS1_OAEP, AES  # Import PKCS1_OAEP for RSA encryption/decryption and AES for symmetric encryption
from Crypto.Signature import DSS  # Import DSS for signing with ECC
from Crypto.Hash import SHA256  # Import SHA256 for hashing keys
from Crypto.Random import get_random_bytes  # Import random bytes generator
from Crypto.Util.Padding import pad, unpad  # Import padding utilities for AES
import time  # Import time for measuring performance

# Measure RSA key generation time
start_time = time.time()  # Start timer
rsa_key = RSA.generate(2048)  # Generate a new RSA key of 2048 bits
rsa_key_generation_time = time.time() - start_time  # Calculate key generation time
rsa_public_key = rsa_key.publickey()  # Extract the public key from the generated RSA key

# Measure ECC key generation time
start_time = time.time()  # Start timer
ecc_key = ECC.generate(curve='P-256')  # Generate a new ECC key using the P-256 curve
ecc_key_generation_time = time.time() - start_time  # Calculate key generation time
ecc_public_key = ecc_key.public_key()  # Extract the public key from the generated ECC key

# Print key generation times for RSA and ECC
print(f"RSA Key Generation Time: {rsa_key_generation_time:.4f} seconds")
print(f"ECC Key Generation Time: {ecc_key_generation_time:.4f} seconds")

# Prepare file data for encryption (1 MB of data)
file_data = b'A' * 1024 * 1024  # Simulate a file by creating 1 MB of data filled with 'A'

# Generate a random AES key for symmetric encryption
aes_key = get_random_bytes(16)  # Generate a random 16-byte AES key (128 bits)
rsa_cipher = PKCS1_OAEP.new(rsa_public_key)  # Initialize RSA cipher for encryption with the public key

# Measure RSA encryption time
start_time = time.time()  # Start timer
rsa_encrypted_key = rsa_cipher.encrypt(aes_key)  # Encrypt the AES key using RSA
rsa_encryption_time = time.time() - start_time  # Calculate encryption time

# Initialize RSA cipher for decryption with the private key
rsa_cipher = PKCS1_OAEP.new(rsa_key)  # Initialize RSA cipher for decryption
# Measure RSA decryption time
start_time = time.time()  # Start timer
rsa_decrypted_key = rsa_cipher.decrypt(rsa_encrypted_key)  # Decrypt the AES key using RSA
rsa_decryption_time = time.time() - start_time  # Calculate decryption time

# Print encryption and decryption times for RSA
print(f"RSA Encryption Time: {rsa_encryption_time:.4f} seconds")
print(f"RSA Decryption Time: {rsa_decryption_time:.4f} seconds")

# Hash the AES key for signing with ECC
aes_key_hash = SHA256.new(aes_key)  # Create a SHA256 hash of the AES key
signer = DSS.new(ecc_key, 'fips-186-3')  # Initialize the signer using the ECC private key

# Measure ECC signature generation time
start_time = time.time()  # Start timer
ecc_signature = signer.sign(aes_key_hash)  # Sign the hash of the AES key with ECC
ecc_encryption_time = time.time() - start_time  # Calculate signature generation time

# Initialize the verifier for ECC
verifier = DSS.new(ecc_public_key, 'fips-186-3')  # Initialize verifier using the ECC public key
ecc_key_hash = SHA256.new(aes_key)  # Create a SHA256 hash of the AES key for verification

# Measure ECC signature verification time
start_time = time.time()  # Start timer
try:
    # Attempt to verify the signature
    verifier.verify(ecc_key_hash, ecc_signature)  # Verify the signature against the hashed AES key
    ecc_decryption_time = time.time() - start_time  # Calculate verification time
    print("ECC Decryption successful: Key verified")  # Print success message if verification passes
except ValueError:
    ecc_decryption_time = time.time() - start_time  # Calculate verification time in case of failure
    print("ECC Decryption failed: Invalid signature")  # Print failure message if verification fails

# Print encryption and decryption times for ECC
print(f"ECC Encryption Time: {ecc_encryption_time:.4f} seconds")
print(f"ECC Decryption Time: {ecc_decryption_time:.4f} seconds")

# Initialize AES cipher for file encryption
cipher = AES.new(aes_key, AES.MODE_CBC)  # Create a new AES cipher in CBC mode
# Measure file encryption time
start_time = time.time()  # Start timer
encrypted_file_data = cipher.encrypt(pad(file_data, AES.block_size))  # Encrypt the file data with padding
file_encryption_time = time.time() - start_time  # Calculate encryption time

# Initialize AES cipher for file decryption using the same IV
cipher = AES.new(aes_key, AES.MODE_CBC, cipher.iv)  # Create a new AES cipher for decryption
# Measure file decryption time
start_time = time.time()  # Start timer
decrypted_file_data = unpad(cipher.decrypt(encrypted_file_data), AES.block_size)  # Decrypt and unpad the file data
file_decryption_time = time.time() - start_time  # Calculate decryption time

# Print encryption and decryption times for file data
print(f"File Encryption Time: {file_encryption_time:.4f} seconds")
print(f"File Decryption Time: {file_decryption_time:.4f} seconds")
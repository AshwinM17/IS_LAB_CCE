import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes, random
from Crypto.Util.Padding import pad, unpad
import os
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

# Function to generate ElGamal keys
def elg_generate_keys(bits=2048):
    start_time = time.time()  # Start time for key generation
    p = getPrime(bits)  # Generate a prime number p
    g = random.randint(2, p-1)  # Choose a random generator g
    x = random.randint(2, p-2)  # Generate a private key x
    h = pow(g, x, p)  # Compute public key component h
    t = time.time() - start_time  # Calculate time taken for key generation
    return (p, g, h), x, t  # Return public key, private key, and time taken

# Function to encrypt a message using ElGamal
def elgamal_encrypt(public_key, file_path):
    p, g, h = public_key  # Unpack public key
    k = random.randint(2, p-2)  # Random value k for encryption
    c1 = pow(g, k, p)  # First part of ciphertext
    with open(file_path, "rb") as f:
        message = f.read()  # Read the message from the file
    m = bytes_to_long(message)  # Convert message to long integer
    c2 = (m * pow(h, k, p)) % p  # Second part of ciphertext
    return c1, c2  # Return the ciphertext parts

# Function to decrypt a message using ElGamal
def elgamal_decrypt(private_key, public_key, c1, c2):
    p = public_key[0]  # Extract prime p from public key
    x = private_key  # Private key
    s = pow(c1, x, p)  # Compute shared secret
    s_inv = inverse(s, p)  # Compute modular inverse of shared secret
    m = (c2 * s_inv) % p  # Recover original message
    return long_to_bytes(m)  # Convert long back to bytes

# Function to generate RSA and ECC keys
def generate_keys():
    start = time.time()  # Start time for RSA key generation
    rsa_key = RSA.generate(2048)  # Generate 2048-bit RSA key pair
    rsa_key_gen_time = time.time() - start  # Calculate time taken for RSA key generation
    # Generate ECC key using the P-256 curve (NIST secp256r1)
    start = time.time()
    ecc_key = ECC.generate(curve="P-256")
    ecc_key_gen_time = time.time() - start  # Calculate time taken for ECC key generation
    
    return rsa_key, ecc_key, rsa_key_gen_time, ecc_key_gen_time  # Return keys and generation times

# Function to encrypt and decrypt a file using RSA
def rsa_encrypt_decrypt(file_path, rsa_key):
    start = time.time()  # Start time for RSA encryption
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())  # Initialize RSA cipher for public key
    aes_key = get_random_bytes(16)  # Generate a random AES session key
    with open(file_path, "rb") as f:
        plaintext = f.read()  # Read the plaintext from the file
    enc_session_key = cipher_rsa.encrypt(aes_key)  # Encrypt the AES key with RSA
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)  # Initialize AES cipher
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))  # Encrypt the message
    rsa_encryption_time = time.time() - start  # Calculate time taken for RSA encryption

    start = time.time()  # Start time for RSA decryption
    cipher_rsa = PKCS1_OAEP.new(rsa_key)  # Initialize RSA cipher for private key
    aes_key = cipher_rsa.decrypt(enc_session_key)  # Decrypt the AES key with RSA
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)  # Initialize AES with the stored nonce
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)  # Decrypt the message
    rsa_decryption_time = time.time() - start  # Calculate time taken for RSA decryption

    return rsa_encryption_time, rsa_decryption_time  # Return encryption and decryption times

# Function to encrypt and decrypt a file using ECC
def ecc_encrypt_decrypt(file_path, ecc_key):
    start = time.time()  # Start time for ECC encryption
    aes_key = get_random_bytes(16)  # Generate a random AES session key
    with open(file_path, "rb") as f:
        plaintext = f.read()  # Read the plaintext from the file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)  # Initialize AES cipher
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))  # Encrypt the message
    ecc_encryption_time = time.time() - start  # Calculate time taken for ECC encryption

    # Store nonce for decryption
    nonce = cipher_aes.nonce

    start = time.time()  # Start time for ECC decryption
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)  # Initialize AES with the stored nonce
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)  # Decrypt the message
    ecc_decryption_time = time.time() - start  # Calculate time taken for ECC decryption

    return ecc_encryption_time, ecc_decryption_time  # Return encryption and decryption times

# Function to measure performance for a given file size
def measure_performance(file_size_mb):
    file_path = f"test_file_{file_size_mb}MB.bin"  # File path for the test file
    with open(file_path, "wb") as f:
        f.write(os.urandom(file_size_mb * 1024 * 1024))  # Create a test file with random bytes

    # Generate RSA and ECC keys
    rsa_key, ecc_key, rsa_key_gen_time, ecc_key_gen_time = generate_keys()
    rsa_enc_time, rsa_dec_time = rsa_encrypt_decrypt(file_path, rsa_key)  # Measure RSA encryption/decryption time
    ecc_enc_time, ecc_dec_time = ecc_encrypt_decrypt(file_path, ecc_key)  # Measure ECC encryption/decryption time
    
    # Generate ElGamal keys
    sender_public_key, sender_private_key, elg_key_gen_t1 = elg_generate_keys(bits=2048)
    receiver_public_key, receiver_private_key, elg_key_gen_t2 = elg_generate_keys(bits=2048)
    elg_key_gen_time = elg_key_gen_t2 + elg_key_gen_t1  # Total time for ElGamal key generation

    # Measure ElGamal encryption time
    start_time = time.time()
    ciphertext = elgamal_encrypt(receiver_public_key, file_path)  # Encrypt the test file
    elg_encryption_time = time.time() - start_time

    # Measure ElGamal decryption time
    start_time = time.time()
    decrypted_message = elgamal_decrypt(receiver_private_key, receiver_public_key, *ciphertext)  # Decrypt the ciphertext
    elg_decryption_time = time.time() - start_time
    
    os.remove(file_path)  # Clean up test file after measurement

    # Print the results
    print(f"File Size: {file_size_mb} MB")
    print(f"RSA Key Generation Time: {rsa_key_gen_time:.6f} s")
    print(f"ECC Key Generation Time: {ecc_key_gen_time:.12f} s")
    print(f"ElGamal Key Generation Time: {elg_key_gen_time:.6f} s")
    print(f"RSA Encryption Time: {rsa_enc_time:.8f} s, Decryption Time: {rsa_dec_time:.8f} s")
    print(f"ECC Encryption Time: {ecc_enc_time:.8f} s, Decryption Time: {ecc_dec_time:.8f} s\n")
    print(f"ElGamal Encryption Time: {elg_encryption_time:.8f} s, Decryption Time: {elg_decryption_time:.8f} s\n")

# Test with different file sizes
measure_performance(1)  # 1 MB
#measure_performance(10)  # 10 MB
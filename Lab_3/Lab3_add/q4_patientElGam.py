import time
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes, random

# Function to generate ElGamal public and private keys
def elg_generate_keys(bits=2048):
    p = getPrime(bits)  # Generate a large prime number p
    g = random.randint(2, p-1)  # Random generator g in the range [2, p-1]
    x = random.randint(2, p-2)  # Choose a random private key x in the range [2, p-2]
    h = pow(g, x, p)  # Compute the public key component h as g^x mod p
    return (p, g, h), x  # Return the public key (p, g, h) and private key x

# Function to encrypt a message using ElGamal encryption
def elgamal_encrypt(public_key, message):
    p, g, h = public_key  # Unpack the public key components (p, g, h)
    k = random.randint(2, p-2)  # Choose a random integer k for encryption
    c1 = pow(g, k, p)  # Compute the first part of the ciphertext c1 = g^k mod p
    m = bytes_to_long(message)  # Convert the message from bytes to a long integer
    c2 = (m * pow(h, k, p)) % p  # Compute the second part of the ciphertext c2 = m * h^k mod p
    return c1, c2  # Return the ciphertext as a tuple (c1, c2)

# Function to decrypt the ciphertext using ElGamal decryption
def elgamal_decrypt(private_key, public_key, c1, c2):
    p = public_key[0]  # Extract the prime number p from the public key
    x = private_key  # Use the private key x
    s = pow(c1, x, p)  # Compute the shared secret s = c1^x mod p
    s_inv = inverse(s, p)  # Compute the modular inverse of the shared secret
    m = (c2 * s_inv) % p  # Recover the original message as m = (c2 * s_inv) mod p
    return long_to_bytes(m)  # Convert the long integer back to bytes (original message)

# Key generation for both sender and receiver
sender_public_key, sender_private_key = elg_generate_keys(bits=2048)  # Generate sender's key pair
receiver_public_key, receiver_private_key = elg_generate_keys(bits=2048)  # Generate receiver's key pair

# Define different sizes of patient records data (in bytes)
sizes = [32, 64, 128, 256, 512, 1024]  # List of different data sizes for testing

# Iterate through each data size to measure encryption and decryption times
for size in sizes:
    # Generate random patient data of the specified size
    message = get_random_bytes(size)

    # Measure encryption time
    start_time = time.time()  # Record start time before encryption
    ciphertext = elgamal_encrypt(receiver_public_key, message)  # Encrypt the message
    encryption_time = time.time() - start_time  # Calculate encryption time

    # Measure decryption time
    start_time = time.time()  # Record start time before decryption
    decrypted_message = elgamal_decrypt(receiver_private_key, receiver_public_key, *ciphertext)  # Decrypt the ciphertext
    decryption_time = time.time() - start_time  # Calculate decryption time

    # Display the results for the current data size
    print(f"Size: {size} bytes")
    print(f"Ciphertext: (c1={ciphertext[0]}, c2={ciphertext[1]})")  # Show the ciphertext (c1, c2)
    print(f"Decrypted message: {decrypted_message}")  # Show the decrypted message
    print(f"Encryption time: {encryption_time:.6f} seconds")  # Show encryption time in seconds
    print(f"Decryption time: {decryption_time:.6f} seconds")  # Show decryption time in seconds
    print("----------")  # Separator for readability between tests
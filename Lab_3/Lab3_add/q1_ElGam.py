# NOT WORKING IDK WHY

from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes  # Import necessary functions for number theory
from Crypto.Random import random  # Import random for secure random number generation

# Function to encrypt a message using the ElGamal encryption scheme
def elgamal_encrypt(public_key, message):
    p, g, h = public_key  # Unpack the public key
    # Choose a random integer k in the range [2, p-2]
    k = random.randint(2, p-2)  
    # Compute c1 as g^k mod p
    c1 = pow(g, k, p)  
    # Convert the message from bytes to a long integer
    m = bytes_to_long(message)
    # Compute c2 as (m * h^k) mod p
    c2 = (m * pow(h, k, p)) % p  
    return c1, c2  # Return the ciphertext (c1, c2)

# Function to decrypt the ciphertext using the ElGamal decryption scheme
def elgamal_decrypt(private_key, p, c1, c2):
    x = private_key  # Use the private key x
    # Compute the shared secret s as c1^x mod p
    s = pow(c1, x, p) 
    # Compute the modular inverse of s
    s_inv = inverse(s, p) 
    # Recover the original message m as (c2 * s_inv) mod p
    m = (c2 * s_inv) % p 
    return long_to_bytes(m)  # Convert the long integer back to bytes

# Given ElGamal public key and private key
p = 7919
g = 2
h = 6465
public_key = (p, g, h)
private_key = 2999

# Define the message to be encrypted
message = b"Asymmetric Algorithms"

# Encrypt the message using the public key
ciphertext = elgamal_encrypt(public_key, message)
print("Ciphertext:", ciphertext)  # Display the ciphertext

# Decrypt the ciphertext using the private key
decrypted_message = elgamal_decrypt(private_key, p, ciphertext[0], ciphertext[1])

print("Decrypted message:", decrypted_message.decode())  # Display the original message after decryption
import random
from sympy import isprime, mod_inverse

# Helper function to generate a large prime number
def generate_large_prime(bits=256):
    """
    Generate a random large prime number.
    
    Args:
        bits (int): The number of bits for the prime number.
        
    Returns:
        int: A large prime number.
    """
    while True:
        prime_candidate = random.getrandbits(bits)  # Generate a random number with specified bits
        if isprime(prime_candidate):  # Check if the candidate is prime
            return prime_candidate  # Return the prime candidate if it is prime

# ElGamal Key Generation
def elgamal_keygen(bits=256):
    """
    Generate ElGamal public and private keys.
    
    Args:
        bits (int): The number of bits for the prime number.
        
    Returns:
        tuple: A tuple containing the public key (p, g, y) and private key x.
    """
    p = generate_large_prime(bits)  # Generate a large prime number p
    g = random.randint(2, p - 1)  # Choose a random generator g
    x = random.randint(1, p - 2)  # Generate a private key x
    y = pow(g, x, p)  # Compute public key component y = g^x mod p
    return (p, g, y), x  # Return public and private keys

# ElGamal Encryption
def elgamal_encrypt(plain_text, public_key):
    """
    Encrypt a plaintext message using the ElGamal encryption scheme.
    
    Args:
        plain_text (int): The plaintext message to encrypt.
        public_key (tuple): The public key (p, g, y).
        
    Returns:
        tuple: The ciphertext as (c1, c2).
    """
    p, g, y = public_key  # Unpack the public key
    k = random.randint(1, p - 2)  # Choose a random integer k for encryption
    c1 = pow(g, k, p)  # Compute c1 = g^k mod p
    c2 = (plain_text * pow(y, k, p)) % p  # Compute c2 = (plain_text * y^k) mod p
    return c1, c2  # Return the ciphertext

# ElGamal Decryption
def elgamal_decrypt(cipher_text, private_key, p):
    """
    Decrypt a ciphertext using the ElGamal decryption scheme.
    
    Args:
        cipher_text (tuple): The ciphertext (c1, c2) to decrypt.
        private_key (int): The private key x.
        p (int): The prime number p used in key generation.
        
    Returns:
        int: The decrypted plaintext message.
    """
    c1, c2 = cipher_text  # Unpack the ciphertext
    s = pow(c1, private_key, p)  # Compute shared secret s = c1^x mod p
    s_inv = mod_inverse(s, p)  # Compute the modular inverse of s
    plain_text = (c2 * s_inv) % p  # Decrypt the message
    return plain_text  # Return the decrypted plaintext

# Example usage:
public_key, private_key = elgamal_keygen()  # Generate public and private keys
message = 12345  # Simple message, convert larger messages into integers
cipher_text = elgamal_encrypt(message, public_key)  # Encrypt the message
decrypted_message = elgamal_decrypt(cipher_text, private_key, public_key[0])  # Decrypt the message

# Display results
print("Original message:", message)  # Print the original message
print("Encrypted message:", cipher_text)  # Print the encrypted message
print("Decrypted message:", decrypted_message)  # Print the decrypted message
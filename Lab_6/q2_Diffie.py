import random
from sympy import isprime

# Generate a large prime number
def generate_large_prime(bits=256):
    """
    Generate a random large prime number.
    
    Args:
        bits (int): The number of bits for the prime number.
        
    Returns:
        int: A large prime number.
    """
    while True:
        prime_candidate = random.getrandbits(bits)  # Generate a random candidate with specified bits
        if isprime(prime_candidate):  # Check if the candidate is prime
            return prime_candidate  # Return the prime candidate if it is prime

# Diffie-Hellman Key Exchange
def dh_keygen(bits=256):
    """
    Generate Diffie-Hellman public and private keys and compute shared secrets.
    
    Args:
        bits (int): The number of bits for the prime number p.
        
    Returns:
        tuple: A tuple containing public values (p, g, A, B) and shared secrets for Alice and Bob.
    """
    p = generate_large_prime(bits)  # Generate a large prime number p
    g = random.randint(2, p - 2)  # Choose a random generator g (primitive root modulo p)

    # Generate private keys for Alice and Bob
    a = random.randint(1, p - 2)  # Private key for Alice
    b = random.randint(1, p - 2)  # Private key for Bob

    # Compute public keys for Alice and Bob
    A = pow(g, a, p)  # Public key for Alice: A = g^a mod p
    B = pow(g, b, p)  # Public key for Bob: B = g^b mod p

    # Calculate shared secret keys
    shared_secret_Alice = pow(B, a, p)  # Alice computes the shared secret using Bob's public key
    shared_secret_Bob = pow(A, b, p)  # Bob computes the shared secret using Alice's public key

    return (p, g, A, B), (shared_secret_Alice, shared_secret_Bob)  # Return public values and shared secrets

# Example usage:
(p, g, A, B), (shared_secret_Alice, shared_secret_Bob) = dh_keygen()  # Generate keys and shared secrets

# Display the results
print("Public values (p, g, A, B):", p, g, A, B)  # Print the public values
print("Shared secret for Alice:", shared_secret_Alice)  # Print Alice's shared secret
print("Shared secret for Bob:", shared_secret_Bob)  # Print Bob's shared secret
print("Do shared secrets match?", shared_secret_Alice == shared_secret_Bob)  # Check if shared secrets match
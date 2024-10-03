import hashlib
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

# Schnorr Key Generation
def schnorr_keygen(p_bits=256):
    """
    Generate Schnorr public and private keys.
    
    Args:
        p_bits (int): The number of bits for the prime number p.
        
    Returns:
        tuple: A tuple containing the public key (p, q, g, y) and private key x.
    """
    p = generate_large_prime(p_bits)  # Generate a large prime number p
    q = (p - 1) // 2  # Calculate a safe prime q
    g = random.randint(2, p - 1)  # Choose a random generator g
    x = random.randint(1, q)  # Generate a private key x
    y = pow(g, x, p)  # Compute public key component y = g^x mod p
    return (p, q, g, y), x  # Return public and private keys

# Schnorr Sign
def schnorr_sign(message, private_key, p, q, g):
    """
    Sign a message using the Schnorr signature scheme.
    
    Args:
        message (str): The message to sign.
        private_key (int): The private key x.
        p (int): The large prime number p.
        q (int): The safe prime q.
        g (int): The generator g.
        
    Returns:
        tuple: The signature as (r, s).
    """
    k = random.randint(1, q)  # Choose a random integer k
    r = pow(g, k, p)  # Compute r = g^k mod p
    # Hash the concatenation of r and message to produce e
    h = hashlib.sha256(f"{r}{message}".encode()).hexdigest()  
    e = int(h, 16) % q  # Convert hash to integer and reduce modulo q
    s = (k + e * private_key) % q  # Compute s = (k + e * x) mod q
    return r, s  # Return the signature

# Schnorr Verify
def schnorr_verify(message, signature, public_key):
    """
    Verify a Schnorr signature.
    
    Args:
        message (str): The signed message.
        signature (tuple): The signature (r, s).
        public_key (tuple): The public key (p, q, g, y).
        
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    r, s = signature  # Unpack the signature
    p, q, g, y = public_key  # Unpack the public key
    # Hash the concatenation of r and message to produce e
    h = hashlib.sha256(f"{r}{message}".encode()).hexdigest()  
    e = int(h, 16) % q  # Convert hash to integer and reduce modulo q
    v1 = pow(g, s, p)  # Compute v1 = g^s mod p
    v2 = (r * pow(y, e, p)) % p  # Compute v2 = r * y^e mod p
    return v1 == v2  # Verify the signature

# Example usage:
public_key, private_key = schnorr_keygen()  # Generate public and private keys
message = "Hello, Schnorr!"  # Define a message to sign
signature = schnorr_sign(message, private_key, public_key[0], public_key[1], public_key[2])  # Sign the message
is_valid = schnorr_verify(message, signature, public_key)  # Verify the signature

# Display results
print("Message:", message)  # Print the message
print("Signature:", signature)  # Print the generated signature
print("Signature valid:", is_valid)  # Print whether the signature is valid
import hashlib
import random
from sympy import isprime, mod_inverse

# Helper function to generate a large prime number
def generate_large_prime(bits=256):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

# Schnorr Key Generation
def schnorr_keygen(p_bits=256):
    p = generate_large_prime(p_bits)
    q = (p - 1) // 2  # Safe prime
    g = random.randint(2, p - 1)
    x = random.randint(1, q)  # Private key
    y = pow(g, x, p)  # Public key
    return (p, q, g, y), x  # Public and private keys

# Schnorr Sign
def schnorr_sign(message, private_key, p, q, g):
    k = random.randint(1, q)
    r = pow(g, k, p)
    h = hashlib.sha256(f"{r}{message}".encode()).hexdigest()
    e = int(h, 16) % q
    s = (k + e * private_key) % q
    return r, s

# Schnorr Verify
def schnorr_verify(message, signature, public_key):
    r, s = signature
    p, q, g, y = public_key
    h = hashlib.sha256(f"{r}{message}".encode()).hexdigest()
    e = int(h, 16) % q
    v1 = pow(g, s, p)
    v2 = (r * pow(y, e, p)) % p
    return v1 == v2

# Example usage:
public_key, private_key = schnorr_keygen()
message = "Hello, Schnorr!"
signature = schnorr_sign(message, private_key, public_key[0], public_key[1], public_key[2])
is_valid = schnorr_verify(message, signature, public_key)

print("Message:", message)
print("Signature:", signature)
print("Signature valid:", is_valid)

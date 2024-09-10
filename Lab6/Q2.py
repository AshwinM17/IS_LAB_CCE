import random
from sympy import isprime


# Generate a large prime number
def generate_large_prime(bits=256):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate


# Diffie-Hellman Key Exchange
def dh_keygen(bits=256):
    p = generate_large_prime(bits)  # Large prime number
    g = random.randint(2, p - 2)  # Generator (primitive root modulo p)

    # Private keys for Alice and Bob
    a = random.randint(1, p - 2)
    b = random.randint(1, p - 2)

    # Public keys for Alice and Bob
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Shared secret key calculation
    shared_secret_Alice = pow(B, a, p)
    shared_secret_Bob = pow(A, b, p)

    return (p, g, A, B), (shared_secret_Alice, shared_secret_Bob)


# Example usage:
(p, g, A, B), (shared_secret_Alice, shared_secret_Bob) = dh_keygen()

print("Public values (p, g, A, B):", p, g, A, B)
print("Shared secret for Alice:", shared_secret_Alice)
print("Shared secret for Bob:", shared_secret_Bob)
print("Do shared secrets match?", shared_secret_Alice == shared_secret_Bob)

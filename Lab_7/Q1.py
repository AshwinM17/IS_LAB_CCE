import random
from sympy import mod_inverse, isprime, nextprime
import math


def generate_prime(bits):
    """ Generate a prime number with the given number of bits. """
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p


def generate_keypair(bits=512):
    """ Generate a pair of public and private keys. """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    n_squared = n * n
    g = n + 1

    lambda_n = (p - 1) * (q - 1)
    mu = mod_inverse(lambda_n, n)

    public_key = (n, g)
    private_key = (n, n_squared, lambda_n, mu)

    return public_key, private_key


def encrypt(public_key, plaintext):
    """ Encrypt a plaintext integer using the Paillier scheme. """
    n, g = public_key
    n_squared = n * n
    r = random.randint(1, n - 1)
    c = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared
    return c


def decrypt(private_key, ciphertext):
    """ Decrypt a ciphertext integer using the Paillier scheme. """
    n, n_squared, lambda_n, mu = private_key
    x = pow(ciphertext, lambda_n, n_squared) - 1
    x = x // n
    plaintext = (x * mu) % n
    return plaintext


def homomorphic_add(ciphertext1, ciphertext2, public_key):
    """ Perform homomorphic addition of two ciphertexts. """
    n, _ = public_key
    n_squared = n * n
    return (ciphertext1 * ciphertext2) % n_squared


# Generate key pair
public_key, private_key = generate_keypair()

# Encrypt integers
a = 15
b = 25
ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)

print(f'Ciphertext of a: {ciphertext_a}')
print(f'Ciphertext of b: {ciphertext_b}')

# Perform homomorphic addition
ciphertext_sum = homomorphic_add(ciphertext_a, ciphertext_b, public_key)
print(f'Ciphertext of a + b: {ciphertext_sum}')

# Decrypt the result
decrypted_sum = decrypt(private_key, ciphertext_sum)
print(f'Decrypted sum: {decrypted_sum}')
print(f'Expected sum: {a + b}')
import random
from sympy import isprime, mod_inverse

# Helper function to generate a large prime number
def generate_large_prime(bits=256):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

# ElGamal Key Generation
def elgamal_keygen(bits=256):
    p = generate_large_prime(bits)
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)  # Private key
    y = pow(g, x, p)  # Public key component
    return (p, g, y), x  # Public and private keys

# ElGamal Encryption
def elgamal_encrypt(plain_text, public_key):
    p, g, y = public_key
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (plain_text * pow(y, k, p)) % p
    return c1, c2

# ElGamal Decryption
def elgamal_decrypt(cipher_text, private_key, p):
    c1, c2 = cipher_text
    s = pow(c1, private_key, p)
    s_inv = mod_inverse(s, p)
    plain_text = (c2 * s_inv) % p
    return plain_text

# Example usage:
public_key, private_key = elgamal_keygen()
message = 21481  # Simple message, convert larger messages into integers
cipher_text = elgamal_encrypt(message, public_key)
decrypted_message = elgamal_decrypt(cipher_text, private_key, public_key[0])

print("Original message:", message)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)

'''
Original message: 21481
Encrypted message: (12194202736242736452104259687732138013963292676085872100109611756925981687517, 13635466824176720246146197320790799561264099884392058475002430211342456081084)
Decrypted message: 21481
'''

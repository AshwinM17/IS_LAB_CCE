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
message = 12345  # Simple message, convert larger messages into integers
cipher_text = elgamal_encrypt(message, public_key)
decrypted_message = elgamal_decrypt(cipher_text, private_key, public_key[0])

print("Original message:", message)
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)

'''
Original message: 12345
Encrypted message: (10069114562865985365784914797161780181153223960110081119530219667336078998286, 40092983642518516986499427458862517595361912667084031267485021300741129738755)
Decrypted message: 12345
'''

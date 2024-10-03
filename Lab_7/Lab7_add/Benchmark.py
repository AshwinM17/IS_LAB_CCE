import time
from Crypto.Util import number
from Crypto.Random import random

class Paillier:
    def __init__(self, bit_length=2048):
        # Generate two large prime numbers p and q
        self.p = number.getPrime(bit_length)
        self.q = number.getPrime(bit_length)
        # Calculate n and n_squared
        self.n = self.p * self.q
        self.n_squared = self.n ** 2
        # Set g as n + 1
        self.g = self.n + 1
        # Calculate lambda, which is the least common multiple of (p-1) and (q-1)
        self.lambda_ = (self.p - 1) * (self.q - 1)

    def encrypt(self, message):
        # Generate a random value r for encryption
        r = random.randint(1, self.n - 1)
        # Encrypt the message using the Paillier encryption formula
        c = (pow(self.g, message, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return c

    def decrypt(self, ciphertext):
        # Decrypt the ciphertext using the Paillier decryption formula
        u = pow(ciphertext, self.lambda_, self.n_squared)
        l = (u - 1) // self.n
        return (l * number.inverse(self.lambda_, self.n)) % self.n

    def add_encrypted(self, c1, c2):
        # Perform homomorphic addition of two encrypted ciphertexts
        return (c1 * c2) % self.n_squared


class ElGamal:
    def __init__(self, bit_length=2048):
        # Generate a large prime number p
        self.p = number.getPrime(bit_length)  
        # Choose a generator g
        self.g = random.randint(2, self.p - 1)  
        # Generate a private key x
        self.x = random.randint(1, self.p - 2)  
        # Compute the public key y = g^x mod p
        self.y = pow(self.g, self.x, self.p)  

    def encrypt(self, message):
        # Randomly choose k for each encryption
        k = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)  # First part of the ciphertext
        c2 = (message * pow(self.y, k, self.p)) % self.p  # Second part of the ciphertext
        return (c1, c2)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext
        s = pow(c1, self.x, self.p)  # Compute the shared secret
        s_inv = pow(s, self.p - 2, self.p)  # Compute the modular inverse
        return (c2 * s_inv) % self.p

    def get_p(self):
        return self.p  # Return the prime number p


def benchmark_elgamal():
    elgamal = ElGamal()
    message = 5  # Sample message for encryption

    # Measure encryption time
    start = time.time()
    ciphertext = elgamal.encrypt(message)
    encryption_time = time.time() - start

    # Measure decryption time
    start = time.time()
    decrypted_message = elgamal.decrypt(ciphertext)
    decryption_time = time.time() - start

    # Check if the decrypted message matches the original message
    assert decrypted_message == message, "Decryption failed for ElGamal"

    print(f"ElGamal Encryption Time: {encryption_time:.6f}s")
    print(f"ElGamal Decryption Time: {decryption_time:.6f}s")
    print(f"Decrypted message matches the original: {decrypted_message == message}")


def benchmark_paillier():
    paillier = Paillier()
    message = 5  # Sample message for encryption

    # Measure encryption time
    start = time.time()
    ciphertext = paillier.encrypt(message)
    encryption_time = time.time() - start

    # Measure decryption time
    start = time.time()
    decrypted_message = paillier.decrypt(ciphertext)
    decryption_time = time.time() - start

    # Check if the decrypted message matches the original message
    assert decrypted_message == message, "Decryption failed for Paillier"

    print(f"Paillier Encryption Time: {encryption_time:.6f}s")
    print(f"Paillier Decryption Time: {decryption_time:.6f}s")
    print(f"Decrypted message matches the original: {decrypted_message == message}")


if __name__ == "__main__":
    # Run benchmarks for both ElGamal and Paillier encryption schemes
    benchmark_elgamal()
    benchmark_paillier()
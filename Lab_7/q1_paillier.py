import random
from sympy import mod_inverse, nextprime

class Paillier:
    def __init__(self, bit_length=512):
        # Generate two distinct large prime numbers p and q
        self.p = nextprime(random.getrandbits(bit_length))
        self.q = nextprime(random.getrandbits(bit_length))
        
        # Compute n as the product of p and q
        self.n = self.p * self.q
        
        # Compute n squared
        self.n_squared = self.n * self.n
        
        # g is set to n + 1
        self.g = self.n + 1 
        
        # Calculate lambda(n), the least common multiple of (p-1) and (q-1)
        self.lambda_n = (self.p - 1) * (self.q - 1)
        
        # Calculate mu, the modular inverse of lambda(n) modulo n
        self.mu = mod_inverse(self.lambda_n, self.n)

    def encrypt(self, plaintext):
        # Generate a random integer r in the range [1, n-1]
        r = random.randint(1, self.n - 1)
        
        # Compute c1 as g^plaintext mod n_squared
        c1 = pow(self.g, plaintext, self.n_squared)
        
        # Compute c2 as r^n mod n_squared
        c2 = pow(r, self.n, self.n_squared)
        
        # Return the ciphertext as the product of c1 and c2 mod n_squared
        return (c1 * c2) % self.n_squared

    def decrypt(self, ciphertext):
        # Compute u as (ciphertext^lambda(n) - 1) / n
        u = (pow(ciphertext, self.lambda_n, self.n_squared) - 1) // self.n
        
        # Recover the plaintext by multiplying u with mu mod n
        plaintext = (u * self.mu) % self.n
        return plaintext

    def add_encrypted(self, c1, c2):
        # Perform homomorphic addition on two ciphertexts
        return (c1 * c2) % self.n_squared

if __name__ == "__main__":
    # Instantiate the Paillier cryptosystem
    paillier = Paillier()

    # Encrypt two integers
    plaintext1 = 15
    plaintext2 = 25
    ciphertext1 = paillier.encrypt(plaintext1)
    ciphertext2 = paillier.encrypt(plaintext2)

    # Print the resulting ciphertexts
    print("Ciphertext 1:", ciphertext1)
    print("Ciphertext 2:", ciphertext2)

    # Perform addition on the encrypted integers
    encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
    print("Encrypted Sum:", encrypted_sum)

    # Decrypt the result of the addition
    decrypted_sum = paillier.decrypt(encrypted_sum)
    print("Decrypted Sum:", decrypted_sum)

    # Verify it matches the sum of the original integers
    original_sum = plaintext1 + plaintext2
    print("Original Sum:", original_sum)
    print("Verification:", decrypted_sum == original_sum)
import random
from sympy import mod_inverse, isprime

class RSA:
    def __init__(self, bit_length=16):
        # Generate two distinct prime numbers p and q
        self.p = self.generate_prime(bit_length)
        self.q = self.generate_prime(bit_length)
        
        # Compute n as the product of p and q
        self.n = self.p * self.q
        
        # Calculate φ(n) = (p - 1)(q - 1)
        self.phi_n = (self.p - 1) * (self.q - 1)
        
        # Set e to a commonly used value, 65537
        self.e = 65537
        
        # Calculate d, the modular inverse of e mod φ(n)
        self.d = mod_inverse(self.e, self.phi_n)

    def generate_prime(self, bit_length):
        # Continuously generate random numbers until a prime is found
        while True:
            num = random.getrandbits(bit_length)  # Generate a random number of the specified bit length
            if isprime(num):  # Check if the number is prime
                return num  # Return the prime number

    def encrypt(self, plaintext):
        # Encrypt the plaintext using the public key (n, e)
        return pow(plaintext, self.e, self.n)

    def decrypt(self, ciphertext):
        # Decrypt the ciphertext using the private key (n, d)
        return pow(ciphertext, self.d, self.n)

    def multiply_encrypted(self, c1, c2):
        # Perform multiplication on two ciphertexts (homomorphic property)
        return (c1 * c2) % self.n

if __name__ == "__main__":
    # Instantiate the RSA cryptosystem
    rsa = RSA()

    # Encrypt two integers
    plaintext1 = 7
    plaintext2 = 3
    ciphertext1 = rsa.encrypt(plaintext1)
    ciphertext2 = rsa.encrypt(plaintext2)

    # Print the resulting ciphertexts
    print("Ciphertext 1:", ciphertext1)
    print("Ciphertext 2:", ciphertext2)

    # Perform multiplication on the encrypted integers
    encrypted_product = rsa.multiply_encrypted(ciphertext1, ciphertext2)
    print("Encrypted Product:", encrypted_product)

    # Decrypt the result of the multiplication
    decrypted_product = rsa.decrypt(encrypted_product)
    print("Decrypted Product:", decrypted_product)

    # Verify it matches the product of the original integers
    original_product = plaintext1 * plaintext2
    print("Original Product:", original_product)
    print("Verification:", decrypted_product == original_product)

'''
Ciphertext 1: 182690229
Ciphertext 2: 85121177
Encrypted Product: 134286110
Decrypted Product: 21
Original Product: 21
Verification: True
'''
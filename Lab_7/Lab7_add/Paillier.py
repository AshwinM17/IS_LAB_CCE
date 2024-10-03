from Crypto.Util import number
from Crypto.Random import random

class Paillier:
    def __init__(self, bit_length=2048):
        # Generate two large prime numbers p and q
        self.p = number.getPrime(bit_length)
        self.q = number.getPrime(bit_length)
        # Calculate n as the product of p and q
        self.n = self.p * self.q
        # Calculate n squared
        self.n_squared = self.n ** 2
        # Set g as n + 1
        self.g = self.n + 1
        # Calculate lambda as (p-1)(q-1)
        self.lambda_ = (self.p - 1) * (self.q - 1)

    def encrypt(self, message):
        # Generate a random number r in the range [1, n-1]
        r = random.randint(1, self.n - 1)
        # Calculate the ciphertext using the Paillier encryption formula
        c = (pow(self.g, message, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return c  # Return the ciphertext

    def decrypt(self, ciphertext):
        # Compute u as ciphertext^lambda mod n_squared
        u = pow(ciphertext, self.lambda_, self.n_squared)
        # Calculate l as (u - 1) // n
        l = (u - 1) // self.n
        # Return the original message using the modular inverse of lambda mod n
        return (l * number.inverse(self.lambda_, self.n)) % self.n

    def add_encrypted(self, c1, c2):
        # Return the product of two ciphertexts, which corresponds to the sum of their plaintexts
        return (c1 * c2) % self.n_squared

# Example usage
if __name__ == "__main__":
    paillier = Paillier()  # Create an instance of the Paillier encryption scheme
    message1 = 5  # First message to encrypt
    message2 = 10  # Second message to encrypt

    # Encrypt the messages
    ciphertext1 = paillier.encrypt(message1)  # Encrypt the first message
    ciphertext2 = paillier.encrypt(message2)  # Encrypt the second message

    print("Ciphertext 1:", ciphertext1)  # Output the first ciphertext
    print("Ciphertext 2:", ciphertext2)  # Output the second ciphertext

    # Perform addition on the encrypted ciphertexts
    encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
    print("Encrypted Sum:", encrypted_sum)  # Output the encrypted sum

    # Decrypt the sum
    decrypted_sum = paillier.decrypt(encrypted_sum)  # Decrypt the combined ciphertext
    print("Decrypted Sum:", decrypted_sum)  # Output the decrypted sum

    # Verify that the decrypted sum matches the expected sum of the original messages
    original_sum = message1 + message2  # Calculate the original sum
    print("Original Sum:", original_sum)  # Output the original sum
    # Check if the decrypted sum matches the original sum and output the result
    print("Verification:", decrypted_sum == original_sum)  
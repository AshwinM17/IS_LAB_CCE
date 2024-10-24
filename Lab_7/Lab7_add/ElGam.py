import random
from Crypto.Util import number

class ElGamal:
    def __init__(self, bit_length=2048):
        # Generate a large prime number p for the ElGamal encryption scheme
        self.p = number.getPrime(bit_length)
        # Choose a random generator g from the range [2, p-1]
        self.g = random.randint(2, self.p - 1)
        # Generate a private key x in the range [1, p-2]
        self.x = random.randint(1, self.p - 2)
        # Compute the public key y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

    def encrypt(self, message):
        # Randomly choose a value k for each encryption, ensuring k is in the range [1, p-2]
        k = random.randint(1, self.p - 2)
        # Calculate the first part of the ciphertext, c1 = g^k mod p
        c1 = pow(self.g, k, self.p)
        # Calculate the second part of the ciphertext, c2 = (message * y^k) mod p
        c2 = (message * pow(self.y, k, self.p)) % self.p
        return (c1, c2)  # Return the ciphertext as a tuple (c1, c2)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext  # Unpack the ciphertext
        # Compute the shared secret s = c1^x mod p
        s = pow(c1, self.x, self.p)
        # Calculate the modular inverse of the shared secret
        s_inv = pow(s, self.p - 2, self.p)
        # Decrypt the message using the formula: m = (c2 * s_inv) mod p
        return (c2 * s_inv) % self.p

    def get_p(self):
        # Return the prime number p used in the encryption scheme
        return self.p

# Function to perform homomorphic multiplication of two ciphertexts
def homomorphic_multiplication(elgamal, ciphertext1, ciphertext2):
    c1_1, c2_1 = ciphertext1  # Unpack the first ciphertext
    c1_2, c2_2 = ciphertext2  # Unpack the second ciphertext
    # Combine the ciphertexts using the homomorphic property
    return (c1_1 * c1_2 % elgamal.get_p(), c2_1 * c2_2 % elgamal.get_p())

# Example usage
if __name__ == "__main__":
    elgamal = ElGamal()  # Create an instance of the ElGamal encryption scheme
    #we are sending this object only to the functions

    message1 = 5  # First message to encrypt
    message2 = 3  # Second message to encrypt

    # Encrypt the messages
    ciphertext1 = elgamal.encrypt(message1)  # Encrypt the first message
    ciphertext2 = elgamal.encrypt(message2)  # Encrypt the second message

    print("Ciphertext 1:", ciphertext1)  # Output the first ciphertext
    print("Ciphertext 2:", ciphertext2)  # Output the second ciphertext

    # Perform homomorphic multiplication on the ciphertexts
    encrypted_product = homomorphic_multiplication(elgamal, ciphertext1, ciphertext2)
    print("Encrypted Product:", encrypted_product)  # Output the encrypted product

    # Decrypt the product
    decrypted_product = elgamal.decrypt(encrypted_product)  # Decrypt the combined ciphertext
    print("Decrypted Product:", decrypted_product)  # Output the decrypted product

    # Verify that the decrypted product matches the original product
    original_product = message1 * message2  # Calculate the original product
    print("Original Product:", original_product)  # Output the original product
    # Check if the decrypted product matches the original product and output the result
    print("Verification:", decrypted_product == original_product)  
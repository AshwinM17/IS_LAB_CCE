from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number 
from Crypto.Random import get_random_bytes
import math

def generate_keypair(bit_length=1024):
    """
    Generates a public/private key pair for ElGamal encryption.
    The public key consists of (p, g, y), and the private key is x.
    
    :param bit_length: The bit length of the prime number p.
    :return: A tuple containing the public key and private key.
    """
    # Generate a large prime p
    p = number.getPrime(bit_length)

    # g is the generator, usually a small number like 2
    g = 2

    # Private key: x, a random integer in the range [1, p-2]
    x = int.from_bytes(get_random_bytes(bit_length // 8), byteorder='big') % (p - 2) + 1

    # Public key: y = g^x mod p
    y = pow(g, x, p)

    # Return public key (p, g, y) and private key x
    return ((p, g, y), x)


def encrypt(pub_key, message):
    """
    Encrypts a message using the public key.
    
    :param pub_key: The public key (p, g, y).
    :param message: The message to encrypt (as an integer).
    :return: The ciphertext as a tuple (a, b).
    """
    p, g, y = pub_key

    # Randomly choose r such that gcd(r, p) = 1
    r = int.from_bytes(get_random_bytes(p.bit_length() // 8), byteorder='big') % (p - 1)
    while math.gcd(r, p) != 1:
        r = int.from_bytes(get_random_bytes(p.bit_length() // 8), byteorder='big') % (p - 1)

    # Ciphertext: a = g^r mod p, b = m * y^r mod p
    a = pow(g, r, p)
    b = (message * pow(y, r, p)) % p

    return (a, b)


def decrypt(priv_key, ciphertext):
    """
    Decrypts a ciphertext using the private key.
    
    :param priv_key: The private key (x).
    :param ciphertext: The ciphertext as a tuple (a, b).
    :return: The decrypted message.
    """
    p, g, x = priv_key
    a, b = ciphertext

    # Compute shared secret s = a^x mod p
    s = pow(a, x, p)

    # Compute modular inverse of s: s_inv = s^(p-2) mod p (using Fermat's Little Theorem)
    s_inv = pow(s, p - 2, p)

    # Decrypted message: m = b * s_inv mod p
    message = (b * s_inv) % p

    return message


def homomorphic_comparison(ciphertext1, ciphertext2, pub_key):
    """
    Performs a homomorphic comparison on two ciphertexts (encrypted greater-than check).
    
    :param ciphertext1: The first ciphertext (a1, b1).
    :param ciphertext2: The second ciphertext (a2, b2).
    :param pub_key: The public key (p, g, y).
    :return: A ciphertext that represents the comparison (m1 > m2).
    """
    p, g, y = pub_key
    a1, b1 = ciphertext1
    a2, b2 = ciphertext2

    # Homomorphically compare the two encrypted values
    a_comparison = (a1 * a2) % p
    b_comparison = (b1 * b2 * pow(y, 1, p)) % p

    return (a_comparison, b_comparison)


# Example usage:
if __name__ == "__main__":
    # Generate key pair (public and private keys)
    pub_key, priv_key = generate_keypair()

    # Blood pressure readings (as integers) - encrypting both readings
    blood_pressure1 = encrypt(pub_key, 120)
    blood_pressure2 = encrypt(pub_key, 140)

    # Perform homomorphic comparison (this results in encrypted comparison)
    ciphertext_comparison = homomorphic_comparison(blood_pressure1, blood_pressure2, pub_key)

    # Optional: Decrypt the comparison result for demonstration (not typically done in real-world)
    decrypted_comparison = decrypt((pub_key[0], pub_key[1], priv_key), ciphertext_comparison)
    print(f"Decrypted comparison: {decrypted_comparison} (True if blood pressure 1 > blood pressure 2)")

    # Diagnosis based on the encrypted comparison result
    # Using modular arithmetic to decrypt and check the comparison
    diagnosis = ciphertext_comparison[0] * pow(ciphertext_comparison[1], -1, pub_key[0]) % pub_key[0]

    # If diagnosis > 1, it indicates blood pressure 1 > blood pressure 2
    if diagnosis > 1:
        print("Diagnosis: High Blood Pressure detected.")
    else:
        print("Diagnosis: Normal Blood Pressure.")
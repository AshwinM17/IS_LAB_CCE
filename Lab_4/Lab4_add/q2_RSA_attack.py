from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, getPrime
from Crypto.Random import get_random_bytes
import math

def weak_rsa_key_generation():
    """Generates a weak RSA key with small prime factors."""
    # Use small primes for demonstration purposes (not secure)
    p = 61  # Small prime
    q = 53  # Small prime
    n = p * q  # RSA modulus
    phi = (p - 1) * (q - 1)  # Euler's totient
    e = 65537  # Commonly used public exponent

    # Calculate the private exponent d
    d = inverse(e, phi)
    return n, e, d, p, q

def factor_n(n):
    """Attempts to factor the modulus n into its prime factors."""
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return i, n // i  # Return the factors (p, q)
    return None

def encrypt_message(n, e, message):
    """Encrypts the message using the public key (n, e)."""
    message_bytes = message.encode('utf-8')
    m = int.from_bytes(message_bytes, byteorder='big')
    c = pow(m, e, n)  # Ciphertext
    return c

def decrypt_message(c, d, n):
    """Decrypts the ciphertext using the private key (d)."""
    m = pow(c, d, n)  # Decrypted message
    # Convert back to bytes, ensuring we properly handle the byte length
    byte_length = (n.bit_length() + 7) // 8  # Calculate byte length of n
    return m.to_bytes(byte_length, byteorder='big').decode('utf-8').rstrip('\x00')  # Decode and strip null bytes

# Demonstrating the attack
if __name__ == "__main__":
    # Step 1: Generate a weak RSA key
    n, e, d, p, q = weak_rsa_key_generation()
    print(f"Weak RSA key generated with n = {n}, e = {e}")

    # Step 2: Eve attempts to factor n
    print("Eve attempts to factor n...")
    factors = factor_n(n)
    
    if factors:
        print(f"Eve successfully factors n: p = {factors[0]}, q = {factors[1]}")
        
        # Step 3: Recover the private key (d)
        recovered_d = inverse(e, (factors[0] - 1) * (factors[1] - 1))
        print(f"Eve recovers the private key d = {recovered_d}")

        # Step 4: Encrypt a message using the public key
        message = "Confidential Information"
        ciphertext = encrypt_message(n, e, message)
        print(f"Ciphertext: {ciphertext}")

        # Step 5: Decrypt the message using the recovered private key
        decrypted_message = decrypt_message(ciphertext, recovered_d, n)
        print(f"Decrypted message: {decrypted_message}")
    else:
        print("Eve failed to factor n.")
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
from Crypto.Random import random

def generate_keys(bits=2048):
    p = getPrime(bits)  
    g = random.randint(2, p-1) 
    x = random.randint(2, p-2) 
    h = pow(g, x, p) 
    return (p, g, h), x

def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    k = random.randint(2, p-2)  
    c1 = pow(g, k, p)  
    m = bytes_to_long(message)
    c2 = (m * pow(h, k, p)) % p  
    return c1, c2

def elgamal_decrypt(private_key, p, c1, c2):
    x = private_key
    s = pow(c1, x, p) 
    s_inv = inverse(s, p) 
    m = (c2 * s_inv) % p 
    return long_to_bytes(m)

public_key, private_key = generate_keys(bits=2048)
message = b"Confidential Data"

ciphertext = elgamal_encrypt(public_key, message)
print("Ciphertext:", ciphertext)

decrypted_message = elgamal_decrypt(private_key, public_key[0], ciphertext[0], ciphertext[1])
print("Decrypted message:", decrypted_message.decode())
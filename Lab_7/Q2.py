import sympy

def generate_rsa_keys():
    p = sympy.randprime(1 << 7, 1 << 8)
    q = sympy.randprime(1 << 7, 1 << 8)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    d = pow(e, -1, phi)

    return (e, n), (d, n)

def encrypt(message, e, n):
    return pow(message, e, n)

def decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)


public_key, private_key = generate_rsa_keys()
e, n = public_key
d, n = private_key

m1 = 7
m2 = 3
c1 = encrypt(m1, e, n)
c2 = encrypt(m2, e, n)

c_product = (c1 * c2) % n

decrypted_product = decrypt(c_product, d, n)

expected_product = m1 * m2

# Output results
print(f"Original integers: {m1}, {m2}")
print(f"Encrypted integers: {c1}, {c2}")
print(f"Ciphertext of the product: {c_product}")
print(f"Decrypted product: {decrypted_product}")
print(f"Expected product: {expected_product}")

# Verification
assert decrypted_product == expected_product, "Decrypted result does not match the expected product!"
print("Verification successful: Decrypted result matches the expected product.")
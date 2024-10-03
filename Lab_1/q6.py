from sympy import mod_inverse
def calculate_affine_keys(plain_pair, cipher_pair):
    # Extract the values from the pairs
    x1, x2 = plain_pair  # Plaintext values (e.g., C=2, I=8)
    y1, y2 = cipher_pair  # Ciphertext values (e.g., J=9, V=21)
    
    # Calculate a (multiplicative key)
    diff_x = (x2 - x1) % 26
    diff_y = (y2 - y1) % 26
    
    # Find the modular inverse of (x2 - x1) mod 26
    diff_x_inv = mod_inverse(diff_x, 26)
    
    if diff_x_inv is None:
        raise ValueError(f"No modular inverse for {diff_x} under modulo 26. Ensure x2 - x1 is coprime with 26.")
    
    # Calculate a using the formula: a = (diff_y * diff_x_inv) % 26
    a = (diff_y * diff_x_inv) % 26
    
    # Calculate b (additive key)
    # Use the equation: y1 = (a * x1 + b) mod 26 -> b = (y1 - a * x1) mod 26
    b = (y1 - a * x1) % 26
    
    return a, b

def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError(f"No modular inverse for a={a} under modulo 26.")

    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))
        else:
            plaintext += char
    return plaintext

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
plain_pair = (0, 1)
cipher_pair = (6, 11)

a,b=calculate_affine_keys(plain_pair, cipher_pair)
decrypted_message = affine_decrypt(ciphertext, a, b)
print("\nDecrypted Message:", decrypted_message)
from sympy import mod_inverse

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

b = cipher_pair[0]
a = (cipher_pair[1] - b) % 26

decrypted_message = affine_decrypt(ciphertext, a, b)
print("\nDecrypted Message:", decrypted_message)
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
import random

random.seed(40)

def fixed_rng(seed, length):
    random.seed(seed)
    return bytes(random.getrandbits(8) for _ in range(length))

private_key = ECC.generate(curve='P-256', randfunc=lambda n: fixed_rng(42, n))
public_key = private_key.public_key()

def encrypt_message(public_key, message):
    ephemeral_private_key = ECC.generate(curve='P-256', randfunc=lambda n: fixed_rng(123, n))
    ephemeral_public_key = ephemeral_private_key.public_key()
    shared_secret = ephemeral_private_key.d * public_key.pointQ
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')
    derived_key = HKDF(master=shared_secret_bytes, key_len=32, salt=None, hashmod=SHA256)
    iv = fixed_rng(999, 16)
    cipher_aes = AES.new(derived_key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    return ephemeral_public_key, iv, ciphertext, tag

def decrypt_message(private_key, ephemeral_public_key, iv, ciphertext, tag):
    shared_secret = private_key.d * ephemeral_public_key.pointQ
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big')
    derived_key = HKDF(master=shared_secret_bytes, key_len=32, salt=None, hashmod=SHA256)
    cipher_aes = AES.new(derived_key, AES.MODE_GCM, iv)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message

message = b"Secure Transactions"
ephemeral_public_key, iv, ciphertext, tag = encrypt_message(public_key, message)
print("Ciphertext (in hex):", ciphertext.hex())

decrypted_message = decrypt_message(private_key, ephemeral_public_key, iv, ciphertext, tag)
print("Decrypted message:", decrypted_message.decode())
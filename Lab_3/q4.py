from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time

start_time = time.time()
rsa_key = RSA.generate(2048)
rsa_key_generation_time = time.time() - start_time
rsa_public_key = rsa_key.publickey()

start_time = time.time()
ecc_key = ECC.generate(curve='P-256')
ecc_key_generation_time = time.time() - start_time
ecc_public_key = ecc_key.public_key()

print(f"RSA Key Generation Time: {rsa_key_generation_time:.4f} seconds")
print(f"ECC Key Generation Time: {ecc_key_generation_time:.4f} seconds")

file_data = b'A' * 1024 * 1024 

aes_key = get_random_bytes(16)
rsa_cipher = PKCS1_OAEP.new(rsa_public_key)

start_time = time.time()
rsa_encrypted_key = rsa_cipher.encrypt(aes_key)
rsa_encryption_time = time.time() - start_time

rsa_cipher = PKCS1_OAEP.new(rsa_key)
start_time = time.time()
rsa_decrypted_key = rsa_cipher.decrypt(rsa_encrypted_key)
rsa_decryption_time = time.time() - start_time

print(f"RSA Encryption Time: {rsa_encryption_time:.4f} seconds")
print(f"RSA Decryption Time: {rsa_decryption_time:.4f} seconds")

aes_key_hash = SHA256.new(aes_key)
signer = DSS.new(ecc_key, 'fips-186-3')

start_time = time.time()
ecc_signature = signer.sign(aes_key_hash)
ecc_encryption_time = time.time() - start_time

verifier = DSS.new(ecc_public_key, 'fips-186-3')
ecc_key_hash = SHA256.new(aes_key)

start_time = time.time()
try:
    verifier.verify(ecc_key_hash, ecc_signature)
    ecc_decryption_time = time.time() - start_time
    print("ECC Decryption successful: Key verified")
except ValueError:
    ecc_decryption_time = time.time() - start_time
    print("ECC Decryption failed: Invalid signature")

print(f"ECC Encryption Time: {ecc_encryption_time:.4f} seconds")
print(f"ECC Decryption Time: {ecc_decryption_time:.4f} seconds")

cipher = AES.new(aes_key, AES.MODE_CBC)
start_time = time.time()
encrypted_file_data = cipher.encrypt(pad(file_data, AES.block_size))
file_encryption_time = time.time() - start_time

cipher = AES.new(aes_key, AES.MODE_CBC, cipher.iv)
start_time = time.time()
decrypted_file_data = unpad(cipher.decrypt(encrypted_file_data), AES.block_size)
file_decryption_time = time.time() - start_time

print(f"File Encryption Time: {file_encryption_time:.4f} seconds")
print(f"File Decryption Time: {file_decryption_time:.4f} seconds")
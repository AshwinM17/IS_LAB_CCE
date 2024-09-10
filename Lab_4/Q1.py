import rsa
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# --- Key Management System ---
class KeyManagementSystem:
    def __init__(self):
        self.keys = {}

    def generate_rsa_keys(self, system_name):
        (pubkey, privkey) = rsa.newkeys(2048)
        self.keys[system_name] = {'public': pubkey, 'private': privkey}
        print(f"RSA keys generated for {system_name}")

    def get_public_key(self, system_name):
        return self.keys[system_name]['public']

    def get_private_key(self, system_name):
        return self.keys[system_name]['private']

    def revoke_key(self, system_name):
        del self.keys[system_name]
        print(f"Keys revoked for {system_name}")


# --- Secure Communication System ---
class SecureCommunication:
    def __init__(self, key_mgmt):
        self.kms = key_mgmt

    def sign_message(self, system_name, message):
        priv_key = self.kms.get_private_key(system_name)
        signature = rsa.sign(message.encode(), priv_key, 'SHA-256')
        return signature

    def verify_signature(self, system_name, message, signature):
        pub_key = self.kms.get_public_key(system_name)
        try:
            rsa.verify(message.encode(), signature, pub_key)
            return True
        except:
            return False

    def diffie_hellman_exchange(self):
        # Simulated Diffie-Hellman key exchange
        p = 23  # a prime number
        g = 5  # a primitive root modulo p

        a = random.randint(1, 100)  # System A's private key
        b = random.randint(1, 100)  # System B's private key

        A = pow(g, a, p)  # System A's public key
        B = pow(g, b, p)  # System B's public key

        # Shared secrets
        shared_secret_A = pow(B, a, p)
        shared_secret_B = pow(A, b, p)

        if shared_secret_A == shared_secret_B:
            return hashlib.sha256(str(shared_secret_A).encode()).digest()
        else:
            raise Exception("Diffie-Hellman key exchange failed.")

    def encrypt_message(self, shared_key, message):
        cipher = AES.new(shared_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return (cipher.nonce, ciphertext, tag)

    def decrypt_message(self, shared_key, nonce, ciphertext, tag):
        cipher = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return plaintext.decode()
        except ValueError:
            return "Key incorrect or message corrupted"


# --- Main Program ---
kms = KeyManagementSystem()
sc = SecureCommunication(kms)

# Generate RSA keys for the systems
kms.generate_rsa_keys('System A')
kms.generate_rsa_keys('System B')

# Example of Diffie-Hellman key exchange and communication
shared_key = sc.diffie_hellman_exchange()

# System A sends an encrypted and signed message to System B
message = "Confidential Financial Report"
signature = sc.sign_message('System A', message)
nonce, ciphertext, tag = sc.encrypt_message(shared_key, message)

# System B receives the message and verifies the signature
is_valid_signature = sc.verify_signature('System A', message, signature)
if is_valid_signature:
    decrypted_message = sc.decrypt_message(shared_key, nonce, ciphertext, tag)
    print(f"Decrypted Message: {decrypted_message}")
else:
    print("Signature verification failed.")

# Revoke a key
kms.revoke_key('System A')

# The system can be scaled by adding more subsystems with kms.generate_rsa_keys('System X')
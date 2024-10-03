from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import time

class SecureCommunicationSystem:
    def __init__(self):
        # Dictionary to hold subsystem information, including keys
        self.subsystems = {}
        # List to log activities and messages
        self.logs = []
    
    def generate_rsa_key_pair(self, subsystem_id):
        # Generate a new RSA key pair for the specified subsystem
        key = RSA.generate(2048)  # 2048-bit RSA key
        self.subsystems[subsystem_id] = {
            'key_pair': key,  # Store the RSA key pair
            'shared_key': None  # Initialize shared key as None
        }
        self.log(f"RSA key pair generated for {subsystem_id}.")
        
    def log(self, message):
        # Log a message with the current timestamp
        self.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        print(message)  # Print the log message to console

    def dh_key_exchange(self, sender_id, receiver_id):
        # Implement a simple Diffie-Hellman key exchange for shared secret generation
        p = getPrime(2048)  # Generate a large prime number
        g = 2  # Use 2 as the base for DH

        # Sender's private key (randomly generated)
        a = get_random_bytes(32)
        A = pow(g, int.from_bytes(a, 'big'), p)  # Compute sender's public key

        # Receiver's private key (randomly generated)
        b = get_random_bytes(32)
        B = pow(g, int.from_bytes(b, 'big'), p)  # Compute receiver's public key

        # Compute the shared secret
        shared_secret_sender = pow(B, int.from_bytes(a, 'big'), p)  # Sender computes shared secret
        shared_secret_receiver = pow(A, int.from_bytes(b, 'big'), p)  # Receiver computes shared secret

        # Check if both computed shared secrets match
        if shared_secret_sender == shared_secret_receiver:
            # Reduce key size to fit AES requirements (16 bytes)
            self.subsystems[sender_id]['shared_key'] = shared_secret_sender % (2 ** 128)  
            self.subsystems[receiver_id]['shared_key'] = shared_secret_receiver % (2 ** 128)  
            self.log(f"Shared key established between {sender_id} and {receiver_id}.")
        else:
            self.log("Failed to establish shared key.")

    def encrypt_message(self, sender_id, receiver_id, message):
        # Encrypt a message using AES with the shared key
        # Convert the shared key to a 16-byte format
        shared_key = self.subsystems[sender_id]['shared_key'].to_bytes(16, 'big')  
        cipher_aes = AES.new(shared_key, AES.MODE_EAX)  # Create a new AES cipher object in EAX mode
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())  # Encrypt the message and generate a tag
        # Return the concatenated nonce, tag, and ciphertext for decryption
        return cipher_aes.nonce + tag + ciphertext  

    def decrypt_message(self, receiver_id, encrypted_message):
        # Decrypt an encrypted message using AES with the shared key
        # Convert the shared key to a 16-byte format
        shared_key = self.subsystems[receiver_id]['shared_key'].to_bytes(16, 'big')  
        nonce = encrypted_message[:16]  # Extract the nonce from the encrypted message
        tag = encrypted_message[16:32]  # Extract the tag
        ciphertext = encrypted_message[32:]  # Extract the actual ciphertext

        # Create a new AES cipher object using the shared key and the extracted nonce
        cipher_aes = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)  
        # Decrypt the message and verify using the tag
        original_message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
        self.log(f"Message decrypted for {receiver_id}.")
        return original_message  # Return the original decrypted message

    def revoke_key(self, subsystem_id):
        # Revoke the keys associated with a given subsystem
        if subsystem_id in self.subsystems:
            del self.subsystems[subsystem_id]  # Remove subsystem from the dictionary
            self.log(f"Keys revoked for subsystem {subsystem_id}.")

# Example Usage:
secure_system = SecureCommunicationSystem()

# Generate RSA keys for subsystems
secure_system.generate_rsa_key_pair("Finance System")
secure_system.generate_rsa_key_pair("HR System")
secure_system.generate_rsa_key_pair("Supply Chain Management")

# Establish secure communication using Diffie-Hellman key exchange
secure_system.dh_key_exchange("Finance System", "HR System")

# Encrypt a message from Finance to HR
encrypted_msg = secure_system.encrypt_message("Finance System", "HR System", "Confidential financial report.")

# Decrypt the message at HR
original_message = secure_system.decrypt_message("HR System", encrypted_msg)
print(f"Decrypted Message: {original_message}")

# Revoking keys (if necessary)
secure_system.revoke_key("Finance System")
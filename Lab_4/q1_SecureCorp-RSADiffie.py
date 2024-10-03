from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import time

class SecureCommunicationSystem:
    def __init__(self):
        self.subsystems = {}
        self.logs = []

    def create_system(self, subsystem_id):
        self.subsystems[subsystem_id] = {
            'shared_key': None,
            'private': get_random_bytes(32)  # Randomly generated private value for DH
        }
        self.log(f"{subsystem_id} created.")
        
    def log(self, message):
        self.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        print(message)

    def dh_key_exchange(self, sender_id, receiver_id):
        p = getPrime(2048)  # Generate a large prime number
        g = 2  # Use 2 as the base for DH

        # Sender's private key

        # Convert the sender's private key byte string to an integer
        a = int.from_bytes(self.subsystems[sender_id]['private'], 'big')  
        A = pow(g, a, p)  # Compute sender's public key

        # Receiver's private key
         # Convert the sender's private key byte string to an integer
        b = int.from_bytes(self.subsystems[receiver_id]['private'], 'big')
        B = pow(g, b, p)  # Compute receiver's public key

        # Compute the shared secret
        shared_secret_sender = pow(B, a, p)  # Sender computes shared secret
        shared_secret_receiver = pow(A, b, p)  # Receiver computes shared secret

        # Check if both computed shared secrets match
        if shared_secret_sender == shared_secret_receiver:
            # Reduce key size to fit AES requirements (16 bytes)
            shared_key = shared_secret_sender % (2 ** 128)
            self.subsystems[sender_id]['shared_key'] = shared_key
            self.subsystems[receiver_id]['shared_key'] = shared_key
            self.log(f"Shared key established between {sender_id} and {receiver_id}.")
        else:
            self.log("Failed to establish shared key.")

    def encrypt_message(self, sender_id, receiver_id, message):
        # Ensure sender has a shared key
        if sender_id not in self.subsystems or self.subsystems[sender_id]['shared_key'] is None:
            self.log(f"No shared key found for {sender_id}.")
            return None

        # Use the receiver's shared key for encryption
        shared_key = self.subsystems[receiver_id]['shared_key'].to_bytes(16, 'big')  
        cipher_aes = AES.new(shared_key, AES.MODE_EAX)  # Create a new AES cipher object in EAX mode
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())  # Encrypt the message and generate a tag
        # Return the concatenated nonce, tag, and ciphertext for decryption
        return cipher_aes.nonce + tag + ciphertext  

    def decrypt_message(self, receiver_id, encrypted_message):
        # Ensure receiver has a shared key
        if receiver_id not in self.subsystems or self.subsystems[receiver_id]['shared_key'] is None:
            self.log(f"No shared key found for {receiver_id}.")
            return None

        shared_key = self.subsystems[receiver_id]['shared_key'].to_bytes(16, 'big')  
        nonce = encrypted_message[:16]  # Extract the nonce from the encrypted message
        tag = encrypted_message[16:32]  # Extract the tag
        ciphertext = encrypted_message[32:]  # Extract the actual ciphertext

        # Create a new AES cipher object using the shared key and the extracted nonce
        cipher_aes = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)  
        try:
            original_message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
            self.log(f"Message decrypted for {receiver_id}.")
            return original_message  # Return the original decrypted message
        except ValueError:
            self.log("Decryption failed: MAC check failed.")
            return None

    def revoke_key(self, subsystem_id):
        # Revoke the keys associated with a given subsystem
        if subsystem_id in self.subsystems:
            del self.subsystems[subsystem_id]  # Remove subsystem from the dictionary
            self.log(f"Keys revoked for subsystem {subsystem_id}.")

# Example Usage:
secure_system = SecureCommunicationSystem()

# Generate RSA keys for subsystems
secure_system.create_system("Finance System")
secure_system.create_system("HR System")
secure_system.create_system("Supply Chain Management")

# Establish secure communication using Diffie-Hellman key exchange
secure_system.dh_key_exchange("Finance System", "HR System")
secure_system.dh_key_exchange("Supply Chain Management", "HR System")
secure_system.dh_key_exchange("Supply Chain Management", "Finance System")

# Encrypt a message from Finance to HR
encrypted_msg = secure_system.encrypt_message("Finance System", "HR System", "Confidential financial report.")

# Decrypt the message at HR
original_message = secure_system.decrypt_message("HR System", encrypted_msg)
if original_message is not None:
    print(f"Decrypted Message: {original_message}")
else:
    print("Failed to decrypt the message.")
    
# Revoking keys (if necessary)
secure_system.revoke_key("Finance System")

import random
import json
import os
from datetime import datetime, timedelta
from sympy import isprime

# Directory for storing keys and logs
KEY_DIRECTORY = 'keys/'
# Key expiry interval set to 365 days
KEY_EXPIRY_INTERVAL = timedelta(days=365)

# Ensure the key directory exists; if not, create it
if not os.path.exists(KEY_DIRECTORY):
    os.makedirs(KEY_DIRECTORY)

# Function to generate a large prime number
def generate_large_prime(bits):
    while True:
        # Generate a random number with the specified number of bits
        p = random.getrandbits(bits)
        # Check if the number is prime
        if isprime(p):
            return p  # Return the prime number if found

# Rabin key pair generation
def rabin_key_pair(bits):
    # Generate two large prime numbers p and q
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    n = p * q  # Calculate n as the product of p and q
    public_key = n  # Public key is n
    private_key = (p, q)  # Private key is a tuple of (p, q)
    
    return public_key, private_key  # Return the keys

# Rabin encryption function
def encrypt_rabin(public_key, plaintext):
    n = public_key  # Public key
    # Encrypt plaintext using Rabin encryption formula
    return (plaintext ** 2) % n

# Rabin decryption function
def decrypt_rabin(private_key, ciphertext):
    p, q = private_key  # Extract p and q from the private key
    n = p * q  # Calculate n

    # Calculate square roots of ciphertext modulo p and q
    sqrt_p1 = pow(ciphertext, (p + 1) // 4, p)
    sqrt_p2 = (p - sqrt_p1) % p
    sqrt_q1 = pow(ciphertext, (q + 1) // 4, q)
    sqrt_q2 = (q - sqrt_q1) % q
    
    # Combine the results to get all possible plaintext candidates
    plaintext_candidates = [
        (sqrt_p1 * sqrt_q1) % n,
        (sqrt_p1 * sqrt_q2) % n,
        (sqrt_p2 * sqrt_q1) % n,
        (sqrt_p2 * sqrt_q2) % n
    ]
    
    return plaintext_candidates  # Return the candidates

# Class to manage key generation, storage, and revocation
class KeyManager:
    def __init__(self):
        self.keys = {}  # Dictionary to store keys
        self.load_keys()  # Load existing keys from the file

    # Key pair generation for a facility
    def generate_key_pair(self, facility_id, bits=1024):
        public_key, private_key = rabin_key_pair(bits)  # Generate key pair
        # Store keys along with metadata (creation and expiry dates)
        self.keys[facility_id] = {
            'public_key': public_key,
            'private_key': private_key,
            'creation_date': datetime.now().isoformat(),
            'expiry_date': (datetime.now() + KEY_EXPIRY_INTERVAL).isoformat()
        }
        self.save_keys()  # Save the updated keys to a file
        # Log the key generation event
        self.audit_log('Key Generation', f"Generated key pair for facility {facility_id}")
        return public_key, private_key  # Return the generated keys

    # Retrieve the key pair for a specific facility
    def get_key_pair(self, facility_id):
        key_data = self.keys.get(facility_id)  # Get key data for the facility
        # Check if the key is found and not expired
        if key_data and datetime.now() < datetime.fromisoformat(key_data['expiry_date']):
            return key_data['public_key'], key_data['private_key']  # Return keys
        else:
            raise ValueError("Key not found or expired")  # Raise an error if not found or expired

    # Revoke the key for a specific facility
    def revoke_key(self, facility_id):
        if facility_id in self.keys:
            del self.keys[facility_id]  # Delete the key for the facility
            self.save_keys()  # Save the updated keys to a file
            # Log the key revocation event
            self.audit_log('Key Revocation', f"Revoked key pair for facility {facility_id}")
        else:
            raise ValueError("Key not found")  # Raise an error if not found

    # Renew keys for all facilities if expired
    def renew_keys(self):
        for facility_id, key_data in list(self.keys.items()):
            # Check if the key is expired
            if datetime.now() >= datetime.fromisoformat(key_data['expiry_date']):
                self.generate_key_pair(facility_id)  # Re-generate for renewal
                # Log the key renewal event
                self.audit_log('Key Renewal', f"Renewed key pair for facility {facility_id}")

    # Save keys to a JSON file
    def save_keys(self):
        with open(os.path.join(KEY_DIRECTORY, 'keys.json'), 'w') as f:
            json.dump(self.keys, f, indent=4)  # Write the keys to the file in JSON format

    # Load keys from a JSON file
    def load_keys(self):
        key_file = os.path.join(KEY_DIRECTORY, 'keys.json')  # Path to the key file
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                self.keys = json.load(f)  # Load keys from the file

    # Audit logging function
    def audit_log(self, action, details):
        # Append log entries to the audit log file
        with open(os.path.join(KEY_DIRECTORY, 'audit.log'), 'a') as f:
            f.write(f"{datetime.now()} - {action}: {details}\n")

# Example Usage
if __name__ == "__main__":
    key_manager = KeyManager()  # Initialize the key manager
    
    facility_id = 'hospital_123'  # Example facility ID
    # Generate key pair for the facility
    public_key, private_key = key_manager.generate_key_pair(facility_id)
    print(f"Generated keys for {facility_id}:")
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

    # Get key pair and demonstrate encryption/decryption
    pub_key, priv_key = key_manager.get_key_pair(facility_id)  # Retrieve the keys
    plaintext = 12345  # Example plaintext
    # Encrypt the plaintext
    encrypted = encrypt_rabin(pub_key, plaintext)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt the ciphertext
    decrypted_candidates = decrypt_rabin(priv_key, encrypted)
    print(f"Decrypted candidates: {decrypted_candidates}")

    # Check which candidate matches the original plaintext
    decrypted_plaintext = next((pt for pt in decrypted_candidates if pt == plaintext), None)
    
    # Verify if decryption was successful
    if decrypted_plaintext is not None:
        print(f"Decrypted to original plaintext: {decrypted_plaintext}")
    else:
        print("Decryption did not yield the original plaintext.")

    # Renew keys for all facilities
    key_manager.renew_keys()

    # Revoke the key for the facility
    key_manager.revoke_key(facility_id)

    # Display keys to verify revocation
    print("Keys after revocation:")
    print(key_manager.keys)
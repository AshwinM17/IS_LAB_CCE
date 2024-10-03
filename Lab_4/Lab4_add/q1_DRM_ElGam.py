from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import os
import time
import json
from threading import Timer

class DRMSystem:
    def __init__(self, key_size=2048):
        # Initialize the DRM system with a specified key size
        self.key_size = key_size
        self.master_key_pair = None  # To hold the master public-private key pair
        self.content_keys = {}  # To map content IDs to their encrypted content
        self.access_control = {}  # To manage access rights for customers
        self.logs = []  # To store logs of operations
        self.key_renewal_interval = 60 * 60 * 24 * 30  # Set key renewal interval to 30 days
        self.start_key_renewal()  # Start the automatic key renewal process

    def generate_master_key(self):
        """Generates a master public-private key pair using the ElGamal cryptosystem."""
        self.master_key_pair = ElGamal.generate(self.key_size, get_random_bytes)
        self.log("Master key pair generated.")

    def encrypt_content(self, content_id, content):
        """Encrypts the given content using the master public key.

        Args:
            content_id (str): Unique identifier for the content.
            content (bytes): The content to be encrypted.
        """
        h = SHA256.new(content).digest()  # Create a hash of the content
        encrypted_content = self.master_key_pair.encrypt(h, get_random_bytes(16))  # Encrypt the hash
        self.content_keys[content_id] = encrypted_content  # Store the encrypted content
        self.log(f"Content {content_id} encrypted.")

    def distribute_key(self, customer_id, content_id):
        """Grants limited-time access to customers for specific content.

        Args:
            customer_id (str): Unique identifier for the customer.
            content_id (str): Unique identifier for the content.
        """
        # Example access control: Limited-time access for 1 hour
        self.access_control[(customer_id, content_id)] = time.time() + 3600  # Set access expiration
        self.log(f"Access granted to {customer_id} for content {content_id}.")

    def revoke_access(self, customer_id, content_id):
        """Revokes access for a specific customer to specific content.

        Args:
            customer_id (str): Unique identifier for the customer.
            content_id (str): Unique identifier for the content.
        """
        if (customer_id, content_id) in self.access_control:
            del self.access_control[(customer_id, content_id)]  # Remove access entry
            self.log(f"Access revoked for {customer_id} for content {content_id}.")

    def key_revocation(self):
        """Revokes the master key and generates a new one."""
        self.generate_master_key()  # Generate a new master key pair
        self.log("Master key revoked and renewed.")

    def check_access(self, customer_id, content_id):
        """Checks if a customer has access to specific content.

        Args:
            customer_id (str): Unique identifier for the customer.
            content_id (str): Unique identifier for the content.

        Returns:
            bool: True if access is granted, False otherwise.
        """
        if (customer_id, content_id) in self.access_control:
            access_time = self.access_control[(customer_id, content_id)]
            if time.time() <= access_time:  # Check if access is still valid
                return True
        return False

    def secure_store_key(self):
        """Securely stores the master private key."""
        with open("private_key.pem", "wb") as f:
            f.write(self.master_key_pair.export_key())  # Export the master key to a file
        os.chmod("private_key.pem", 0o600)  # Restrict access to the private key file
        self.log("Master private key securely stored.")

    def log(self, message):
        """Logs actions and operations in the DRM system.

        Args:
            message (str): The message to be logged.
        """
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')  # Get the current timestamp
        log_entry = f"{timestamp} - {message}"  # Create a log entry
        self.logs.append(log_entry)  # Append the log entry to the log list
        print(log_entry)  # For demonstration purposes, print the log entry

    def start_key_renewal(self):
        """Starts a timer to automatically renew keys at regular intervals."""
        Timer(self.key_renewal_interval, self.renew_keys).start()  # Set a timer to renew keys

    def renew_keys(self):
        """Renews the master public-private key pair."""
        self.key_revocation()  # Revoke the current key and generate a new one
        self.start_key_renewal()  # Restart the key renewal timer

    def save_logs(self):
        """Saves logs to a file for auditing purposes."""
        with open("drm_logs.json", "w") as f:
            json.dump(self.logs, f, indent=4)  # Write logs to a JSON file

# Example Usage
if __name__ == "__main__":
    drm = DRMSystem()  # Create an instance of the DRM system
    drm.generate_master_key()  # Generate the master key pair
    drm.encrypt_content("content1", b"Some digital content")  # Encrypt some content
    drm.distribute_key("customer1", "content1")  # Grant access to a customer
    drm.revoke_access("customer1", "content1")  # Revoke access for the customer
    drm.key_revocation()  # Renew the master key
    drm.secure_store_key()  # Securely store the master private key
    drm.save_logs()  # Save logs at the end of operations
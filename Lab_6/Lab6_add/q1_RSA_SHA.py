from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes

# Generate RSA Key Pair
def generate_rsa_key_pair():
    # Generate a new RSA key pair with a key size of 2048 bits
    key = RSA.generate(2048)
    
    # Export the private key in PEM format
    private_key = key.export_key(format='PEM')
    
    # Export the public key in PEM format
    public_key = key.publickey().export_key(format='PEM')
    
    return private_key, public_key

# Encrypt a message using RSA
def encrypt_message(public_key, message):
    # Import the public key for encryption
    key = RSA.import_key(public_key)
    
    # Create a new PKCS1_OAEP cipher for encryption
    cipher = PKCS1_OAEP.new(key)
    
    # Encrypt the message
    encrypted_message = cipher.encrypt(message)
    
    return encrypted_message

# Decrypt a message using RSA
def decrypt_message(private_key, encrypted_message):
    # Import the private key for decryption
    key = RSA.import_key(private_key)
    
    # Create a new PKCS1_OAEP cipher for decryption
    cipher = PKCS1_OAEP.new(key)
    
    # Decrypt the message
    decrypted_message = cipher.decrypt(encrypted_message)
    
    return decrypted_message

# Sign a message using SHA-256 and RSA
def sign_message(private_key, message):
    # Import the private key for signing
    key = RSA.import_key(private_key)
    
    # Create a SHA-256 hash of the message
    message_hash = SHA256.new(message)
    
    # Create a PSS signature for the message hash
    signature = pss.new(key).sign(message_hash)
    
    return signature

# Verify a message signature
def verify_signature(public_key, message, signature):
    # Import the public key for verification
    key = RSA.import_key(public_key)
    
    # Create a SHA-256 hash of the message
    message_hash = SHA256.new(message)
    
    # Create a PSS verifier
    verifier = pss.new(key)
    try:
        # Verify the signature against the message hash
        verifier.verify(message_hash, signature)
        return True  # Signature is valid
    except (ValueError, TypeError):
        return False  # Signature is invalid

if __name__ == "__main__":
    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()
    print("Keys generated.")

    # Step 2: Define the message to be encrypted and signed
    original_message = b"This is a secret message."

    # Step 3: Encrypt the message (Confidentiality)
    encrypted_message = encrypt_message(public_key, original_message)
    print("Encrypted message:", encrypted_message)

    # Step 4: Decrypt the message back to its original form
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print("Decrypted message:", decrypted_message)

    # Step 5: Sign the original message (Integrity)
    signature = sign_message(private_key, original_message)
    print("Signature created:", signature)

    # Step 6: Verify the signature to ensure the message hasn't been altered
    is_valid = verify_signature(public_key, original_message, signature)
    print("Is the signature valid?", is_valid)

    # Check integrity by altering the message
    altered_message = b"This is an altered message."
    is_valid_altered = verify_signature(public_key, altered_message, signature)
    print("Is the signature valid for altered message?", is_valid_altered)
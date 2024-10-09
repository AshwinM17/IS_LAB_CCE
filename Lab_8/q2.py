import phe as paillier
from collections import defaultdict

documents = [
    "The quick brown fox jumps over the lazy dog",
    "Symmetric encryption ensures confidentiality",
    "Searchable hehehe enables search over encrypted data",
    "Data privacy is important in modern applications",
    "Encryption and decryption are key operations in cryptography",
    "The quick brown fox likes running",
    "Confidentiality, integrity, and availability are pillars of security",
    "Cloud storage often employs encryption for data protection",
    "Machine learning and data science often require large datasets",
    "Secure data management is a key concern in the digital age"
]

# Generate Paillier keypair
public_key, private_key = paillier.generate_paillier_keypair()

# Function to encrypt data using the Paillier public key
def encrypt_number(public_key, number):
    return public_key.encrypt(number)

# Function to decrypt data using the Paillier private key
def decrypt_number(private_key, encrypted_number):
    return private_key.decrypt(encrypted_number)

# Build an inverted index
inverted_index = defaultdict(list)

for doc_id, document in enumerate(documents):
    words = set(document.lower().split())  # Create a set to avoid duplicate words in the same doc
    for word in words:
        inverted_index[word].append(doc_id)

# Encrypt the index: Encrypt document IDs using Paillier
encrypted_inverted_index = {
    word: [encrypt_number(public_key, doc_id) for doc_id in doc_ids]
    for word, doc_ids in inverted_index.items()
}

# Search for a word in the encrypted index
def search_encrypted_index(query, encrypted_index, private_key):
    query = query.lower()
    
    # If the word exists in the index, retrieve encrypted document IDs
    if query in encrypted_index:
        encrypted_doc_ids = encrypted_index[query]
        
        # Decrypt the document IDs using the private key
        decrypted_doc_ids = [decrypt_number(private_key, enc_doc_id) for enc_doc_id in encrypted_doc_ids]
        return decrypted_doc_ids
    else:
        return []

# Search for a word
query = "encryption"
search_results = search_encrypted_index(query, encrypted_inverted_index, private_key)
print("Search Results:", search_results)
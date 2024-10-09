from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

documents = [
    "The quick brown fox jumps over the lazy dog",
    "Symmetric encryption ensures confidentiality",
    "Searchable encryption enables search over encrypted data",
    "Data privacy is important in modern applications",
    "Encryption and decryption are key operations in cryptography",
    "The quick brown fox likes running",
    "Confidentiality, integrity, and availability are pillars of security",
    "Cloud storage often employs encryption for data protection",
    "Machine learning and data science often require large datasets",
    "Secure data management is a key concern in the digital age"
]

# Define a fixed IV for encrypting index words and search queries
FIXED_IV = b'16_byte_fixed_iv'

# Function to encrypt text with a fixed IV
def encrypt_text_fixed_iv(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(FIXED_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext

# Function to decrypt text with a fixed IV
def decrypt_text_fixed_iv(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(FIXED_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

from collections import defaultdict

# Build an inverted index
inverted_index = defaultdict(list)

for doc_id, document in enumerate(documents):
    words = set(document.lower().split())
    for word in words:
        inverted_index[word].append(doc_id)

# Encrypt the index using the fixed IV encryption function
encrypted_inverted_index = {encrypt_text_fixed_iv(key, word): [doc_id for doc_id in doc_ids]
                            for word, doc_ids in inverted_index.items()}

# Function to search for a word in the encrypted index
def search_encrypted_index(query, key, encrypted_index, documents):
    encrypted_query = encrypt_text_fixed_iv(key, query.lower())
    
    # Search for matching terms in the encrypted index
    results = []
    for encrypted_word, doc_ids in encrypted_index.items():
        if encrypted_word == encrypted_query:
            for doc_id in doc_ids:
                results.append(documents[doc_id])
            break

    return results

# Search for a word
query = "encryption"
search_results = search_encrypted_index(query, key, encrypted_inverted_index, documents)
print("Search Results:", search_results)
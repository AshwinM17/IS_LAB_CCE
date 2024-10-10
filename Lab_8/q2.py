import hashlib
from phe import paillier
from collections import defaultdict

# 2a. Generate text corpus
documents = [
    "The wind howled through the empty streets on a cold evening.",
    "An orange cat sat silently under the oak tree, watching the world.",
    "Quantum computing may revolutionize cryptographic systems.",
    "Bright colors danced across the sky during the sunset .",
    "The spaceship drifted silently through the vast emptiness of space.",
    "Baking a cake requires precision and patience for the best results.",
    "The ancient ruins held secrets that no one had yet uncovered.",
    "Robots are becoming an essential part of modern manufacturing.",
    "A mysterious note was left on the doorstep in the dead of night.",
    "The evolution of technology is accelerating faster than ever before."
]


# 2b. Paillier Encryption and Decryption functions
# Generate Paillier keypair (public and private keys)
public_key, private_key = paillier.generate_paillier_keypair()


def word_to_hash(word):
    """Convert a word to a hash representation using SHA-256."""
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


def encrypt_ids(doc_ids, pub_key):
    """Encrypt document IDs using Paillier encryption."""
    return [pub_key.encrypt(doc_id) for doc_id in doc_ids]


def decrypt_ids(encrypted_doc_ids, priv_key):
    """Decrypt encrypted document IDs using Paillier decryption."""
    return [priv_key.decrypt(enc_id) for enc_id in encrypted_doc_ids]


# 2c. Create inverted index
def build_inverted_index(docs):
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            index[word_to_hash(word.lower())].append(doc_id)
    return index


# Encrypt the document IDs in the inverted index
def encrypt_inverted_index(index, pub_key):
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt_ids(doc_ids, pub_key)
    return encrypted_index


# 2d. Implement search function
def search(query, encrypted_index, priv_key, documents):
    query_hash = word_to_hash(query.lower())

    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        doc_ids = decrypt_ids(encrypted_doc_ids, priv_key)
        return [documents[doc_id] for doc_id in doc_ids]
    else:
        return []


# Main execution
if __name__ == "__main__":
    # Build and encrypt inverted index
    inverted_index = build_inverted_index(documents)
    encrypted_index = encrypt_inverted_index(inverted_index, public_key)

    # Take search query input
    query = input("Enter search query: ")
    results = search(query, encrypted_index, private_key, documents)

    # Display results
    if results:
        print("Documents matching query:")
        for result in results:
            print(result)
    else:
        print("No matching documents found.")
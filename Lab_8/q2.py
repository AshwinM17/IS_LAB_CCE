import hashlib
from phe import paillier
from collections import defaultdict

# 2a. Generate text corpus
# A list of 10 sample documents (text corpus) is created to simulate a collection of textual data.
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
# Generate Paillier keypair (public and private keys) for homomorphic encryption
public_key, private_key = paillier.generate_paillier_keypair()


def word_to_hash(word):
    """Convert a word to a hash representation using SHA-256.
    
    Args:
        word (str): The word to be hashed.
    
    Returns:
        str: The hashed representation of the word.
    """
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


def encrypt_ids(doc_ids, pub_key):
    """Encrypt document IDs using Paillier encryption.
    
    Args:
        doc_ids (list): List of document IDs to encrypt.
        pub_key (PaillierPublicKey): Public key used for encryption.
    
    Returns:
        list: Encrypted document IDs.
    """
    return [pub_key.encrypt(doc_id) for doc_id in doc_ids]


def decrypt_ids(encrypted_doc_ids, priv_key):
    """Decrypt encrypted document IDs using Paillier decryption.
    
    Args:
        encrypted_doc_ids (list): List of encrypted document IDs.
        priv_key (PaillierPrivateKey): Private key used for decryption.
    
    Returns:
        list: Decrypted document IDs.
    """
    return [priv_key.decrypt(enc_id) for enc_id in encrypted_doc_ids]


# 2c. Create inverted index
def build_inverted_index(docs):
    """Build an inverted index from the given documents.
    
    The inverted index maps hashed words to lists of document IDs where they occur.
    
    Args:
        docs (list): List of documents (strings).
    
    Returns:
        defaultdict: Inverted index mapping word hashes to lists of document IDs.
    """
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            index[word_to_hash(word.lower())].append(doc_id)
    return index


# Encrypt the document IDs in the inverted index
def encrypt_inverted_index(index, pub_key):
    """Encrypt the document IDs in the inverted index.
    
    Args:
        index (dict): Inverted index with word hashes as keys and lists of document IDs as values.
        pub_key (PaillierPublicKey): Public key used to encrypt document IDs.
    
    Returns:
        dict: Inverted index with encrypted document IDs.
    """
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt_ids(doc_ids, pub_key)#creates a dict with word_hash as key and the corresponding doc_ids as encrypted
    return encrypted_index


# 2d. Implement search function
def search(query, encrypted_index, priv_key, documents):
    """Search for documents that match the given query.
    
    Args:
        query (str): Search query (word).
        encrypted_index (dict): Encrypted inverted index.
        priv_key (PaillierPrivateKey): Private key to decrypt document IDs.
        documents (list): List of original documents (strings).
    
    Returns:
        list: List of documents that match the query.
    """
    query_hash = word_to_hash(query.lower())

    if query_hash in encrypted_index:
        # Retrieve encrypted document IDs that match the query
        encrypted_doc_ids = encrypted_index[query_hash]
        
        # Decrypt document IDs to get original document indices
        doc_ids = decrypt_ids(encrypted_doc_ids, priv_key)
        
        # Return matching documents based on decrypted document IDs
        return [documents[doc_id] for doc_id in doc_ids]
    else:
        # No match found for the query
        return []


# Main execution
if __name__ == "__main__":
    # Build the inverted index using the sample documents
    inverted_index = build_inverted_index(documents)
    
    # Encrypt the inverted index using the public key
    encrypted_index = encrypt_inverted_index(inverted_index, public_key)

    # Take search query input from the user
    query = input("Enter search query: ")
    
    # Search the encrypted index and retrieve matching documents
    results = search(query, encrypted_index, private_key, documents)

    # Display results
    if results:
        print("Documents matching query:")
        for result in results:
            print(result)
    else:
        print("No matching documents found.")

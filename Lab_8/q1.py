import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict

# 1a. Generate text corpus
# List of documents to serve as our searchable text corpus.
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


# Encryption & Decryption functions using AES
def get_aes_key():
    """Generate a deterministic AES key by hashing a password (or key) with SHA-256."""
    return hashlib.sha256(b"supersecretkey").digest()  # Using a fixed password for key generation


def encrypt(text, key):
    """Encrypt the given text using AES encryption in CBC mode with padding."""
    cipher = AES.new(key, AES.MODE_CBC)  # Create a new AES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))  # Encrypt the padded text
    return cipher.iv + ciphertext  # Return the IV concatenated with the ciphertext


def decrypt(ciphertext, key):
    """Decrypt the given AES-encrypted ciphertext."""
    iv = ciphertext[: AES.block_size]  # Extract the initialization vector (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Create a cipher using the IV
    decrypted = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)  # Decrypt and unpad the text
    return decrypted.decode("utf-8")  # Return the decrypted plaintext


# 1c. Create inverted index using word hashes
def build_inverted_index(docs):
    """Build an inverted index where words (hashed) map to document IDs."""
    index = defaultdict(list)  # Initialize a defaultdict to store word hashes and corresponding doc IDs
    for doc_id, doc in enumerate(docs):  # Iterate over each document and its ID
        for word in doc.split():  # Split the document into words
            word_hash = hashlib.sha256(word.lower().encode("utf-8")).hexdigest()  # Hash each word in lowercase
            index[word_hash].append(doc_id)  # Map the word hash to the document ID
    return index  # Return the inverted index


# Encrypt document IDs
def encrypt_inverted_index(index, key):
    """Encrypt the document IDs in the inverted index using AES."""
    encrypted_index = {}  # Initialize an empty dictionary for the encrypted index
    for word_hash, doc_ids in index.items():  # Iterate over each word hash and its list of document IDs
        encrypted_index[word_hash] = encrypt(",".join(map(str, doc_ids)), key)  # Encrypt the list of doc IDs
    return encrypted_index  # Return the encrypted inverted index


# Decrypt inverted index results
def decrypt_inverted_index_results(encrypted_doc_ids, key):
    """Decrypt the encrypted document IDs and return them as a list of integers."""
    decrypted_doc_ids = decrypt(encrypted_doc_ids, key)  # Decrypt the ciphertext
    return list(map(int, decrypted_doc_ids.split(",")))  # Convert the decrypted string back to a list of integers


# 1d. Implement search function
def search(query, encrypted_index, key, documents):
    """Search for a query in the encrypted inverted index and return matching documents."""
    # Hash the search query (instead of encrypting) to find the corresponding word in the index
    query_hash = hashlib.sha256(query.lower().encode("utf-8")).hexdigest()  # Hash the query in lowercase
    if query_hash in encrypted_index:  # If the query hash exists in the encrypted index
        encrypted_doc_ids = encrypted_index[query_hash]  # Get the encrypted document IDs for the query
        doc_ids = decrypt_inverted_index_results(encrypted_doc_ids, key)  # Decrypt the document IDs
        return [documents[doc_id] for doc_id in doc_ids]  # Return the documents matching the document IDs
    else:
        return []  # Return an empty list if no matches are found


# Main execution block
if __name__ == "__main__":
    # Generate AES key
    aes_key = get_aes_key()  # Generate a deterministic AES key using SHA-256

    # Build and encrypt inverted index
    inverted_index = build_inverted_index(documents)  # Build the inverted index using word hashes
    encrypted_index = encrypt_inverted_index(inverted_index, aes_key)  # Encrypt the inverted index using AES

    # Take search query input and search
    query = input("Enter search query: ")  # Get search query from the user
    results = search(query, encrypted_index, aes_key, documents)  # Search the encrypted index for matching documents

    # Display results
    if results:  # If there are matching documents
        print("Documents matching query:")  # Print a header
        for result in results:  # Iterate over matching documents
            print(result)  # Print each matching document
    else:
        print("No matching documents found.")  # Print message if no documents are found

'''
Enter search query: sunset
Documents matching query:
Bright colors danced across the sky during the sunset .
'''

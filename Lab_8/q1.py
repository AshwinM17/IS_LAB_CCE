import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from collections import defaultdict

# 1a. Generate text corpus
documents = [
    "the quick brown fox jumps over the lazy dog",
    "never gonna give you up never gonna let you down",
    "this is a test document for secure search engine",
    "data science is an inter-disciplinary field",
    "machine learning is a subset of artificial intelligence",
    "deep learning is a branch of machine learning",
    "natural language processing is a fascinating field",
    "this document contains various topics on AI",
    "cryptography is essential for secure communication",
    "secure search engines protect user privacy"
]

# Encryption & Decryption functions using AES
def get_aes_key():
    """Generate a random AES key."""
    return hashlib.sha256(b"supersecretkey").digest()


def encrypt(text, key):
    """Encrypt text using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def decrypt(ciphertext, key):
    """Decrypt ciphertext using AES."""
    iv = ciphertext[: AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[AES.block_size :]), AES.block_size)
    return decrypted.decode("utf-8")


# 1c. Create inverted index using word hashes
def build_inverted_index(docs):
    index = defaultdict(list)
    for doc_id, doc in enumerate(docs):
        for word in doc.split():
            word_hash = hashlib.sha256(word.lower().encode("utf-8")).hexdigest()
            index[word_hash].append(doc_id)
    return index


# Encrypt document IDs
def encrypt_inverted_index(index, key):
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[word_hash] = encrypt(",".join(map(str, doc_ids)), key)
    return encrypted_index


# Decrypt inverted index results
def decrypt_inverted_index_results(encrypted_doc_ids, key):
    decrypted_doc_ids = decrypt(encrypted_doc_ids, key)
    return list(map(int, decrypted_doc_ids.split(",")))


# 1d. Implement search function
def search(query, encrypted_index, key, documents):
    # Hash the query instead of encrypting
    query_hash = hashlib.sha256(query.lower().encode("utf-8")).hexdigest()
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        doc_ids = decrypt_inverted_index_results(encrypted_doc_ids, key)
        return [documents[doc_id] for doc_id in doc_ids]
    else:
        return []


# Main execution
if __name__ == "__main__":
    # Generate AES key
    aes_key = get_aes_key()

    # Build and encrypt inverted index
    inverted_index = build_inverted_index(documents)
    encrypted_index = encrypt_inverted_index(inverted_index, aes_key)

    # Take search query input and search
    query = input("Enter search query: ")
    results = search(query, encrypted_index, aes_key, documents)

    # Display results
    if results:
        print("Documents matching query:")
        for result in results:
            print(result)
    else:
        print("No matching documents found.")
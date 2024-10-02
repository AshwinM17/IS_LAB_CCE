from collections import defaultdict
from phe import paillier

documents = [
    "The quick brown fox jumps over the lazy dog",
    "Hello world this is a test document",
    "Secure search is essential for privacy",
    "We need to encrypt the search index",
    "Document retrieval should be efficient",
    "The fox is quick and the dog is lazy",
    "Encryption algorithms keep data safe",
    "Search queries should be handled securely",
    "Data privacy is a growing concern",
    "Efficient search can be implemented with indices"
]

# Print the documents
for i, doc in enumerate(documents):
    print(f"Document {i}: {doc}")



# Generate Paillier keys
public_key, private_key = paillier.generate_paillier_keypair()

def encrypt_paillier(value, pub_key):
    return pub_key.encrypt(value)

def decrypt_paillier(encrypted_value, priv_key):
    return priv_key.decrypt(encrypted_value)

# Example usage
value = 42
encrypted_value = encrypt_paillier(value, public_key)
decrypted_value = decrypt_paillier(encrypted_value, private_key)

print(f"Value: {value}")
print(f"Encrypted value: {encrypted_value}")
print(f"Decrypted value: {decrypted_value}")


def build_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in enumerate(docs):
        for word in text.lower().split():
            index[word].add(doc_id)
    return index

def encrypt_index(index, pub_key):
    encrypted_index = {}
    for word, doc_ids in index.items():
        encrypted_word = encrypt_paillier(len(word), pub_key)  # Encrypt word length as a placeholder
        encrypted_doc_ids = {encrypt_paillier(doc_id, pub_key) for doc_id in doc_ids}
        encrypted_index[encrypted_word] = encrypted_doc_ids
    return encrypted_index

# Build and encrypt the inverted index
index = build_inverted_index(documents)
encrypted_index = encrypt_index(index, public_key)
print(f"Encrypted index: {encrypted_index}")

def search_query(query, encrypted_index, pub_key, priv_key):
    encrypted_query_length = encrypt_paillier(len(query), pub_key)
    decrypted_results = set()

    for encrypted_word, encrypted_doc_ids in encrypted_index.items():
        if decrypt_paillier(encrypt_paillier(len(query), pub_key), priv_key) == decrypt_paillier(encrypted_word,
                                                                                                     priv_key):
            for encrypted_doc_id in encrypted_doc_ids:
                decrypted_doc_id = decrypt_paillier(encrypted_doc_id, priv_key)
                decrypted_results.add(int(decrypted_doc_id))

    return decrypted_results

query = "quick"
search_results = search_query(query, encrypted_index, public_key, private_key)

print(f"Search results for '{query}': {search_results}")
for doc_id in search_results:
    print(f"Document {doc_id}: {documents[doc_id]}")
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from collections import defaultdict

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


def generate_key():
    return get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV to the ciphertext

def decrypt_aes(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# Example usage
key = generate_key()
plaintext = "Hello, world!"
ciphertext = encrypt_aes(plaintext, key)
decrypted = decrypt_aes(ciphertext, key)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {decrypted}")



def build_inverted_index(docs):
    index = defaultdict(set)
    for doc_id, text in enumerate(docs):
        for word in text.lower().split():
            index[word].add(doc_id)
    return index

def encrypt_index(index, key):
    encrypted_index = {}
    for word, doc_ids in index.items():
        encrypted_word = encrypt_aes(word, key)
        encrypted_doc_ids = {encrypt_aes(str(doc_id), key) for doc_id in doc_ids}
        encrypted_index[encrypted_word] = encrypted_doc_ids
    return encrypted_index

index = build_inverted_index(documents)
encrypted_index = encrypt_index(index, key)
print(f"Encrypted index: {encrypted_index}")

def search_query(query, encrypted_index, key):
    encrypted_query = encrypt_aes(query, key)
    decrypted_results = set()
    for encrypted_word, encrypted_doc_ids in encrypted_index.items():
        if encrypted_query == encrypted_word:
            for encrypted_doc_id in encrypted_doc_ids:
                decrypted_doc_id = decrypt_aes(encrypted_doc_id, key)
                decrypted_results.add(int(decrypted_doc_id))
    return decrypted_results

query = "quick"
search_results = search_query(query, encrypted_index, key)

print(f"Search results for '{query}': {search_results}")
for doc_id in search_results:
    print(f"Document {doc_id}: {documents[doc_id]}")
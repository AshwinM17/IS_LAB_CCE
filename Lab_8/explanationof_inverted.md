```
The inverted index is a data structure that allows for efficient full-text search by mapping words to the documents in which they appear. Here's a breakdown of how the inverted_index in your code works:

Steps for Building the Inverted Index
Iterating Over Documents:

The function build_inverted_index(docs) takes a list of documents (which are strings of text) as input.
It assigns a unique doc_id (integer) to each document by iterating over the list of documents using enumerate(docs). Each doc_id corresponds to the index of the document in the list.
Splitting Documents into Words:

For each document, the function splits the text into individual words using doc.split(). This generates a list of words for that document.
Hashing Words:

Each word in the document is hashed using hashlib.sha256. The reason for hashing the words is to protect their original form (perhaps for privacy, in case of sensitive data).
The hashing process:
Converts the word to lowercase (using word.lower()) to ensure that the search is case-insensitive.
Encodes the word in UTF-8 and then hashes it using SHA-256 to generate a fixed-length unique string (digest) that represents the word.
The output of this is a 64-character hexadecimal string.
Mapping Words to Document IDs:

The word hash is used as a key in a dictionary (index). The corresponding value is a list of doc_ids, i.e., the indices of documents where that word appears.
If the same word appears in multiple documents, the doc_id is appended to the list. This makes it an inverted index because instead of mapping documents to words, it maps words (hashed) to the documents in which they are found.
Example of How It Works
Let’s break down an example to clarify how the inverted index is built:
```
```
Given Document List
python
Copy code
documents = [
    "The wind howled through the empty streets on a cold evening.",
    "Bright colors danced across the sky during the sunset."
]
Step 1: Processing the First Document
For the first document "The wind howled through the empty streets on a cold evening." with doc_id = 0:
```
```
Split the document into words:
python
Copy code
['The', 'wind', 'howled', 'through', 'the', 'empty', 'streets', 'on', 'a', 'cold', 'evening.']
For each word, compute its hash:
python
Copy code
'the'  -> 'b94d27b9934d3e08a52e52d7da7dabfa935ff7f73c928547a2e1593c79bde3eb'  # 'the' appears twice
'wind' -> 'fa9b1a83200a606655a25f4e0d317e29392d4cf37e60b8d0cadd706960d50d63'
'howled' -> '8b7a7d7e084805fa4ddf4ddc98783e0224cc2956cfa68a376b63c6fc6b0cfb26'
These word hashes are stored as keys in the inverted index, with the doc_id (0) as their value:
python
Copy code
{
    'b94d27b9934d3e08a52e52d7da7dabfa935ff7f73c928547a2e1593c79bde3eb': [0],  # 'the'
    'fa9b1a83200a606655a25f4e0d317e29392d4cf37e60b8d0cadd706960d50d63': [0],  # 'wind'
    '8b7a7d7e084805fa4ddf4ddc98783e0224cc2956cfa68a376b63c6fc6b0cfb26': [0],  # 'howled'
    ...
}
```
```
Step 2: Processing the Second Document
For the second document "Bright colors danced across the sky during the sunset." with doc_id = 1:

Split the document into words:
python
Copy code
['Bright', 'colors', 'danced', 'across', 'the', 'sky', 'during', 'the', 'sunset.']
Each word is hashed:
python
Copy code
'bright' -> 'd68c19d69a76847b74902b55e8e407d4d412c168059b3dd178d084a67913ef91'
'colors' -> 'd601136ac6ae3833d8711e9d055a3d2b7e4aa40fc31bcbff999ccfc6e1ed77ed'
These word hashes are added to the inverted index. If a word hash already exists (e.g., "the"), its doc_id (1) is appended to the existing list:
python
Copy code
{
    'b94d27b9934d3e08a52e52d7da7dabfa935ff7f73c928547a2e1593c79bde3eb': [0, 1],  # 'the'
    'fa9b1a83200a606655a25f4e0d317e29392d4cf37e60b8d0cadd706960d50d63': [0],  # 'wind'
    '8b7a7d7e084805fa4ddf4ddc98783e0224cc2956cfa68a376b63c6fc6b0cfb26': [0],  # 'howled'
    'd68c19d69a76847b74902b55e8e407d4d412c168059b3dd178d084a67913ef91': [1],  # 'bright'
    ...
}
```
```
How It’s Used in Search
Once the inverted index is built, the search process works as follows:

Hashing the Query:

When the user inputs a search query, the query is hashed in the same way as the words in the documents were hashed.
Finding Matching Documents:

The system checks if the hash of the search query exists in the inverted index. If it does, it retrieves the list of doc_ids (the documents in which the query word appears).
Returning Results:

The system then uses these doc_ids to retrieve the corresponding documents from the list and returns them to the user.
Summary of the Inverted Index
Key: A hashed word (e.g., SHA-256 hash of "the").
Value: A list of doc_ids (the IDs of documents where the word appears).
This allows fast lookups when searching for a word, as you can directly find the documents that contain that word by looking up its hash.
The inverted index enables quick and efficient searching, especially when dealing with large text corpora, and the use of hashing adds a layer of privacy to the indexed data.
```

    Summary of What’s Stored:
    Keys: Word hashes (SHA-256 hash of each word in the document).
    Values: AES-encrypted document IDs (the IDs of documents where the word appears, encrypted for security).
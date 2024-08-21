# Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The 
# secret key can be made by filling the first and part of the second row with the word 
# "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet

def create_playfair_matrix(key):
    # Remove duplicates from key and create the matrix with the remaining alphabet
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    key = "".join(sorted(set(key), key=key.index))
    
    for char in key:
        if char not in matrix:
            matrix.append(char)
    
    for char in alphabet:
        if char not in matrix:
            matrix.append(char)
    
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

def playfair_encipher(pair, matrix):
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    if r1 == r2:
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
    elif c1 == c2:
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
    else:
        return matrix[r1][c2] + matrix[r2][c1]

def prepare_text(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    prepared_text = ""
    
    i = 0
    while i < len(text):
        prepared_text += text[i]
        if i + 1 < len(text) and text[i] == text[i + 1]:
            prepared_text += 'X'
            i += 1
        else:
            if i + 1 < len(text):
                prepared_text += text[i + 1]
            i += 2
    
    if len(prepared_text) % 2 != 0:
        prepared_text += 'X'
    
    return prepared_text

def playfair_cipher(text, key):
    matrix = create_playfair_matrix(key)
    prepared_text = prepare_text(text)
    ciphertext = ""
    
    for i in range(0, len(prepared_text), 2):
        ciphertext += playfair_encipher(prepared_text[i:i + 2], matrix)
    
    return ciphertext

# Input
text = "The key is hidden under the door pad"
key = "GUIDANCE"

# Encipher the text
ciphertext = playfair_cipher(text, key)
print("Ciphertext:", ciphertext)

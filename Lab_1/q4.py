import numpy as np

def hill_cipher_encrypt(message, key_matrix):
    message = message.replace(" ", "").lower()
    
    if len(message) % 2 != 0:
        message += 'x'
    
    message_numbers = [ord(char) - ord('a') for char in message]
    
    encrypted_message = ""
    
    for i in range(0, len(message_numbers), 2):
        pair_vector = np.array([[message_numbers[i]], [message_numbers[i+1]]])
        encrypted_vector = np.dot(key_matrix, pair_vector) % 26
        encrypted_message += chr(encrypted_vector[0, 0] + ord('a'))
        encrypted_message += chr(encrypted_vector[1, 0] + ord('a'))
    
    return encrypted_message

key_matrix = np.array([[3, 3], [2, 7]])

message = "We live in an insecure world"

encrypted_message = hill_cipher_encrypt(message, key_matrix)
print("\nEncrypted Message:", encrypted_message)
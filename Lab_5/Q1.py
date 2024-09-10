# Implement the hash function in Python. Your function should start with 
# an initial hash value of 5381 and for each character in the input string, 
# multiply the current hash value by 33, add the ASCII value of the 
# character, and use bitwise operations to ensure thorough mixing of the 
# bits. Finally, ensure the hash value is kept within a 32-bit range by 
# applying an appropriate mask

def custom_hash(input_string):
    # Initialize the hash value
    hash_value = 5381
    # Iterate through each character in the input string
    for char in input_string:
        
        # Multiply the current hash value by 33
        hash_value = (hash_value * 33) & 0xFFFFFFFF  # Ensure 32-bit range
    
        # Add the ASCII value of the character
        hash_value += ord(char)
        
        # Ensure thorough mixing of the bits (optional bitwise operation)
        hash_value ^= (hash_value >> 5)
        hash_value = (hash_value) & 0xFFFFFFFF
    
    return hash_value

# Example usage
input_str = "hello"
result = custom_hash(input_str)
print(f"Hash value for '{input_str}': {result}")
'''
Hash value for 'hello': 1032782281
'''
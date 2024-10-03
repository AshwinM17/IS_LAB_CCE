import socket

def hash_function(input_string):
    """
    A simple hash function implementing the DJB2 algorithm.
    
    Args:
        input_string (str): The string to be hashed.

    Returns:
        int: The resulting hash value.
    """
    hash_value = 5381  # Initial hash value (starting point)

    # Iterate over each character in the input string
    for char in input_string:
        # Update the hash value using the current character's ASCII value
        # and the previous hash value
        hash_value = (hash_value * 33 + ord(char)) & 0xFFFFFFFF  # Keep it within 32 bits

    return hash_value  # Return the final hash value

def client_program():
    """
    Client program that connects to a server, sends a message, and verifies data integrity using hashing.
    """
    host = '127.0.0.1'  # Localhost address
    port = 65432  # Port number to connect to the server
    
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server using the specified host and port
    client_socket.connect((host, port))
    
    message = "Hello, Server! This is a test message."  # Message to be sent to the server
    
    # Send the encoded message to the server(string to bytes)
    client_socket.send(message.encode())
    
    # Receive a response from the server (up to 1024 bytes)
    response = client_socket.recv(1024).decode()
    
    # Split the response into data and received hash
    data, received_hash = response.split('\n')
    received_hash = int(received_hash)  # Convert the received hash to an integer
    
    # Print the received data and hash
    print(f"Received from server: {data}")
    print(f"Received hash: {received_hash}")
    
    # Compute the hash of the received data
    computed_hash = hash_function(data)
    print(f"Computed hash: {computed_hash}")
    
    # Compare received hash with computed hash to verify data integrity
    if received_hash == computed_hash:
        print("Data integrity verified. No corruption detected.")
    else:
        print("Data corruption detected. Hashes do not match.")

    client_socket.close()  # Close the socket connection

if __name__ == "__main__":
    client_program()  # Run the client program
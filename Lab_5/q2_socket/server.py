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

def server_program():
    """
    Server program that listens for incoming connections, receives messages,
    computes their hash, and sends back the original message along with the hash.
    """
    host = '127.0.0.1'  # Localhost address to bind the server
    port = 65432  # Port number to listen for incoming connections
    
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to the specified host and port
    server_socket.bind((host, port))
    
    # Start listening for incoming connections (maximum 1 connection at a time)
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")
    
    # Accept a connection from a client
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")
    
    while True:
        # Receive data from the client (up to 1024 bytes)
        data = conn.recv(1024).decode()
        if not data:
            break  # Exit the loop if no data is received
        
        print(f"Received data: {data}")
        
        # Compute the hash of the received data
        data_hash = hash_function(data)
        print(f"Computed hash: {data_hash}")
        
        # Prepare the response with the original data and the computed hash
        response = f"{data}\n{data_hash}"
        
        # Send the response back to the client
        conn.send(response.encode())

    # Close the connection when done
    conn.close()

if __name__ == "__main__":
    server_program()  # Run the server program
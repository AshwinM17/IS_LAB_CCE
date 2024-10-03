import socket
import hashlib

def compute_sha256(s):
    """Compute the SHA-256 hash of a given string."""
    return hashlib.sha256(s.encode()).hexdigest()

def client_program():
    host = '127.0.0.1'  # Server IP address
    port = 65432        # Server port
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))  # Connect to the server

    # Define the message to be sent in parts
    original_message = "Hello, this is a message sent in multiple parts."
    message_parts = [original_message[i:i+10] for i in range(0, len(original_message), 10)]  # Split into parts
    
    # Send each part to the server
    for part in message_parts:
        print(f"Sending part: {part}")
        client_socket.send(part.encode())  # Send part to the server

    client_socket.send(b'xxxx')  # Send an specific message to indicate completion

    # Receive the hash from the server
    received_hash = client_socket.recv(1024).decode()
    print(f"Received hash from server: {received_hash}")

    # Compute the hash of the original message
    computed_hash = compute_sha256(original_message)
    print(f"Computed hash of original message: {computed_hash}")

    # Verify the integrity of the message
    if received_hash == computed_hash:
        print("Data integrity verified. No corruption detected.")
    else:
        print("Data corruption detected. Hashes do not match.")

    client_socket.close()

if __name__ == "__main__":
    client_program()  # Run the client program
import socket
import hashlib

def compute_sha256(s):
    """Compute the SHA-256 hash of a given string."""
    return hashlib.sha256(s.encode()).hexdigest()

def server_program():
    host = '127.0.0.1'  # Server IP address
    port = 65432        # Server port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")
    
    conn, addr = server_socket.accept()  # Accept client connection
    print(f"Connection from {addr}")
    
    complete_message = ""
    while True:
        data = conn.recv(1024).decode()  # Receive data from the client
        if not data or data=='xxxx':  # Break if no data is received
            break
        print(f"Received part: {data}")
        complete_message += data  # Reassemble the message

    print(f"Complete message received: {complete_message}")
    
    # Compute the hash of the reassembled message
    message_hash = compute_sha256(complete_message)
    print(f"Computed hash: {message_hash}")
    
    # Send the hash back to the client
    conn.send(message_hash.encode())
    conn.close()

if __name__ == "__main__":
    server_program()  # Run the server program
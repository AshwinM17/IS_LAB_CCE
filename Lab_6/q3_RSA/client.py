from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import socket

def verify_signature(public_key, message, signature):
    try:
        # Verify the signature
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", e)

def main():
    # Step 1: Create a socket to connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 65432))  # Connect to the server
        data = client_socket.recv(4096)  # Receive data from the server

    # Split the received data into public key and signature
    public_key_pem, signature = data.rsplit(b'\n', 1)

    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Define the original message
    message = b"Server's response to the client's request"

    # Step 2: Verify the signature
    verify_signature(public_key, message, signature)

if __name__ == "__main__":
    main()
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import socket

def generate_rsa_key_pair():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, private_pem, public_pem

def sign_message(private_key, message):
    # Sign the message using the private key
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def main():
    # Step 1: Generate RSA key pair
    private_key, private_key_pem, public_key_pem = generate_rsa_key_pair()
    print("Keys generated.")

    # Step 2: Define the message
    message = b"Server's response to the client's request"

    # Step 3: Sign the message
    signature = sign_message(private_key, message)
    print("Message signed.")

    # Step 4: Create a socket and send the signed message and public key to the client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 65432))  # Bind to localhost on port 65432
        server_socket.listen()
        print("Server is listening for connections...")

        conn, addr = server_socket.accept()
        with conn:
            print('Connected by', addr)
            # Send the public key and signature
            conn.sendall(public_key_pem + b"\n" + signature)

if __name__ == "__main__":
    main()
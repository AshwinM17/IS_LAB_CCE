from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Server loads the private key and signs a message
def sign_message(private_key_path, message):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Sign the message
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


if __name__ == "__main__":
    message = b"Server's response to the client's request"
    signature = sign_message("private_key.pem", message)
    print("Message signed.")
    print("Signature:", signature.hex())

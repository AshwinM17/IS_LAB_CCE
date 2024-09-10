from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Client loads the public key and verifies the signature
def verify_signature(public_key_path, message, signature):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
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


if __name__ == "__main__":
    message = b"Server's response to the client's request"
    # Signature received from the server (you'd use the real one in a real scenario)
    signature = bytes.fromhex(input("Enter the server's signature (in hex): "))
    verify_signature("public_key.pem", message, signature)

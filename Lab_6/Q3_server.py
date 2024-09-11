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
'''
Message signed.
Signature: 64b856e0d843e15cb7e7d8a917c60ea8ab3a7f57044af0caad0217bacb796329aa962bae2c6c6d383b5f02879ab7933494f7629ef157812322dda2e7c0df5196cf046011eaf9e0cb3648745334866f41e3547c233dbf0f78e8435e367838aa4545c02b445afcf264106ddda98240658fa03a765c02a54c3bd9c2294b48fd4073c291326c39cfb38d36f8bb5e7b64e56ce8696b81598d869c6272cba6d074346399cf030642d0a1d612350d1e6e2b78767d077f567b00d2a69c7196137742a9cb9251b9537b7f33e201aa75c273270b24a620e3066b1a50d09bd70763b92d28d900391688b237401546123fce0cc75b55d95b8e35ef138717efbe7e9965a24099
'''
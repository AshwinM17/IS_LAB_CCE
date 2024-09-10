import socket


def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = (hash_value * 33) + ord(char)
        hash_value = hash_value ^ ((hash_value >> 16) & 0xFFFFFFFF)
    return hash_value & 0xFFFFFFFF


def start_client():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        data_to_send = input("Enter Message : ")
        print(f"Sending data: {data_to_send}")

        client_socket.sendall(data_to_send.encode('utf-8'))

        local_hash = custom_hash(data_to_send)
        print(f"Local hash: {local_hash}")

        received_hash = int(client_socket.recv(1024).decode('utf-8'))
        print(f"Received hash from server: {received_hash}")

        if local_hash == received_hash:
            print("Data integrity verified: No corruption or tampering detected.")
        else:
            print("Data integrity verification failed: Corruption or tampering detected!")


if __name__ == "__main__":
    start_client()

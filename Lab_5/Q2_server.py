import socket

def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = (hash_value * 33) + ord(char)
        hash_value = hash_value ^ ((hash_value >> 16) & 0xFFFFFFFF)
    return hash_value & 0xFFFFFFFF


def start_server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print("Server is listening...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")

            data = conn.recv(1024).decode('utf-8')
            if not data:
                return

            print(f"Received data: {data}")

            received_hash = custom_hash(data)
            print(f"Computed hash: {received_hash}")

            conn.sendall(str(received_hash).encode('utf-8'))


if __name__ == "__main__":
    start_server()

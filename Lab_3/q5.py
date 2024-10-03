from Crypto.Random import random  # Import random for generating secure random numbers
import time  # Import time for measuring performance

# Define parameters for the DSA key generation(to create keys fow which we will perform diffie helleman)
# p is a large prime number
p = int('0xB10B8F96A080E01DE7B9CBE6B86A2A33'
        '8C1F3C2E1F00B03A6C1C4A64B92D90C4'
        'A8323512CD225E1A91D3A26755E59D6E'
        'F9E4551AEF8765363458D647D148D479'
        '545AA381C37A35D93F0BFB3EC0C6B47B'
        '940670BB2D91B24BFFD9841F1E229149'
        '23B9AFA8E827C9EBC7206CF94CFF2DAE'
        'A2A14720C071DFDD88D47FCA9F1F4359', 16)  # Hexadecimal to integer conversion

g = 2  # Base generator for the group (commonly a small integer)

# Measure the time taken to generate private keys
start_time = time.time()  # Start timer
# Generate random private keys for both parties, A and B
private_key_A = random.StrongRandom().randint(2, p-2)  # Private key A must be in the range [2, p-2]
private_key_B = random.StrongRandom().randint(2, p-2)  # Private key B must be in the range [2, p-2]
key_generation_time = time.time() - start_time  # Calculate the time taken for key generation

# Measure the time taken to generate public keys
start_time = time.time()  # Start timer
# Compute public keys based on private keys and parameters p and g
public_key_A = pow(g, private_key_A, p)  # Public key A = g^private_key_A mod p
public_key_B = pow(g, private_key_B, p)  # Public key B = g^private_key_B mod p
public_key_generation_time = time.time() - start_time  # Calculate the time taken for public key generation

# Measure the time taken for key exchange from Peer A's perspective
start_time = time.time()  # Start timer
# Calculate the shared secret from Peer A's perspective
shared_secret_A = pow(public_key_B, private_key_A, p)  # Shared secret A = public_key_B^private_key_A mod p
key_exchange_time_A = time.time() - start_time  # Calculate the time taken for key exchange for Peer A

# Measure the time taken for key exchange from Peer B's perspective
start_time = time.time()  # Start timer
# Calculate the shared secret from Peer B's perspective
shared_secret_B = pow(public_key_A, private_key_B, p)  # Shared secret B = public_key_A^private_key_B mod p
key_exchange_time_B = time.time() - start_time  # Calculate the time taken for key exchange for Peer B

# Print the timing results for each operation
print(f"Key Generation Time: {key_generation_time:.4f} seconds")  # Time taken to generate private keys
print(f"Public Key Generation Time: {public_key_generation_time:.4f} seconds")  # Time taken to generate public keys
print(f"Key Exchange Time (Peer A): {key_exchange_time_A:.4f} seconds")  # Time taken for key exchange by Peer A
print(f"Key Exchange Time (Peer B): {key_exchange_time_B:.4f} seconds")  # Time taken for key exchange by Peer B
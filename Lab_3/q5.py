from Crypto.PublicKey import DSA
from Crypto.Random import random
import time

p = int('0xB10B8F96A080E01DE7B9CBE6B86A2A33'
        '8C1F3C2E1F00B03A6C1C4A64B92D90C4'
        'A8323512CD225E1A91D3A26755E59D6E'
        'F9E4551AEF8765363458D647D148D479'
        '545AA381C37A35D93F0BFB3EC0C6B47B'
        '940670BB2D91B24BFFD9841F1E229149'
        '23B9AFA8E827C9EBC7206CF94CFF2DAE'
        'A2A14720C071DFDD88D47FCA9F1F4359', 16)
g = 2 

start_time = time.time()
private_key_A = random.StrongRandom().randint(2, p-2)
private_key_B = random.StrongRandom().randint(2, p-2)
key_generation_time = time.time() - start_time

start_time = time.time()
public_key_A = pow(g, private_key_A, p)
public_key_B = pow(g, private_key_B, p)
public_key_generation_time = time.time() - start_time

start_time = time.time()
shared_secret_A = pow(public_key_B, private_key_A, p)
key_exchange_time_A = time.time() - start_time

start_time = time.time()
shared_secret_B = pow(public_key_A, private_key_B, p)
key_exchange_time_B = time.time() - start_time

print(f"Key Generation Time: {key_generation_time:.4f} seconds")
print(f"Public Key Generation Time: {public_key_generation_time:.4f} seconds")
print(f"Key Exchange Time (Peer A): {key_exchange_time_A:.4f} seconds")
print(f"Key Exchange Time (Peer B): {key_exchange_time_B:.4f} seconds")
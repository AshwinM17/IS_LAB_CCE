from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

BLOCK_SIZE = 16

def aes_192_encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_msg = pad(msg.encode('utf-8'), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_msg)
    return ciphertext

def aes_192_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, BLOCK_SIZE).decode('utf-8')
    return plaintext

key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210" 
key = binascii.unhexlify(key_hex)
message = "Top Secret Data"

ciphertext = aes_192_encrypt(message, key)
print(f'Ciphertext (hex): {ciphertext.hex()}')

plaintext = aes_192_decrypt(ciphertext, key)
print(f'Plaintext: {plaintext}')

# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import binascii

# # Key (24 bytes / 192 bits for AES-192)
# key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"  # 48 hex characters = 24 bytes
# key = binascii.unhexlify(key_hex)
# message = "Top Secret Data"

# # AES block size
# BLOCK_SIZE = 16

# # Key Expansion (simplified)
# def key_expansion(key):
#     # AES-192 key expansion would normally generate 13 round keys
#     round_keys = [key]  # Initial key as the first round key
#     for i in range(12):
#         # Simplified example: In practice, this involves the key schedule steps
#         round_keys.append(b''.join([bytes([b ^ (i + 1)]) for b in key]))  # Illustrative only
#     return round_keys

# # AddRoundKey function (XOR state with round key)
# def add_round_key(state, round_key):
#     return bytes([s ^ k for s, k in zip(state, round_key)])

# # SubBytes function (Substitution using S-box)
# def sub_bytes(state):
#     # Using AES encryption as a proxy for SubBytes
#     return AES.new(state, AES.MODE_ECB).encrypt(state)[:BLOCK_SIZE]

# # ShiftRows function (Row shifting)
# def shift_rows(state):
#     return state[0:4] + state[5:8] + state[4:5] + state[9:12] + state[8:9] + state[13:] + state[12:13]

# # MixColumns function (Column mixing, simplified)
# def mix_columns(state):
#     # Using AES encryption as a proxy for MixColumns
#     return AES.new(state, AES.MODE_ECB).encrypt(state)[:BLOCK_SIZE]

# # AES-192 encryption function
# def aes_192_encrypt(padded_msg, key):
#     round_keys = key_expansion(key)

#     # Initial round
#     state = add_round_key(padded_msg, round_keys[0])

#     # Main rounds
#     for i in range(1, 12):
#         state = sub_bytes(state)
#         state = shift_rows(state)
#         state = mix_columns(state)
#         state = add_round_key(state, round_keys[i])

#     # Final round (no MixColumns)
#     state = sub_bytes(state)
#     state = shift_rows(state)
#     state = add_round_key(state, round_keys[12])

#     return state

# # AES-192 decryption function (to verify correctness)
# def aes_192_decrypt(ciphertext, key):
#     round_keys = key_expansion(key)

#     # Final round (inverse order)
#     state = add_round_key(ciphertext, round_keys[12])
#     state = shift_rows(state)  # This would be inverse in real decryption
#     state = sub_bytes(state)  # This would be inverse in real decryption

#     # Main rounds (inverse order)
#     for i in range(11, 0, -1):
#         state = add_round_key(state, round_keys[i])
#         state = mix_columns(state)  # This would be inverse in real decryption
#         state = shift_rows(state)  # This would be inverse in real decryption
#         state = sub_bytes(state)  # This would be inverse in real decryption

#     # Initial round
#     state = add_round_key(state, round_keys[0])

#     # Unpad and return plaintext
#     plaintext = unpad(state, BLOCK_SIZE).decode('utf-8')
#     return plaintext

# # Pad the message and perform encryption
# padded_message = pad(message.encode('utf-8'), BLOCK_SIZE)
# ciphertext = aes_192_encrypt(padded_message, key)
# print(f'Ciphertext (hex): {ciphertext.hex()}')

# # Perform decryption
# plaintext = aes_192_decrypt(ciphertext, key)
# print(f'Plaintext: {plaintext}')
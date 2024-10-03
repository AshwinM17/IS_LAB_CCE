import time  # Import time module for measuring execution time
from Crypto.Cipher import DES, AES  # Import DES and AES cipher from PyCryptodome
from Crypto.Random import get_random_bytes  # Import function to generate random bytes
import matplotlib.pyplot as plt  # Import matplotlib for plotting results
from Crypto.Util.Padding import pad  # Import padding utility for handling block sizes

# Define a list of messages to encrypt for testing
messages = [
    b"First message for encryption",
    b"Second message for encryption",
    b"Third message for encryption",
    b"Fourth message for encryption",
    b"Fifth message for encryption"
]

# Key sizes for AES (128, 192, and 256 bits)
aes_key_sizes = [16, 24, 32]  # Corresponding to 128, 192, and 256 bits
des_key = get_random_bytes(8)  # Generate a random 8-byte (64-bit) key for DES

# Define the modes of operation for AES and DES
aes_modes = [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]  # AES modes
des_modes = [DES.MODE_ECB, DES.MODE_CBC, DES.MODE_CFB, DES.MODE_OFB]  # DES modes

# Define a function for encrypting messages using DES
def encrypt_DES(message, key, mode):
    cipher = DES.new(key, mode)  # Create a new DES cipher object with the given key and mode
    ciphertext = cipher.encrypt(pad(message, DES.block_size))  # Encrypt the padded message
    return ciphertext  # Return the ciphertext

# Define a function for encrypting messages using AES
def encrypt_AES(message, key_size, mode):
    key = get_random_bytes(key_size)  # Generate a random key of the specified size
    cipher = AES.new(key, mode)  # Create a new AES cipher object with the key and mode
    ciphertext = cipher.encrypt(pad(message, AES.block_size))  # Encrypt the padded message
    return ciphertext  # Return the ciphertext

# Function to measure the execution time of the encryption
def measure_time(encrypt_function, message, key=None, key_size=None, mode=None):
    start_time = time.time()  # Start the timer
    if key_size:  # Check if a key size is provided (for AES)
        encrypt_function(message, key_size, mode)  # Call the AES encryption function
    else:  # Otherwise, assume DES is being used
        encrypt_function(message, key, mode)  # Call the DES encryption function
    return time.time() - start_time  # Return the elapsed time

# Create lists to store execution times for DES and AES in different modes
des_times = {mode: [] for mode in des_modes}  # Initialize a dictionary for DES times
aes_128_times = {mode: [] for mode in aes_modes}  # Initialize for AES-128 times
aes_192_times = {mode: [] for mode in aes_modes}  # Initialize for AES-192 times
aes_256_times = {mode: [] for mode in aes_modes}  # Initialize for AES-256 times

# Encrypt each message and record the execution times
for message in messages:
    for mode in des_modes:
        # Measure and record DES encryption time for each mode
        des_times[mode].append(measure_time(encrypt_DES, message, key=des_key, mode=mode))
        
    for mode in aes_modes:
        # Measure and record AES encryption times for each key size and mode
        aes_128_times[mode].append(measure_time(encrypt_AES, message, key_size=16, mode=mode))
        aes_192_times[mode].append(measure_time(encrypt_AES, message, key_size=24, mode=mode))
        aes_256_times[mode].append(measure_time(encrypt_AES, message, key_size=32, mode=mode))

# Function to calculate average execution times
def average_times(times):
    return {mode: sum(times[mode]) / len(times[mode]) for mode in times}  # Return average times for each mode

# Calculate average execution times for DES and AES
avg_des_times = average_times(des_times)  # Average DES times
avg_aes_128_times = average_times(aes_128_times)  # Average AES-128 times
avg_aes_192_times = average_times(aes_192_times)  # Average AES-192 times
avg_aes_256_times = average_times(aes_256_times)  # Average AES-256 times

# Plotting the average execution times
modes = ['ECB', 'CBC', 'CFB', 'OFB']  # Labels for different modes of operation
plt.figure(figsize=(10, 6))  # Set the figure size for the plot

# Plot the execution times for each encryption method
plt.plot(modes, list(avg_des_times.values()), label='DES', marker='o')
plt.plot(modes, list(avg_aes_128_times.values()), label='AES-128', marker='o')
plt.plot(modes, list(avg_aes_192_times.values()), label='AES-192', marker='o')
plt.plot(modes, list(avg_aes_256_times.values()), label='AES-256', marker='o')

# Adding labels and title to the plot
plt.xlabel('Modes of Operation')  # X-axis label
plt.ylabel('Average Execution Time (seconds)')  # Y-axis label
plt.title('Execution Time for DES and AES (128, 192, 256 bits)')  # Plot title
plt.legend()  # Show legend for different encryption methods
plt.grid(True)  # Enable grid for better readability
plt.show()  # Display the plot
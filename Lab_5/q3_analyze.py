import hashlib  # Import the hashlib library for hashing functions
import time     # Import time library to measure execution time
import random   # Import random library for generating random strings
import string   # Import string library to access predefined string constants
from collections import defaultdict  # Import defaultdict for easier hash counting

def generate_random_strings(num_strings, min_length=10, max_length=20):
    """
    Generate a list of random strings.
    
    Parameters:
    num_strings (int): Number of random strings to generate.
    min_length (int): Minimum length of each string.
    max_length (int): Maximum length of each string.
    
    Returns:
    list: A list containing random strings.
    """
    strings = []
    for _ in range(num_strings):
        # Randomly determine the length of the string within the specified range
        length = random.randint(min_length, max_length)
        # Generate a random string composed of letters and digits
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        strings.append(random_string)
    return strings

def compute_md5(s):
    """Compute the MD5 hash of a given string."""
    return hashlib.md5(s.encode()).hexdigest()

def compute_sha1(s):
    """Compute the SHA-1 hash of a given string."""
    return hashlib.sha1(s.encode()).hexdigest()

def compute_sha256(s):
    """Compute the SHA-256 hash of a given string."""
    return hashlib.sha256(s.encode()).hexdigest()

def measure_time_and_compute_hashes(strings, hash_function):
    """
    Measure the time taken to compute hashes for a list of strings using a specified hash function.
    
    Parameters:
    strings (list): The list of strings to hash.
    hash_function (function): The hash function to use for hashing.
    
    Returns:
    tuple: A tuple containing the list of hashes and the time taken to compute them.
    """
    start_time = time.time()  # Start timing
    hashes = [hash_function(s) for s in strings]  # Compute hashes for each string
    end_time = time.time()  # End timing
    return hashes, end_time - start_time  # Return the list of hashes and the elapsed time

def detect_collisions(hashes):
    """
    Detect hash collisions in a list of hashes.
    
    Parameters:
    hashes (list): The list of computed hashes.
    
    Returns:
    list: A list of hash values that have collisions.
    """
    hash_count = defaultdict(int)  # Create a default dictionary to count occurrences of each hash
    collisions = []  # List to store hash values that collide
    for h in hashes:
        hash_count[h] += 1  # Increment the count for the current hash
        if hash_count[h] > 1:  # Check if a collision has occurred
            collisions.append(h)  # Add the colliding hash to the collisions list
    return collisions

def run_experiment(num_strings=100):
    """
    Run the experiment to generate random strings and compute their hashes.
    
    Parameters:
    num_strings (int): Number of random strings to generate for hashing.
    """
    strings = generate_random_strings(num_strings)  # Generate random strings
    md5_hashes, md5_time = measure_time_and_compute_hashes(strings, compute_md5)  # MD5 hashing
    md5_collisions = detect_collisions(md5_hashes)  # Detect MD5 collisions
    sha1_hashes, sha1_time = measure_time_and_compute_hashes(strings, compute_sha1)  # SHA-1 hashing
    sha1_collisions = detect_collisions(sha1_hashes)  # Detect SHA-1 collisions
    sha256_hashes, sha256_time = measure_time_and_compute_hashes(strings, compute_sha256)  # SHA-256 hashing
    sha256_collisions = detect_collisions(sha256_hashes)  # Detect SHA-256 collisions
    
    # Print the results for each hash function
    print(f"MD5 - Computation Time: {md5_time:.4f} seconds, Collisions: {len(md5_collisions)}")
    print(f"SHA-1 - Computation Time: {sha1_time:.4f} seconds, Collisions: {len(sha1_collisions)}")
    print(f"SHA-256 - Computation Time: {sha256_time:.4f} seconds, Collisions: {len(sha256_collisions)}")

if __name__ == "__main__":
    run_experiment()  # Execute the experiment when the script is run
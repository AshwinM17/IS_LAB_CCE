import hashlib
import random
import string
import time


def generate_random_strings(num_strings, min_length=5, max_length=15):
    random_strings = []
    for _ in range(num_strings):
        length = random.randint(min_length, max_length)
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        random_strings.append(random_string)
    return random_strings


def compute_hashes(strings, hash_function):
    hash_dict = {}
    for s in strings:
        hash_value = hash_function(s.encode('utf-8')).hexdigest()
        hash_dict[s] = hash_value
    return hash_dict


def detect_collisions(hash_dict):
    hash_values = list(hash_dict.values())
    unique_hashes = set(hash_values)
    collisions = len(hash_values) - len(unique_hashes)
    return collisions


def measure_time(hash_function, strings):
    start_time = time.time()
    compute_hashes(strings, hash_function)
    end_time = time.time()
    return end_time - start_time


def analyze_hash_performance(num_strings):
    random_strings = generate_random_strings(num_strings)

    # Measure computation time
    md5_time = measure_time(hashlib.md5, random_strings)
    sha1_time = measure_time(hashlib.sha1, random_strings)
    sha256_time = measure_time(hashlib.sha256, random_strings)

    print(f"MD5 Computation Time: {md5_time:.6f} seconds")
    print(f"SHA-1 Computation Time: {sha1_time:.6f} seconds")
    print(f"SHA-256 Computation Time: {sha256_time:.6f} seconds")

    # Compute hashes and detect collisions
    md5_hashes = compute_hashes(random_strings, hashlib.md5)
    sha1_hashes = compute_hashes(random_strings, hashlib.sha1)
    sha256_hashes = compute_hashes(random_strings, hashlib.sha256)

    md5_collisions = detect_collisions(md5_hashes)
    sha1_collisions = detect_collisions(sha1_hashes)
    sha256_collisions = detect_collisions(sha256_hashes)

    print(f"MD5 Collisions: {md5_collisions}")
    print(f"SHA-1 Collisions: {sha1_collisions}")
    print(f"SHA-256 Collisions: {sha256_collisions}")


if __name__ == "__main__":
    num_strings = random.randint(500000, 1000000)
    print(f"Analyzing performance with {num_strings} random strings:")
    analyze_hash_performance(num_strings)

import random
import time
import logging
import sys
import math
import matplotlib.pyplot as plt
from sympy import isprime

sys.setrecursionlimit(10000)

def generate_prime(bits):
    start_prime_gen = time.time()
    while True:
        prime_candidate = random.getrandbits(bits)
        if prime_candidate % 2 == 0:  
            prime_candidate += 1
        if isprime(prime_candidate):
            end_prime_gen = time.time()
            return prime_candidate, end_prime_gen - start_prime_gen

# Extended Euclidean algorithm to find the GCD and modular inverse
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Function to compute the modular inverse
def mod_inverse(e, phi):
    gcd, x, y = egcd(e, phi)
    if gcd != 1:
        raise ValueError("mod_inverse does not exist")
    return x % phi

# Function to generate RSA key pair
def generate_keypair(bits):
    logging.info("Generating key pair...")
    start_key_gen = time.time()  # Start timer for key generation

    p, p_gen_time = generate_prime(bits)
    logging.info("Generated prime p: %d", p)
    q, q_gen_time = generate_prime(bits)
    logging.info("Generated prime q: %d", q)

    while p == q:
        q, q_gen_time = generate_prime(bits)
        logging.info("Regenerated prime q: %d", q)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randint(3, phi - 1)
    while math.gcd(e, phi) != 1:
        e = random.randint(3, phi - 1)

    d = mod_inverse(e, phi)

    logging.info("Public key (e, n): (%d, %d)", e, n)
    logging.info("Private key (d): %d", d)

    end_key_gen = time.time()  # Stop timer for key generation
    key_gen_time = end_key_gen - start_key_gen
    logging.info(f"Time to generate keys (public & private): {key_gen_time} seconds")

    total_prime_gen_time = p_gen_time + q_gen_time
    logging.info(f"Time to generate primes (p & q): {total_prime_gen_time} seconds")

    return (e, n), (d, n), key_gen_time, total_prime_gen_time

# Function to encrypt a plaintext using the public key
def encrypt(plaintext, public_key):
    num = int(plaintext)  # Ensure plaintext is an integer
    start_crypto = time.time()
    ciphertext = pow(num, public_key[0], public_key[1])
    end_crypto = time.time()
    crypto_time = end_crypto - start_crypto
    logging.info(f"Time for encryption: {crypto_time} seconds")
    return ciphertext, crypto_time

# Function to decrypt a ciphertext using the private key
def decrypt(ciphertext, private_key):
    start_crypto = time.time()
    num = pow(ciphertext, private_key[0], private_key[1])
    end_crypto = time.time()
    crypto_time = end_crypto - start_crypto
    logging.info(f"Time for decryption: {crypto_time} seconds")
    return str(num), crypto_time

# Function for homomorphic multiplication
def homomorphic_multiply(ciphertext1, ciphertext2, n):
    # Homomorphic multiplication in the ciphertext domain
    return (ciphertext1 * ciphertext2) % n

# Function to plot times for key generation, prime generation, encryption, and decryption
def plot_times(key_gen_time, prime_gen_time, encryption_time, decryption_time):
    # Labels for the operations
    operations = ['Key Generation', 'Prime Generation', 'Encryption', 'Decryption']
    times = [key_gen_time, prime_gen_time, encryption_time, decryption_time]

    # Create a bar plot
    plt.figure(figsize=(8, 6))
    plt.bar(operations, times, color=['blue', 'orange', 'green', 'red'])

    # Add titles and labels
    plt.title('Time Analysis for RSA Key Generation, Encryption, and Decryption')
    plt.xlabel('Operation')
    plt.ylabel('Time (seconds)')

    # Display the plot
    plt.show()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Generate a 512-bit key pair
    public_key, private_key, key_gen_time, prime_gen_time = generate_keypair(512)

    # Get plaintext input from user
    plaintext1 = int(input("Enter the first plaintext integer: "))
    plaintext2 = int(input("Enter the second plaintext integer: "))

    # Encrypt both plaintexts
    ciphertext1, encryption_time1 = encrypt(str(plaintext1), public_key)
    ciphertext2, encryption_time2 = encrypt(str(plaintext2), public_key)

    total_encryption_time = encryption_time1 + encryption_time2
    logging.info(f"Total encryption time: {total_encryption_time} seconds")

    # Perform homomorphic multiplication
    encrypted_product = homomorphic_multiply(ciphertext1, ciphertext2, public_key[1])

    # Decrypt the result
    decrypted_product, decryption_time = decrypt(encrypted_product, private_key)
    decrypted_product = int(decrypted_product)

    print("Plaintext 1:", plaintext1)
    print("Plaintext 2:", plaintext2)
    print("Encrypted product:", encrypted_product)
    print("Decrypted product:", decrypted_product)

    total_processing_time = total_encryption_time + decryption_time + key_gen_time + prime_gen_time
    logging.info(f"Total processing time: {total_processing_time} seconds")

    # Generate the plot for timing analysis
    plot_times(prime_gen_time, key_gen_time, total_encryption_time, decryption_time)

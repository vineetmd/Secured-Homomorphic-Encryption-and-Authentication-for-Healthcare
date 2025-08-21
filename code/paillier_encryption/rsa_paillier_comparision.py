import random
import time
from sympy import isprime, mod_inverse, gcd
import matplotlib.pyplot as plt
import numpy as np
import math

# Paillier Cryptosystem

def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

def find_valid_g(n, lambda_n):
    n_sq = n * n
    while True:
        g = random.randint(1, n_sq - 1)
        # Check if L(g^lambda mod n^2) is invertible mod n
        if gcd((pow(g, lambda_n, n_sq) - 1) // n, n) == 1:
            return g

def paillier_generate_keypair(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    
    # Find a valid g using the verification approach
    g = find_valid_g(n, lambda_n)
    
    mu = mod_inverse((pow(g, lambda_n, n * n) - 1) // n, n)
    
    public_key = (n, g)
    private_key = (lambda_n, mu)
    
    return public_key, private_key

def paillier_encrypt(message, public_key):
    n, g = public_key
    r = random.randint(1, n-1)
    n_sq = n * n
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def paillier_decrypt(ciphertext, private_key, public_key):
    n, _ = public_key
    lambda_n, mu = private_key
    n_sq = n * n
    
    def L(x):
        return (x - 1) // n

    u = pow(ciphertext, lambda_n, n_sq)
    l = L(u)
    message = (l * mu) % n
    return message

def paillier_homomorphic_addition(c1, c2, public_key):
    n, _ = public_key
    n_sq = n * n
    c_sum = (c1 * c2) % n_sq
    return c_sum

# RSA Cryptosystem

def rsa_generate_keypair(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randint(2, phi - 1)
    while math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    
    d = mod_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

def rsa_encrypt(message, public_key):
    e, n = public_key
    ciphertext = pow(message, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    message = pow(ciphertext, d, n)
    return message

def rsa_homomorphic_multiplication(c1, c2, public_key):
    _, n = public_key
    return (c1 * c2) % n

# Performance Comparison

def compare_performance(iterations=5):
    bit_sizes = [512, 1024, 1536, 2048, 2560, 3072, 3584, 4096]
    avg_keygen_times = {'Paillier': [], 'RSA': []}
    avg_encryption_times = {'Paillier': [], 'RSA': []}
    avg_decryption_times = {'Paillier': [], 'RSA': []}

    for bits in bit_sizes:
        for algo in ['Paillier', 'RSA']:
            keygen_times = []
            encryption_times = []
            decryption_times = []
            iters = iterations if bits <= 3072 else 3  # Reduce iterations for very large sizes

            for _ in range(iters):
                try:
                    # Generate keys
                    if algo == 'Paillier':
                        start_time = time.time()
                        public_key, private_key = paillier_generate_keypair(bits)
                        keygen_times.append(time.time() - start_time)
                        
                        message1 = 42
                        message2 = 17
                        start_time = time.time()
                        ciphertext1 = paillier_encrypt(message1, public_key)
                        ciphertext2 = paillier_encrypt(message2, public_key)
                        encryption_times.append(time.time() - start_time)

                        ciphertext_sum = paillier_homomorphic_addition(ciphertext1, ciphertext2, public_key)
                        
                        start_time = time.time()
                        paillier_decrypt(ciphertext_sum, private_key, public_key)
                        decryption_times.append(time.time() - start_time)

                    elif algo == 'RSA':
                        start_time = time.time()
                        public_key, private_key = rsa_generate_keypair(bits)
                        keygen_times.append(time.time() - start_time)
                        
                        message1 = 42
                        message2 = 17
                        start_time = time.time()
                        ciphertext1 = rsa_encrypt(message1, public_key)
                        ciphertext2 = rsa_encrypt(message2, public_key)
                        encryption_times.append(time.time() - start_time)

                        ciphertext_product = rsa_homomorphic_multiplication(ciphertext1, ciphertext2, public_key)
                        
                        start_time = time.time()
                        rsa_decrypt(ciphertext_product, private_key)
                        decryption_times.append(time.time() - start_time)
                        
                except Exception as e:
                    print(f"Error processing {bits}-bit key: {e}")
                    break

            avg_keygen_times[algo].append(np.mean(keygen_times) if keygen_times else float('inf'))
            avg_encryption_times[algo].append(np.mean(encryption_times) if encryption_times else float('inf'))
            avg_decryption_times[algo].append(np.mean(decryption_times) if decryption_times else float('inf'))
        
    # Displaying the results in console
    for i, bits in enumerate(bit_sizes):
        print(f"Bit Size: {bits}")
        print(f"  Paillier Key Generation Time: {avg_keygen_times['Paillier'][i]:.4f} seconds")
        print(f"  RSA Key Generation Time: {avg_keygen_times['RSA'][i]:.4f} seconds")
        print(f"  Paillier Encryption Time: {avg_encryption_times['Paillier'][i]:.4f} seconds")
        print(f"  RSA Encryption Time: {avg_encryption_times['RSA'][i]:.4f} seconds")
        print(f"  Paillier Decryption Time: {avg_decryption_times['Paillier'][i]:.4f} seconds")
        print(f"  RSA Decryption Time: {avg_decryption_times['RSA'][i]:.4f} seconds")
        print("-" * 50)
        
    # Plotting the results
    bar_width = 0.35
    index = np.arange(len(bit_sizes))

    # Plot for Key Generation Time
    plt.figure(figsize=(14, 8))
    plt.bar(index - bar_width/2, avg_keygen_times['Paillier'], bar_width, label='Paillier Key Generation Time', color='blue')
    plt.bar(index + bar_width/2, avg_keygen_times['RSA'], bar_width, label='RSA Key Generation Time', color='orange')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.title('Key Generation Time Comparison')
    plt.xticks(index, bit_sizes)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # Plot for Encryption Time
    plt.figure(figsize=(14, 8))
    plt.bar(index - bar_width/2, avg_encryption_times['Paillier'], bar_width, label='Paillier Encryption Time', color='blue')
    plt.bar(index + bar_width/2, avg_encryption_times['RSA'], bar_width, label='RSA Encryption Time', color='orange')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.title('Encryption Time Comparison')
    plt.xticks(index, bit_sizes)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # Plot for Decryption Time
    plt.figure(figsize=(14, 8))
    plt.bar(index - bar_width/2, avg_decryption_times['Paillier'], bar_width, label='Paillier Decryption Time', color='blue')
    plt.bar(index + bar_width/2, avg_decryption_times['RSA'], bar_width, label='RSA Decryption Time', color='orange')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.title('Decryption Time Comparison')
    plt.xticks(index, bit_sizes)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    compare_performance(iterations=5)

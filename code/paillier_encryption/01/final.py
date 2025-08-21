import random
import time
from sympy import isprime, mod_inverse
import matplotlib.pyplot as plt
import numpy as np

def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

def generate_keypair(bits=512):
    start_time = time.time()
    
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    g = n + 1
    mu = mod_inverse(lambda_n, n)
    
    public_key = (n, g)
    private_key = (lambda_n, mu)
    
    end_time = time.time()
    keygen_time = end_time - start_time
    
    return public_key, private_key, keygen_time

def encrypt(message, public_key):
    start_time = time.time()
    
    n, g = public_key
    r = random.randint(1, n-1)
    n_sq = n * n
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    
    end_time = time.time()
    encryption_time = end_time - start_time
    
    return c, encryption_time

def decrypt(ciphertext, private_key, public_key):
    start_time = time.time()
    
    n, _ = public_key
    lambda_n, mu = private_key
    n_sq = n * n
    
    def L(x):
        return (x - 1) // n

    u = pow(ciphertext, lambda_n, n_sq)
    l = L(u)
    message = (l * mu) % n
    
    end_time = time.time()
    decryption_time = end_time - start_time
    
    return message, decryption_time

def homomorphic_addition(c1, c2, public_key):
    """
    Performs homomorphic addition on two ciphertexts.
    """
    n, _ = public_key
    n_sq = n * n
    c_sum = (c1 * c2) % n_sq
    
    return c_sum

def compare_performance(iterations=5):
    bit_sizes = [512, 1024, 1536, 2048, 2560, 3072, 3584, 4096]
    avg_keygen_times = []
    avg_encryption_times = []
    avg_decryption_times = []

    for bits in bit_sizes:
        keygen_times = []
        encryption_times = []
        decryption_times = []
        iters = iterations if bits <= 3072 else 3  # Reduce iterations for very large sizes

        for _ in range(iters):
            try:
                # Generate keys
                public_key, private_key, keygen_time = generate_keypair(bits)
                keygen_times.append(keygen_time)

                # Encrypt two sample messages (using '42' and '17' as placeholder messages)
                message1 = 42
                message2 = 17
                ciphertext1, encryption_time1 = encrypt(message1, public_key)
                ciphertext2, encryption_time2 = encrypt(message2, public_key)
                
                encryption_times.append(encryption_time1 + encryption_time2)

                # Perform homomorphic addition (not used for timing or plotting)
                ciphertext_sum = homomorphic_addition(ciphertext1, ciphertext2, public_key)
                
                # Decrypt the sum
                _, decryption_time = decrypt(ciphertext_sum, private_key, public_key)
                decryption_times.append(decryption_time)
                
            except Exception as e:
                print(f"Error processing {bits}-bit key: {e}")
                break

        # Calculate average times
        avg_keygen_times.append(np.mean(keygen_times) if keygen_times else float('inf'))
        avg_encryption_times.append(np.mean(encryption_times) if encryption_times else float('inf'))
        avg_decryption_times.append(np.mean(decryption_times) if decryption_times else float('inf'))
        
        print(f"\n### Results for {bits}-bit keys ###")
        print(f"Average Key Generation Time: {np.mean(keygen_times) if keygen_times else 'N/A'} seconds")
        print(f"Average Encryption Time (for two messages): {np.mean(encryption_times) if encryption_times else 'N/A'} seconds")
        print(f"Average Decryption Time: {np.mean(decryption_times) if decryption_times else 'N/A'} seconds\n")

    # Plotting the results
    bar_width = 0.25
    index = np.arange(len(bit_sizes))

    plt.figure(figsize=(12, 8))

    plt.bar(index - bar_width, avg_keygen_times, bar_width, label='Key Generation Time', color='blue')
    plt.bar(index, avg_encryption_times, bar_width, label='Encryption Time', color='green')
    plt.bar(index + bar_width, avg_decryption_times, bar_width, label='Decryption Time', color='red')

    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.title('Performance Comparison for Different Key Sizes')
    plt.xticks(index, bit_sizes)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    compare_performance(iterations=5)
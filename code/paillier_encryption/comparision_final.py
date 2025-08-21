import random
import time
from sympy import isprime, mod_inverse
from Crypto.Util import number
import matplotlib.pyplot as plt
import numpy as np

def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

def generate_keypair_paillier(bits=512):
    print(f"Generating Paillier key pair with {bits}-bit keys...")
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
    print(f"Paillier key generation completed in {keygen_time:.4f} seconds.")
    
    return public_key, private_key, keygen_time

def generate_keypair_rsa(bits=512):
    print(f"Generating RSA key pair with {bits}-bit keys...")
    start_time = time.time()
    
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    e = 65537
    d = number.inverse(e, lambda_n)
    
    public_key = (n, e)
    private_key = (d, lambda_n)
    
    end_time = time.time()
    keygen_time = end_time - start_time
    print(f"RSA key generation completed in {keygen_time:.4f} seconds.")
    
    return public_key, private_key, keygen_time

def encrypt_paillier(message, public_key):
    start_time = time.time()
    
    n, g = public_key
    r = random.randint(1, n-1)
    n_sq = n * n
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    
    end_time = time.time()
    encryption_time = end_time - start_time
    
    return c, encryption_time

def decrypt_paillier(ciphertext, private_key, public_key):
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

def encrypt_rsa(message, public_key):
    start_time = time.time()
    
    n, e = public_key
    ciphertext = pow(message, e, n)
    
    end_time = time.time()
    encryption_time = end_time - start_time
    
    return ciphertext, encryption_time

def decrypt_rsa(ciphertext, private_key, public_key):
    start_time = time.time()
    
    n, e = public_key
    d, _ = private_key
    message = pow(ciphertext, d, n)
    
    end_time = time.time()
    decryption_time = end_time - start_time
    return message, decryption_time

def compare_performance(iterations=5):
    bit_sizes = [512, 1024]  # Reduced key sizes for quicker tests
    avg_keygen_times_paillier = []
    avg_encryption_times_paillier = []
    avg_decryption_times_paillier = []
    
    avg_keygen_times_rsa = []
    avg_encryption_times_rsa = []
    avg_decryption_times_rsa = []

    for bits in bit_sizes:
        keygen_times_paillier = []
        encryption_times_paillier = []
        decryption_times_paillier = []
        
        keygen_times_rsa = []
        encryption_times_rsa = []
        decryption_times_rsa = []
        
        iters = iterations  # Keeping iterations low for demonstration purposes

        for _ in range(iters):
            try:
                # Paillier Key Generation
                public_key_paillier, private_key_paillier, keygen_time_paillier = generate_keypair_paillier(bits)
                keygen_times_paillier.append(keygen_time_paillier)

                # RSA Key Generation
                public_key_rsa, private_key_rsa, keygen_time_rsa = generate_keypair_rsa(bits)
                keygen_times_rsa.append(keygen_time_rsa)

                # Paillier Encryption and Decryption
                message = 42
                ciphertext_paillier, encryption_time_paillier = encrypt_paillier(message, public_key_paillier)
                encryption_times_paillier.append(encryption_time_paillier)
                _, decryption_time_paillier = decrypt_paillier(ciphertext_paillier, private_key_paillier, public_key_paillier)
                decryption_times_paillier.append(decryption_time_paillier)

                # RSA Encryption and Decryption
                ciphertext_rsa, encryption_time_rsa = encrypt_rsa(message, public_key_rsa)
                encryption_times_rsa.append(encryption_time_rsa)
                _, decryption_time_rsa = decrypt_rsa(ciphertext_rsa, private_key_rsa, public_key_rsa)
                decryption_times_rsa.append(decryption_time_rsa)
                
            except Exception as e:
                print(f"Error processing {bits}-bit key: {e}")
                break

        # Calculate average times
        avg_keygen_times_paillier.append(np.mean(keygen_times_paillier) if keygen_times_paillier else float('inf'))
        avg_encryption_times_paillier.append(np.mean(encryption_times_paillier) if encryption_times_paillier else float('inf'))
        avg_decryption_times_paillier.append(np.mean(decryption_times_paillier) if decryption_times_paillier else float('inf'))
        
        avg_keygen_times_rsa.append(np.mean(keygen_times_rsa) if keygen_times_rsa else float('inf'))
        avg_encryption_times_rsa.append(np.mean(encryption_times_rsa) if encryption_times_rsa else float('inf'))
        avg_decryption_times_rsa.append(np.mean(decryption_times_rsa) if decryption_times_rsa else float('inf'))
        
        print(f"\n### Results for {bits}-bit keys ###")
        print(f"Paillier - Average Key Generation Time: {np.mean(keygen_times_paillier) if keygen_times_paillier else 'N/A'} seconds")
        print(f"Paillier - Average Encryption Time: {np.mean(encryption_times_paillier) if encryption_times_paillier else 'N/A'} seconds")
        print(f"Paillier - Average Decryption Time: {np.mean(decryption_times_paillier) if decryption_times_paillier else 'N/A'} seconds")
        
        print(f"RSA - Average Key Generation Time: {np.mean(keygen_times_rsa) if keygen_times_rsa else 'N/A'} seconds")
        print(f"RSA - Average Encryption Time: {np.mean(encryption_times_rsa) if encryption_times_rsa else 'N/A'} seconds")
        print(f"RSA - Average Decryption Time: {np.mean(decryption_times_rsa) if decryption_times_rsa else 'N/A'} seconds")

    # Plotting results
    bar_width = 0.35
    x = np.arange(len(bit_sizes))

    plt.figure(figsize=(15, 5))

    # Key Generation Time
    plt.subplot(131)
    plt.bar(x - bar_width / 2, avg_keygen_times_paillier, bar_width, label='Paillier')
    plt.bar(x + bar_width / 2, avg_keygen_times_rsa, bar_width, label='RSA')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Average Time (s)')
    plt.title('Key Generation Time')
    plt.xticks(x, bit_sizes)
    plt.legend()

    # Encryption Time
    plt.subplot(132)
    plt.bar(x - bar_width / 2, avg_encryption_times_paillier, bar_width, label='Paillier')
    plt.bar(x + bar_width / 2, avg_encryption_times_rsa, bar_width, label='RSA')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Average Time (s)')
    plt.title('Encryption Time')
    plt.xticks(x, bit_sizes)
    plt.legend()

    # Decryption Time
    plt.subplot(133)
    plt.bar(x - bar_width / 2, avg_decryption_times_paillier, bar_width, label='Paillier')
    plt.bar(x + bar_width / 2, avg_decryption_times_rsa, bar_width, label='RSA')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Average Time (s)')
    plt.title('Decryption Time')
    plt.xticks(x, bit_sizes)
    plt.legend()

    plt.tight_layout()
    plt.show()

# Run performance comparison with fewer iterations and smaller key sizes
compare_performance(iterations=3)

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
        if gcd((pow(g, lambda_n, n_sq) - 1) // n, n) == 1:
            return g

def paillier_generate_keypair(bits=512):  
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    g = find_valid_g(n, lambda_n)
    mu = mod_inverse((pow(g, lambda_n, n * n) - 1) // n, n)
    public_key = (n, g)
    private_key = (lambda_n, mu)
    return public_key, private_key

def paillier_encrypt(message, public_key):
    n, g = public_key
    r = random.randint(1, n - 1)
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

# Performance Comparison

def compare_total_performance(iterations=5):
    plaintexts = list(range(1, 11))  # 1 to 10 plaintexts
    avg_total_time = {'Paillier': [], 'RSA': []}

    for num_plaintexts in plaintexts:
        total_times = {'Paillier': [], 'RSA': []}
        
        for algo in ['Paillier', 'RSA']:
            for _ in range(iterations):
                if algo == 'Paillier':
                    start_time = time.time()
                    public_key, private_key = paillier_generate_keypair(bits=512)
                    keygen_time = time.time() - start_time

                    messages = [random.randint(1, 100) for _ in range(num_plaintexts)]
                    start_time = time.time()
                    ciphertexts = [paillier_encrypt(msg, public_key) for msg in messages]
                    encryption_time = time.time() - start_time

                    c_sum = ciphertexts[0]
                    for c in ciphertexts[1:]:
                        c_sum = paillier_homomorphic_addition(c_sum, c, public_key)
                    start_time = time.time()
                    paillier_decrypt(c_sum, private_key, public_key)
                    decryption_time = time.time() - start_time

                    total_time = keygen_time + encryption_time + decryption_time
                    total_times['Paillier'].append(total_time)

                elif algo == 'RSA':
                    start_time = time.time()
                    public_key, private_key = rsa_generate_keypair(bits=512)
                    keygen_time = time.time() - start_time

                    messages = [random.randint(1, 100) for _ in range(num_plaintexts)]
                    start_time = time.time()
                    ciphertexts = [rsa_encrypt(msg, public_key) for msg in messages]
                    encryption_time = time.time() - start_time

                    # Note: We don't use RSA homomorphic properties for normal operations
                    start_time = time.time()
                    rsa_decrypt(ciphertexts[0], private_key)  # Decrypt the first for comparison
                    decryption_time = time.time() - start_time

                    total_time = keygen_time + encryption_time + decryption_time
                    total_times['RSA'].append(total_time)

        # Average the total times for this number of plaintexts
        avg_total_time['Paillier'].append(np.mean(total_times['Paillier']))
        avg_total_time['RSA'].append(np.mean(total_times['RSA']))

    # Convert to numpy arrays for easier plotting
    paillier_total_times = np.array(avg_total_time['Paillier'])
    rsa_total_times = np.array(avg_total_time['RSA'])

    # Plotting the results as a bar graph
    num_plaintexts = np.arange(1, 11)
    bar_width = 0.35
    index = np.arange(len(num_plaintexts))

    plt.figure(figsize=(10, 6))
    plt.bar(index, paillier_total_times, bar_width, label='Paillier Total Time', color='blue')
    plt.bar(index + bar_width, rsa_total_times, bar_width, label='RSA Total Time', color='orange')
    
    plt.title('Total Processing Time vs Number of Plaintexts for 2048 bits')
    plt.xlabel('Number of Plaintexts')
    plt.ylabel('Total Time (seconds)')
    plt.xticks(index + bar_width / 2, num_plaintexts)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    compare_total_performance(iterations=5)

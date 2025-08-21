import random
import time
from sympy import isprime, mod_inverse

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
    
    print("\n### Key Generation ###\n")
    print(f"p: {p}\n")
    print(f"q: {q}\n")
    print(f"n: {n}\n")
    print(f"g: {g}\n")
    print(f"lambda: {lambda_n}\n")
    print(f"mu: {mu}\n")
    print(f"Public Key: {public_key}\n")
    print(f"Private Key: {private_key}\n")
    print(f"Time taken for key generation: {keygen_time:.4f} seconds\n")
    print("\n########################\n")
    
    return public_key, private_key

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

    # Compute u = ciphertext^lambda_n mod n^2
    u = pow(ciphertext, lambda_n, n_sq)
    print("\n### Decryption ###\n")
    print(f"Ciphertext: {ciphertext}\n")
    print(f"Lambda (λ): {lambda_n}\n")
    print(f"n^2: {n_sq}\n")
    print(f"u = ciphertext^λ mod n^2: {u}\n")
    
    # Compute L(u) = (u - 1) // n
    l = L(u)
    print(f"L(u) = (u - 1) // n: {l}\n")

    # Compute the original message
    message = (l * mu) % n
    print(f"Mu (μ): {mu}\n")
    print(f"Original message = (L(u) * μ) mod n: {message}\n")
    
    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"Time taken for decryption: {decryption_time:.4f} seconds\n")
    print("\n############################\n")
    
    return message

def homomorphic_addition(c1, c2, public_key):
    start_time = time.time()
    
    n, _ = public_key
    n_sq = n * n
    c_sum = (c1 * c2) % n_sq
    
    end_time = time.time()
    addition_time = end_time - start_time
    
    return c_sum, addition_time

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=4096)

    # Take input messages from user
    message1 = int(input("Enter the first message to encrypt (as an integer): "))
    message2 = int(input("Enter the second message to encrypt (as an integer): "))

    # Encrypt the messages
    ciphertext1, encryption_time1 = encrypt(message1, public_key)
    ciphertext2, encryption_time2 = encrypt(message2, public_key)
    
    # Perform homomorphic addition
    ciphertext_sum, addition_time = homomorphic_addition(ciphertext1, ciphertext2, public_key)
    
    # Calculate total encryption time
    total_encryption_time = encryption_time1 + encryption_time2 + addition_time
    
    print("\n### Encryption Results ###\n")
    print(f"Plaintext m1: {message1}")
    print(f"Ciphertext c1 (encrypted m1): {ciphertext1}\n")
    print(f"Plaintext m2: {message2}")
    print(f"Ciphertext c2 (encrypted m2): {ciphertext2}\n")
    print(f"Ciphertext of the sum (c1 * c2 mod n^2): {ciphertext_sum}\n")
    print(f"Total time taken for encryption: {total_encryption_time:.4f} seconds\n")

    # Decrypt the result
    decrypted_sum = decrypt(ciphertext_sum, private_key, public_key)
    print(f"Decrypted sum (m1 + m2): {decrypted_sum}\n")
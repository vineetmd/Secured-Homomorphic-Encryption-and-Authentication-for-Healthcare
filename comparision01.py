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

def homomorphic_subtraction(c1, c2, public_key):
    start_time = time.time()
    
    n, _ = public_key
    n_sq = n * n
    c2_inv = pow(c2, -1, n_sq)
    c_diff = (c1 * c2_inv) % n_sq
    
    end_time = time.time()
    subtraction_time = end_time - start_time
    
    return c_diff, subtraction_time

def secure_comparison(a, b, public_key, private_key):
    n, _ = public_key
    
    # Generate random masks
    r_a = random.randint(1, n - 1)
    r_b = random.randint(1, n - 1)
    
    # Log the random masks
    print(f"Random mask for message a: {r_a}")
    print(f"Random mask for message b: {r_b}")
    
    # Encrypt the masked values
    enc_a, _ = encrypt(a + r_a, public_key)
    enc_b, _ = encrypt(b + r_b, public_key)
    
    # Log the encrypted masked values
    print(f"Encrypted masked value for message a: {enc_a}")
    print(f"Encrypted masked value for message b: {enc_b}")
    
    # Homomorphic subtraction: enc_a - enc_b
    enc_diff, _ = homomorphic_subtraction(enc_a, enc_b, public_key)
    
    # Decrypt the difference
    diff = decrypt(enc_diff, private_key, public_key)
    
    # Correct the decrypted difference
    diff_corrected = diff - (r_a - r_b)
    
    if diff_corrected > 0:
        return "Message a has greater bit length than message b"
    elif diff_corrected < 0:
        return "Message b has greater bit length than message a"
    else:
        return "Messages a and b have the same bit length"

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=1024)

    # Take input messages from user
    message1 = int(input("Enter the first message to encrypt (as an integer): "))
    message2 = int(input("Enter the second message to encrypt (as an integer): "))

    # Perform secure comparison
    comparison_result = secure_comparison(message1, message2, public_key, private_key)
    print(comparison_result)

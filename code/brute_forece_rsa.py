import random
from sympy import isprime, mod_inverse

def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

def generate_keypair(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    g = n + 1
    mu = mod_inverse(lambda_n, n)
    
    return (n, g), (lambda_n, mu)

def encrypt(message, public_key):
    n, g = public_key
    r = random.randint(1, n-1)
    n_sq = n * n
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def compare(m1, m2, public_key):
    n, g = public_key
    
    # Encrypt m1 and m2
    T1 = (1 + m1 * n) * encrypt(1, public_key)  # PK is g
    T2 = (1 + m2 * n) * encrypt(2, public_key)  # g is used as 2
    
    # Calculate T1 * T2^-1
    T2_inv = mod_inverse(T2, n * n)
    T = (T1 * T2_inv) % (n * n)
    
    # Determine the sign of the difference
    if T >= 1:
        return "m1 >= m2"
    else:
        return "m1 < m2"

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=512)

    # Input two messages to compare
    m1 = int(input("Enter the first message (m1) to compare: "))
    m2 = int(input("Enter the second message (m2) to compare: "))

    # Compare the messages
    result = compare(m1, m2, public_key)
    print(f"Comparison result: {result}")

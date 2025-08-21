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
    
    public_key = (n, g)
    private_key = (lambda_n, mu)
    
    print("\n### Key Generation ###\n")
    print(f"p: {p}\n")
    print(f"q: {q}\n")
    print(f"n: {n}\n")
    print(f"g: {g}\n")
    print(f"lambda: {lambda_n}\n")
    print(f"mu: {mu}\n")
    print(f"Public Key: {public_key}\n")
    print(f"Private Key: {private_key}\n")
    print("\n########################\n")
    
    return public_key, private_key

def encrypt(message, public_key):
    n, g = public_key
    r = random.randint(1, n-1)
    n_sq = n * n
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    
    print("\n### Encryption ###\n")
    print(f"r: {r}\n")
    print(f"n_sq: {n_sq}\n")
    print(f"message: {message}\n")
    print(f"ciphertext (c): {c}\n")
    
    return c

def decrypt(ciphertext, private_key, public_key):
    n, _ = public_key
    lambda_n, mu = private_key
    n_sq = n * n
    
    def L(x):
        return (x - 1) // n

    u = pow(ciphertext, lambda_n, n_sq)
    l = L(u)
    
    print("\n### Decryption ###\n")
    print(f"u: {u}\n")
    print(f"L(u): {l}\n")
    print(f"mu: {mu}\n")
    print("\n###################\n")
    
    message = (l * mu) % n
    return message

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=4096)

    # Take input message from user
    message = int(input("Enter the message to encrypt (as an integer): "))

    # Encrypt the message
    ciphertext = encrypt(message, public_key)
    print("\n###################\n")

    # Decrypt the message
    decrypted_message = decrypt(ciphertext, private_key, public_key)
    print(f"\nDecrypted message: {decrypted_message}\n")

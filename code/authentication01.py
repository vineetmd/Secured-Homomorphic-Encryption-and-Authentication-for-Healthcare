import random
import hashlib
from sympy import isprime

# Hashing function for password
def hash_password(password):
    return int(hashlib.sha256(str(password).encode()).hexdigest(), 16)

# Modular exponentiation function for encryption
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

# Helper function to generate random primes
def random_prime(bit_length):
    while True:
        prime_candidate = random.getrandbits(bit_length)
        if isprime(prime_candidate):
            return prime_candidate

# Modular inverse using extended Euclidean algorithm
def mod_inv(a, n):
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("Inverse does not exist")
    if t < 0:
        t = t + n
    return t

# Key generation (basic version of Paillier keys)
def key_generation(bit_length=512):
    p = random_prime(bit_length)
    q = random_prime(bit_length)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    g = n + 1
    mu = mod_inv(lambda_n, n)
    return (n, g), (lambda_n, mu)

# Encryption using Paillier scheme
def encrypt(public_key, plaintext):
    n, g = public_key
    r = random.randint(1, n - 1)
    n_square = n * n
    ciphertext = (mod_exp(g, plaintext, n_square) * mod_exp(r, n, n_square)) % n_square
    return ciphertext

# Decryption using Paillier scheme
def decrypt(private_key, public_key, ciphertext):
    lambda_n, mu = private_key
    n, g = public_key
    n_square = n * n
    u = (mod_exp(ciphertext, lambda_n, n_square) - 1) // n
    plaintext = (u * mu) % n
    return plaintext

# Function for homomorphic addition
def homomorphic_add(ciphertext1, ciphertext2, public_key):
    n, g = public_key
    n_square = n * n
    return (ciphertext1 * ciphertext2) % n_square

# Zero-Knowledge Proof-based Authentication with Server Challenge Encryption
def zkp_authentication(encrypted_result, public_key, private_key, stored_encrypted_password):
    user_password = input("Enter your password for authentication: ")
    hashed_password = hash_password(user_password)
    print(f"Hashed input password: {hashed_password}")

    # Step 1: Verifier (Server) sends a random challenge
    challenge = random.randint(1000, 9999)
    print(f"Server's raw challenge: {challenge}")

    # Step 2: Verifier (Server) encrypts the challenge using the user's public key
    encrypted_challenge = encrypt(public_key, challenge)
    print(f"Server sends encrypted challenge: {encrypted_challenge}")

    # Step 3: Prover (User) decrypts the challenge using their private key
    decrypted_challenge = decrypt(private_key, public_key, encrypted_challenge)
    print(f"User decrypts the challenge: {decrypted_challenge}")

    # Step 4: Prover computes the response:
    # Homomorphically combine encrypted password and decrypted challenge
    encrypted_decrypted_challenge = encrypt(public_key, decrypted_challenge)
    combined = homomorphic_add(stored_encrypted_password, encrypted_decrypted_challenge, public_key)
    print(f"Combined encrypted value: {combined}")

    # Step 5: Verifier (Server) decrypts the combined value
    decrypted_value = decrypt(private_key, public_key, combined)
    print(f"Verifier decrypts combined value: {decrypted_value}")

    # Step 6: Verifier checks if decrypted_value matches the sum of the user's password hash and challenge
    if decrypted_value == (hashed_password + decrypted_challenge):
        print("Authentication successful! ZKP validated.")
        # Step 7: Provide access to the encrypted result
        decrypted_result = decrypt(private_key, public_key, encrypted_result)
        print(f"The result of the homomorphic addition is: {decrypted_result}")
    else:
        print("Authentication failed! ZKP validation failed.")

# Main execution
# Key Generation
public_key, private_key = key_generation()

# Registration
password = 12345  # User's password
hashed_password = hash_password(password)
encrypted_password = encrypt(public_key, hashed_password)

# Store encrypted password
stored_encrypted_password = encrypted_password

# Get inputs for homomorphic addition
plaintext1 = int(input("Enter the first plaintext number: "))
plaintext2 = int(input("Enter the second plaintext number: "))

# Encrypt plaintexts
encrypted_plaintext1 = encrypt(public_key, plaintext1)
encrypted_plaintext2 = encrypt(public_key, plaintext2)

# Perform homomorphic addition
encrypted_result = homomorphic_add(encrypted_plaintext1, encrypted_plaintext2, public_key)

# Authenticate and decrypt result
zkp_authentication(encrypted_result, public_key, private_key, stored_encrypted_password)

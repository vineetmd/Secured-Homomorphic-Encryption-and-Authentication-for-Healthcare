import hashlib
import random
import time
import matplotlib.pyplot as plt
from sympy import isprime, mod_inverse

# Generate a prime number with the specified number of bits
def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if isprime(prime_candidate):
            return prime_candidate

# Generate keypair
def generate_keypair(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    lambda_n = (p - 1) * (q - 1)
    g = n + 1
    mu = mod_inverse(lambda_n, n)
    
    public_key = (n, g)
    private_key = (lambda_n, mu)
    
    return public_key, private_key

# Encrypt the message using the public key
def encrypt(message, public_key):
    n, g = public_key
    n_sq = n * n
    r = random.randint(1, n - 1)
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# Mask the ciphertext by raising it to a power
def mask_ciphertext(ciphertext, public_key):
    n, _ = public_key
    n_sq = n * n
    n_bits = len_in_bits(n)
    power = random.randint(2, n_bits)
    masked_ciphertext = pow(ciphertext, power, n_sq)
    return masked_ciphertext, power

# Decrypt the masked ciphertext
def decrypt(masked_ciphertext, private_key, public_key):
    n, _ = public_key
    lambda_n, mu = private_key
    n_sq = n * n

    def L(x):
        return (x - 1) // n

    u = pow(masked_ciphertext, lambda_n, n_sq)
    l = L(u)
    message = (l * mu) % n
    return message

# Demask the decrypted message
def demask_message(decrypted_message, power, public_key):
    n, _ = public_key
    n_sq = n * n
    power_inverse = mod_inverse(power, n_sq)
    demasked_message = (decrypted_message * power_inverse) % n
    return demasked_message

# Calculate the number of bits in an integer
def len_in_bits(x):
    return x.bit_length()

# Hash a password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Authenticate the user
def authenticate_user():
    stored_password = "password"
    stored_hashed_password = hash_password(stored_password)
    
    entered_password = input("Enter your password for decryption: ")
    hashed_entered_password = hash_password(entered_password)

    if hashed_entered_password == stored_hashed_password:
        print("Authentication successful!")
        return True
    else:
        print("Authentication failed! Incorrect password.")
        return False

# Homomorphic addition of ciphertexts
def homomorphic_addition(c1, c2, public_key):
    n, _ = public_key
    n_sq = n * n
    c_sum = (c1 * c2) % n_sq
    return c_sum

# Total processing time function for different bit sizes
def measure_processing_time(bit_size, authenticated):
    if not authenticated:
        return float('inf')  # Skip if authentication fails

    # Generate keypair
    start_time = time.time()
    public_key, private_key = generate_keypair(bits=bit_size)
    keygen_time = time.time() - start_time
    
    # Messages
    message1 = random.randint(1, 100)
    message2 = random.randint(1, 100)
    
    # Encryption
    start_time = time.time()
    ciphertext1 = encrypt(message1, public_key)
    ciphertext2 = encrypt(message2, public_key)
    encryption_time = time.time() - start_time
    
    # Masking
    start_time = time.time()
    masked_ciphertext1, power1 = mask_ciphertext(ciphertext1, public_key)
    masked_ciphertext2, power2 = mask_ciphertext(ciphertext2, public_key)
    masking_time = time.time() - start_time
    
    # Decryption
    start_time = time.time()
    decrypted_message1 = decrypt(masked_ciphertext1, private_key, public_key)
    decrypted_message2 = decrypt(masked_ciphertext2, private_key, public_key)
    decryption_time = time.time() - start_time
    
    # Comparison of bit lengths
    decrypted_message1_bits = len_in_bits(decrypted_message1)
    decrypted_message2_bits = len_in_bits(decrypted_message2)
    comparison_time = time.time() - start_time

    # Demasking
    start_time = time.time()
    demasked_message1 = demask_message(decrypted_message1, power1, public_key)
    demasked_message2 = demask_message(decrypted_message2, power2, public_key)
    demasking_time = time.time() - start_time
    
    # Total processing time
    total_time = (keygen_time + encryption_time + masking_time +
                  decryption_time + comparison_time + demasking_time)
    
    print(f"Key size: {bit_size}-bits, Total time: {total_time:.4f} seconds")
    return total_time

# Bit sizes to test
bit_sizes = [512, 1024, 2048, 3072, 4096]
times = []

# Authenticate user once
authenticated = authenticate_user()

# Measure total processing time for each bit size
for bits in bit_sizes:
    print(f"Measuring for {bits}-bit size...")
    total_time = measure_processing_time(bits, authenticated)
    times.append(total_time)

# Plot the graph
plt.plot(bit_sizes, times, marker='o')
plt.title('Total Processing Time vs Bit Size')
plt.xlabel('Bit Size (bits)')
plt.ylabel('Total Processing Time (seconds)')
plt.grid(True)
plt.show()

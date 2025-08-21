import random
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

    # Generate a random number r
    r = random.randint(1, n-1)

    # Encryption
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    
    return c

# Mask the ciphertext by raising it to a power
def mask_ciphertext(ciphertext, public_key):
    n, _ = public_key
    n_sq = n * n
    n_bits = len_in_bits(n)

    # Generate a random power for masking
    power = random.randint(2, n_bits)
    
    # Mask the ciphertext by raising it to the power modulo n^2
    masked_ciphertext = pow(ciphertext, power, n_sq)
    
    return masked_ciphertext, power

# Decrypt the masked ciphertext
def decrypt(masked_ciphertext, private_key, public_key):
    n, _ = public_key
    lambda_n, mu = private_key
    n_sq = n * n

    def L(x):
        return (x - 1) // n

    # Decrypt the masked ciphertext
    u = pow(masked_ciphertext, lambda_n, n_sq)
    l = L(u)
    
    # Decrypt the message
    message = (l * mu) % n
    return message

# Calculate the number of bits in an integer
def len_in_bits(x):
    return x.bit_length()

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=512)

    # Take a message input from user
    message = int(input("Enter the message to encrypt (as an integer): "))

    # Define the threshold value (for comparison, hardcoded as 72)
    threshold = 72

    # Encrypt the message and the threshold
    ciphertext_message = encrypt(message, public_key)
    ciphertext_threshold = encrypt(threshold, public_key)

    # Mask the ciphertexts
    masked_ciphertext_message, power_message = mask_ciphertext(ciphertext_message, public_key)
    masked_ciphertext_threshold, power_threshold = mask_ciphertext(ciphertext_threshold, public_key)

    # Decrypt the masked threshold before demasking
    decrypted_threshold = decrypt(masked_ciphertext_threshold, private_key, public_key)

    # Subtract the masked message from the masked threshold using modular inverse
    n, _ = public_key
    n_sq = n * n

    # Calculate the modular inverse of masked_ciphertext_message as (n - 1)
    masked_ciphertext_message_inv = pow(masked_ciphertext_message, n-1, n_sq)

    # Subtract (i.e., multiply by inverse) the masked message from the masked threshold
    masked_difference = (masked_ciphertext_threshold * masked_ciphertext_message_inv) % n_sq

    # Decrypt the result of subtraction
    decrypted_difference = decrypt(masked_difference, private_key, public_key)

    # Calculate the bit length of the decrypted difference
    decrypted_difference_bits = len_in_bits(decrypted_difference)

    # Calculate n_bits/2 as the comparison condition
    n_bits = len_in_bits(n)
    compare_condition = n_bits / 4

    print(f"\nDecrypted Difference bit length: {decrypted_difference_bits} bits")
    print(f"Comparison Condition (n_bits / 2): {compare_condition} bits")

    # Compare the decrypted_difference_bits with compare_condition
    if decrypted_difference_bits < compare_condition:
        print("The decrypted difference is less than the threshold.")
    else:
        print("The decrypted difference is greater than the threshold.")

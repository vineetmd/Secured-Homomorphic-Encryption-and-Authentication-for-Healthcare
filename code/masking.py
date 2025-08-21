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

    # Generate a random power for masking
    power = random.randint(2, n-1)
    
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

# Demask the decrypted message
def demask_message(decrypted_message, power, public_key):
    n, _ = public_key
    n_sq = n * n

    # Find the inverse of the power
    power_inverse = mod_inverse(power, n_sq)

    # Directly multiply the decrypted message by the inverse of the power
    demasked_message = (decrypted_message * power_inverse) % n
    
    return demasked_message

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=512)

    # Take input message from user
    message = int(input("Enter the message to encrypt (as an integer): "))

    # Encrypt the message
    ciphertext = encrypt(message, public_key)

    # Mask the ciphertext by raising it to a power
    masked_ciphertext, power = mask_ciphertext(ciphertext, public_key)
    print(f"Masked Ciphertext: {masked_ciphertext}")

    # Decrypt the masked ciphertext
    decrypted_message = decrypt(masked_ciphertext, private_key, public_key)
    print(f"Decrypted Message (masked): {decrypted_message}")

    # Demask the decrypted message
    demasked_message = demask_message(decrypted_message, power, public_key)
    print(f"Demasked Message: {demasked_message}")

    # Display results
    print(f"\nOriginal message: {message}")
    print(f"Decrypted message after masking and demasking: {demasked_message}\n")

import hashlib
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

# Demask the decrypted message
def demask_message(decrypted_message, power, public_key):
    n, _ = public_key
    n_sq = n * n

    # Find the inverse of the power
    power_inverse = mod_inverse(power, n_sq)

    # Directly multiply the decrypted message by the inverse of the power
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
    stored_password = "password"  # Actual plain password
    stored_hashed_password = hash_password(stored_password)
    
    entered_password = input("Enter your password for decryption: ")
    hashed_entered_password = hash_password(entered_password)
    
    # Debugging output
    print(f"Stored hashed password: {stored_hashed_password}")
    print(f"Entered hashed password: {hashed_entered_password}")

    if hashed_entered_password == stored_hashed_password:
        print("Authentication successful!")
        return True
    else:
        print("Authentication failed! Incorrect password.")
        return False

if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=512)

    # Take two input messages from user
    message1 = int(input("Enter the first message to encrypt (as an integer): "))
    message2 = int(input("Enter the second message to encrypt (as an integer): "))

    # Encrypt both messages
    ciphertext1 = encrypt(message1, public_key)
    ciphertext2 = encrypt(message2, public_key)

    # Mask the ciphertexts by raising them to a power
    masked_ciphertext1, power1 = mask_ciphertext(ciphertext1, public_key)
    masked_ciphertext2, power2 = mask_ciphertext(ciphertext2, public_key)

    # Authenticate before decryption
    if authenticate_user():
        # Decrypt both masked ciphertexts
        decrypted_message1 = decrypt(masked_ciphertext1, private_key, public_key)
        decrypted_message2 = decrypt(masked_ciphertext2, private_key, public_key)

        # Compare bit lengths of the decrypted messages
        decrypted_message1_bits = len_in_bits(decrypted_message1)
        decrypted_message2_bits = len_in_bits(decrypted_message2)

        print(f"Decrypted Message 1 bit length: {decrypted_message1_bits} bits")
        print(f"Decrypted Message 2 bit length: {decrypted_message2_bits} bits")

        # Check if the first decrypted message is greater, smaller, or equal in bit length to the second
        if decrypted_message1_bits > decrypted_message2_bits:
            print("Decrypted Message 1 is greater than Decrypted Message 2 (in bit length).")
        else:
            print("Decrypted Message 1 is smaller than Decrypted Message 2 (in bit length).")

        # Demask both decrypted messages
        demasked_message1 = demask_message(decrypted_message1, power1, public_key)
        demasked_message2 = demask_message(decrypted_message2, power2, public_key)

        # Display the original demasked messages
        print(f"\nDemasked Message 1: {demasked_message1}")
        print(f"Demasked Message 2: {demasked_message2}")
    else:
        print("Decryption aborted due to failed authentication.")

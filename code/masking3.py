import random
from sympy import isprime, mod_inverse
import time
import matplotlib.pyplot as plt

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
    r = random.randint(1, n-1)
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# Mask the ciphertext
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

# Compare the bit lengths of n decrypted messages and measure the time taken
def compare_bit_lengths(n, public_key, private_key):
    messages = [random.randint(1, 100) for _ in range(n)]  # Generate n random messages
    decrypted_messages_bits = []
    
    start_time = time.time()  # Start timer

    for message in messages:
        ciphertext = encrypt(message, public_key)
        masked_ciphertext, power = mask_ciphertext(ciphertext, public_key)
        decrypted_message = decrypt(masked_ciphertext, private_key, public_key)
        decrypted_message_bits = len_in_bits(decrypted_message)
        decrypted_messages_bits.append(decrypted_message_bits)

    end_time = time.time()  # End timer
    time_taken = end_time - start_time

    return time_taken

# Main function
if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(bits=2048)

    # Measure the time for comparing 2 to 10 decrypted message bit lengths
    times = []
    num_messages = list(range(2, 11))

    for n in num_messages:
        time_taken = compare_bit_lengths(n, public_key, private_key)
        times.append(time_taken)
        print(f"Time taken to compare {n} decrypted message bit lengths: {time_taken:.6f} seconds")

    # Plotting the bar graph
    plt.bar(num_messages, times, color='orange')
    plt.title('Time taken to compare N decrypted message bit lengths for 2048 bit keylength')
    plt.xlabel('Number of messages compared')
    plt.ylabel('Time taken (seconds)')
    plt.xticks(num_messages)  # Ensure all numbers appear on the x-axis
    plt.grid(True, axis='y')
    plt.show()

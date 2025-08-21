import random
import csv
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
    r = random.randint(1, n - 1)

    # Encryption
    c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
    
    return c

# Mask the ciphertext by raising it to a fixed power
def mask_ciphertext(ciphertext, public_key, power=8):
    n, _ = public_key
    n_sq = n * n
    
    # Mask the ciphertext by raising it to the fixed power modulo n^2
    masked_ciphertext = pow(ciphertext, power, n_sq)
    
    return masked_ciphertext

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

# Function to read inputs from a CSV file
def read_inputs_from_csv(file_name, max_entries=500):
    messages = []
    with open(file_name, mode='r') as file:
        csv_reader = csv.reader(file)
        headers = next(csv_reader)  # Skip the header row
        print(f"CSV Headers: {headers}")  # Debug line
        count = 0
        for row in csv_reader:
            if count >= max_entries:
                break
            if row and row[0].isdigit():  # Ensure the row is not empty and the value is numeric
                messages.append(int(row[0]))
                count += 1
            else:
                print(f"Skipped non-numeric or empty row: {row}")  # Debug line
    return messages

if __name__ == "__main__":
    # Read messages from CSV file
    file_name = 'input.csv'  # Ensure the file is in the same directory as the script
    messages = read_inputs_from_csv(file_name, max_entries=5000)

    # Set the threshold value
    threshold = 85

    # Generate keys
    public_key, private_key = generate_keypair(bits=512)

    # Initialize counters
    count_greater = 0
    count_less = 0
    count_equal = 0

    for message in messages:
        # Encrypt the message and the threshold
        ciphertext_message = encrypt(message, public_key)
        ciphertext_threshold = encrypt(threshold, public_key)

        # Mask the ciphertexts with a fixed power
        fixed_power = 8
        masked_ciphertext_message = mask_ciphertext(ciphertext_message, public_key, fixed_power)
        masked_ciphertext_threshold = mask_ciphertext(ciphertext_threshold, public_key, fixed_power)

        # Calculate the modular inverse of the masked input value raised to the power (n-1)
        n, _ = public_key
        n_sq = n * n
        masked_ciphertext_message_inv = pow(masked_ciphertext_message, n - 1, n_sq)

        # Calculate the difference by multiplying the masked threshold with the modular inverse
        masked_difference = (masked_ciphertext_threshold * masked_ciphertext_message_inv) % n_sq

        # Decrypt the result of subtraction
        decrypted_difference = decrypt(masked_difference, private_key, public_key)

        # Calculate the bit length of the decrypted difference
        decrypted_difference_bits = len_in_bits(decrypted_difference)

        # Calculate n_bits / 2 for comparison
        n_bits = len_in_bits(n)
        compare_condition = n_bits / 2

        print(f"\nMessage: {message}")
        print(f"Decrypted Difference bit length: {decrypted_difference_bits} bits")
        print(f"Comparison Condition (n_bits / 2): {compare_condition} bits")

        # Compare the decrypted_difference_bits with the comparison condition
        if decrypted_difference_bits == 0:
            print("Input is equal to threshold")
            count_equal += 1
        elif decrypted_difference_bits < compare_condition:
            print("The decrypted difference is less than the threshold.")
            count_less += 1
        else:
            print("The decrypted difference is greater than the threshold.")
            count_greater += 1

    # Print the counts
    print(f"\nCount of messages equal to the threshold: {count_equal}")
    print(f"Count of messages less than the threshold: {count_less}")
    print(f"Count of messages greater than the threshold: {count_greater}")

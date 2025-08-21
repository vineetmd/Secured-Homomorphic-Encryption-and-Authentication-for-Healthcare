import os
import random
import json
import logging
from phe import paillier

class Server:
    def __init__(self):
        # Generate Paillier keypair for the server
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
        self.users_db_path = "users_db.json"

        # Load the users' database, create it if it doesn't exist
        self.users_db = self.load_or_create_users_db()

    def load_or_create_users_db(self):
        # Create the JSON file if it doesn't exist
        if not os.path.exists(self.users_db_path):
            with open(self.users_db_path, 'w') as f:
                json.dump({}, f)  # Initialize with an empty dictionary
            logging.info("User database created.")

        # Load existing user data
        with open(self.users_db_path, 'r') as f:
            return json.load(f)

    def save_users_db(self):
        # Save the users' database to JSON
        with open(self.users_db_path, 'w') as f:
            json.dump(self.users_db, f, indent=4)
        logging.debug("User database saved.")

    def is_username_taken(self, username):
        # Check if the username is already registered
        return username in self.users_db

    def register_user(self, username, hashed_password, user_public_key):
        if self.is_username_taken(username):
            logging.error(f"Username '{username}' is already taken.")
            return False
        # Store the user's hashed password and public key
        self.users_db[username] = {
            'hashed_password': hashed_password,
            'public_key': user_public_key.n  # Store the n value of the public key
        }
        self.save_users_db()
        logging.info(f"User '{username}' registered successfully with hashed password and public key.")
        return True

    def generate_challenge(self):
        # Generate a random challenge
        challenge = random.randint(1, 10000)
        return challenge

    def encrypt_challenge(self, challenge, user_public_key_n):
        # Create PaillierPublicKey from the integer stored in the database
        user_public_key = paillier.PaillierPublicKey(n=user_public_key_n)
        return user_public_key.encrypt(challenge)

    def set_challenge(self, challenge):
        self.challenge = challenge

    def validate_response(self, username, enc_response):
        # Retrieve user's information
        user_info = self.users_db[username]
        stored_hashed_password = int(user_info['hashed_password'], 16)

        # Decrypt the response using the server's private key
        decrypted_sum = self.private_key.decrypt(enc_response)
        logging.debug(f"Server decrypted the response: {decrypted_sum}")

        # Validate the response
        if decrypted_sum == self.challenge + stored_hashed_password:
            logging.info(f"Login successful for user: {username}")
            return True
        else:
            logging.error(f"Login failed for user: {username}")
            return False

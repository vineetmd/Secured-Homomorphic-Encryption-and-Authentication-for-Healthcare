import hashlib
from phe import paillier
import os
import json
import logging

class User:
    def __init__(self, username, password, is_registration=True):
        self.username = username
        self.hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Check if user is registering or logging in
        if is_registration:
            # Generate a new Paillier keypair for the user during registration
            self.public_key, self.private_key = paillier.generate_paillier_keypair()
            self.save_keypair()
            logging.debug(f"New Paillier keypair generated for user '{self.username}'.")
        else:
            # Load existing keypair during login
            self.load_keypair()

    def save_keypair(self):
        """Save the user's key pair to a file."""
        keypair_path = f"{self.username}_keys.json"
        with open(keypair_path, 'w') as f:
            json.dump({
                'public_key': self.public_key.n,
                'private_key_p': self.private_key.p,
                'private_key_q': self.private_key.q
            }, f)
        logging.debug(f"Keypair for user '{self.username}' saved to {keypair_path}.")

    def load_keypair(self):
        """Load the user's key pair from a file."""
        keypair_path = f"{self.username}_keys.json"
        if os.path.exists(keypair_path):
            with open(keypair_path, 'r') as f:
                keys = json.load(f)
                n = keys['public_key']
                p = keys['private_key_p']
                q = keys['private_key_q']
                self.public_key = paillier.PaillierPublicKey(n=n)
                self.private_key = paillier.PaillierPrivateKey(self.public_key, p, q)
            logging.debug(f"Keypair for user '{self.username}' loaded from {keypair_path}.")
        else:
            raise ValueError(f"No keypair found for user {self.username}.")

    def encrypt_challenge(self, challenge, server_public_key):
        enc_challenge = server_public_key.encrypt(challenge)
        enc_hashed_password = server_public_key.encrypt(int(self.hashed_password, 16))
        logging.debug(f"Challenge and hashed password encrypted by user '{self.username}'.")
        return enc_challenge + enc_hashed_password

    def decrypt_challenge(self, enc_challenge):
        logging.debug(f"User '{self.username}' decrypting challenge.")
        return self.private_key.decrypt(enc_challenge)

    def get_public_key(self):
        return self.public_key

"""
Voting token authority.

This simulates election commission issuing one-time tokens.
"""

import secrets
import hashlib 
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class TokenAuthority:
    def __init__(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def issue_token(self):
        """
        Create signed voting token.
        """
        token = secrets.token_bytes(32)

        signature = self.private_key.sign(token)

        return token.hex(), signature.hex()
    
    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        ).hex()
    
    def hash_token(token_hex:str)-> str:
        return hashlib.sha256(bytes.fromhex(token_hex)).hexdigest()
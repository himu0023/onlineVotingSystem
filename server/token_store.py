"""
Pulic log of used token hashes.
"""

import json
import os 


class TokenRegistry:
    
    def __init__(self, path = "used_tokens.json"):
        self.path = path 

        if not os.path.exists(self.path):
            with open(self.path, "w") as f:
                json.dump([], f)
    
    
    def is_used(self, token_hash):
        tokens = self.get_all()
        return token_hash in tokens
    
    def mark_used(self, token_hash):
        tokens = self.get_all()
        tokens.append(token_hash)

        with open(self.path, "w") as f:
            json.dump(tokens, f, indent=2)

    def get_all(self):
        with open(self.path, "r") as f:
            return json.load(f)
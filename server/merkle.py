import hashlib
from typing import List, Tuple

def _hash(data: bytes)-> bytes:
    return hashlib.sha256(data).digest()

def hash_leaf(data: bytes)->bytes:
    # Domain sepration
    return _hash(b"L"+data)

def hash_node(left:bytes, right:bytes)->bytes:
    return _hash(b"N"+left+right)

class MerkleTree:
    """
    Full Markel tree with inclusion proof support.
    """

    def __init__(self):
        self.leaves: List[bytes] = []

    def add_leaf(self, data:bytes):
        self.leaves.append(hash_leaf(data))

    def build_tree(self) ->List[List[bytes]]:
        """
        Returns full tree layers bottom-up.
        """
        if not self.leaves:
            return[[b"\x200"*32]]
        
        layers = [self.leaves]

        while len(layers[-1])>1:
            current = layers[-1]
            next_layer = []

            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i+1] if i + 1 < len(current) else left
                next_layer.append(hash_node(left, right))

            layers.append(next_layer)

        return layers
    
    def root(self) -> bytes:
        tree = self.build_tree()
        return tree[-1][0]
    
    def inclusion_proof(self, index: int)-> List[Tuple[bytes, str]]:
        """
        Returns Merkle inclusion proof:
        [(sibling_hash, 'L' or 'R'),...]
        """

        tree = self.build_tree()
        proof = []
        idx = index

        for level in tree[:-1]:
            if idx % 2 == 0:
                sibling = level[idx+1] if idx +1 < len(level) else level[idx]
                proof.append((sibling, "R"))
            else:
                sibling = level[idx-1]
                proof.append((sibling, "L"))

            idx //= 2
        
        return proof
    

def verify_inclusion(leaf_data: bytes, proof, root:bytes) -> bool:
    current = hash_leaf(leaf_data) 

    for sibling, direction in proof:
        if direction == "R":
            current = hash_node(current, sibling)
        else:
            current = hash_node(sibling, current)

    return current == root
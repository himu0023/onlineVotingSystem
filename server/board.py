from server.merkle import MerkleTree
from server.storage import AppendOnlyStorage
from server.utils import canonical_json

class BulletinBoard:
    """
    Tamper-evident public bulletin board.
    """

    def __init__(self):
        self.storage = AppendOnlyStorage()
        self.tree = MerkleTree()

        # rebuild Merkle tree on startip
        for entry in self.storage.load_all():
            self.tree.add_leaf(canonical_json(entry))

    
    def post_ballot(self, ballot: dict):
        """
        append only Operation
        """

        serialized = canonical_json(ballot)

        # Persist first 
        self.storage.append(ballot)

        # then update Merkle tree
        self.tree_add_leaf(serialized)

    def get_all_ballots(self):
        return self.storage.load_all()
    
    def get_merkle_root(self) -> str:
        return self.tree.root().hex()
    
    def get_inclusion_proof(self, index:int):
        ballots = self.storage.load_all()

        if index < 0 or index >= len(ballots):
            raise IndexError("Invalid ballot index")
        
        serialized = canonical_json(ballots[index])
        proof = self.tree.inclusion_proof(index)

        return {
            "leaf": serialized.decode(),
            "proof": [(h.hex(), d) for h, d in proof],
            "root": self.get_merkle_root()
        }
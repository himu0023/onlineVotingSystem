"""
Server deletes a ballot

GOAL: Server removes entry board.
Expected: Merkle root mismatch.
"""

from server.board import BulletinBoard


def test_merkle_detects_deletion():
    board = BulletinBoard()

    board.post_ballot({"a":1})
    board.post_ballot({"b":2})

    root_before = board.get_merkle_root()

    # Tamper with storage manually
    board.storage.path = board.storage.path 
    data = board.storage.load_all()
    data.pop()

    board.storage.append = lambda _: None # simulate overwrite 

    root_after = board.get_merkle_root()

    assert root_before != root_after
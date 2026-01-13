"""
This file defines what it means for an election to be VALID.

Every other component (client, server, trustees, crypto) must produce objects that satisfy this verifer.

Nothing is trusted. Everything is checked.
"""

from dataclasses import dataclass
from typing import List


# PROTOCOL OBJECTS:

class Ciphertext:
    """
    Represents an encrypted vote.
    For now  this is just a placeholder for cryptographic data.
    """
    c1: int
    c2: int

@dataclass
class BallotProof:
    """
    Zero-knowledge proof that:
    - the ciphertext encodes a valid vote
    - the vote is in the allowed domain(e.g. {0,1})
    """
    data:bytes

@dataclass
class Ballot:
    """
    A single submitted ballot.
    """
    ciphertext: Ciphertext
    proof: BallotProof

@dataclass
class DecryptionShare:
    """
    A trustee's partial decryption.
    """
    trustee_id: int
    value: int
    proof: bytes

@dataclass
class ElectionTranscript:
    """
    Everything that is publicly available for an election.
    """
    public_key: int
    ballots: List[Ballot]
    shares: List[DecryptionShare]


#  VERIFIC LOGIC

def verify_ballot(ballot: Ballot, public_key:int) -> bool:
    """
    Checks whether a single ballot is cryptographically valid.

    For now this is a stub. We will replace it with real ZK Verification later.
    """

    # Placeholder: we accept all ballots for now
    return True

def verify_share(share: DecryptionShare, public_key: int, aggregated_ciphertext: Ciphertext) -> bool:
    """
    Checks wheather a trustee's decryption share is valid.

    For now this is a stub.
    """
    return True

def aggregate_ciphertexts(ciphertext: List[Ciphertext])-> Ciphertext:
    """
    Combine all encrypted votes into one encrypted tally.

    This will later use ElGamal homomorphism.
    """
    c1 = 1
    c2 = 2
    for ct in ciphertext:
        c1 *= ct.c1
        c2 *=ct.c2
    return Ciphertext(c1, c2)

def verify_election(transcript: ElectionTranscript, threshold: int)-> bool:
    """
    The core truth function.

    Return Ture if and only if the election transcript is valid.
    """

    # 1. Verify all ballots
    for ballot in transcript.ballots:
        if not verify_ballot(ballot, transcript.public_key):
            print("Invlaid ballot detected")
            return False
        
    # 2. Aggregate encrypted votes
    ciphertexts = [b.ciphertext for b in transcript.ballots]
    aggregated = aggregate_ciphertexts(ciphertexts)

    # 3. Verify enough descryption shares exist
    if len(transcript.shares) < threshold:
        print("Not enough decryption shares")
        return False
    
    # 4. Verify each dectyption share
    for share in transcript.shares:
        if not verify_share(share, transcript.public_key, aggregated):
            print(f"Invalid decryption share from trustee {share.trustee_id}")
            return False
    
    # If all checks passed, the election is cryptographically sound
    return True
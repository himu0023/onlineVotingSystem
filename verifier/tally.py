"""
This file defines what it means for an election to be VALID.

Every other component (client, server, trustees, crypto) must produce objects that satisfy this verifer.

Nothing is trusted. Everything is checked.
"""

from dataclasses import dataclass
from typing import List
from crypto.elgamal import ElGamalCiphertext
from crypto.zk_ballot import verify_bit
from trustees.decrypt import verify_partial_decryption, combine_partial_decryptions


# PROTOCOL OBJECTS:

Ciphertext = ElGamalCiphertext

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
    return verify_bit(public_key, ballot.ciphertext, ballot.proof)

def verify_share(share: DecryptionShare, public_key: int, aggregated_ciphertext: Ciphertext) -> bool:
    """
    Checks wheather a trustee's decryption share is valid.

    For now this is a stub.
    """
    return True

def aggregate_ciphertexts(ciphertexts: List[ElGamalCiphertext])-> ElGamalCiphertext:
    """
    Homomorphically combine all encryped ballots.
    """
    if len(ciphertexts) ==0:
        raise ValueError("No ballots submitted")
   
    total = ciphertexts[0]

    for ct in ciphertexts[1:]:
        total = total*ct

    return total



def verify_election(transcript: ElectionTranscript, threshold: int) -> int:
    """
    Verifies election and returns final tally.

    Raises exception if anything is invalid.
    """

    pk = transcript.public_key

    # 1️⃣ Verify all ballots (ZK proofs)

    for ballot in transcript.ballots:
        valid = verify_bit(pk, ballot.ciphertext, ballot.proof)
        if not valid:
            raise ValueError("Invalid ballot proof detected")

    # 2️⃣ Homomorphic aggregation

    ciphertexts = [b.ciphertext for b in transcript.ballots]
    aggregated_ciphertext = aggregate_ciphertexts(ciphertexts)

    # 3️⃣ Threshold check

    if len(transcript.shares) < threshold:
        raise ValueError("Not enough decryption shares")

    # 4️⃣ Verify each trustee decryption proof

    valid_partials = []

    for share in transcript.shares:
        ok = verify_partial_decryption(pk, aggregated_ciphertext, share)
        if not ok:
            raise ValueError(f"Invalid trustee proof: Trustee {share.trustee_id}")

        valid_partials.append(share)

    # 5️⃣ Combine partial decryptions

    gm = combine_partial_decryptions(pk, aggregated_ciphertext, valid_partials)

    # 6️⃣ Decode final tally (brute-force discrete log)

    tally = brute_force_discrete_log(pk.g, gm, pk.p)

    return tally
    
# HELPER 

def brute_force_discrete_log(g, value, p, limit = 10000):
    """
    Because this is a demo system, we brute-force tally extraction.

    Works because number of voters is small.
    """

    cur = 1
    for i in range(limit):
        if cur == value:
            return i
        cur = (cur*g)%p

    raise ValueError("Tally too large or invalid")
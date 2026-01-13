"""
Defines what values are allowed to be encrypted as votes.

This is NOT just validation.
This defines the mathematical meaning of a vote.
"""

ALLOWED_VOTES = {0,1}

def encode_vote(v: int) -> int:
    """
    Maps a vote to a number that can be encrypted.

    For binary voting:
        0 = no 
        1 = yes
    """
    if v not in ALLOWED_VOTES:
        raise ValueError(f"Invalid vote: {v}")
    return v

def decode_tally(total: int) -> int :
    """
    Maps decrypted group value back to a real-world tally.

    If we have N votes, the decrypted result is:
        sum of all encoded votes
    """
    if total < 0:
        raise ValueError("Negative tally impossible")
    
    return total
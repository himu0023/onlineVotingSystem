"""
Double Voting attack

GOAL : Resuse same token twice 
Expected: Verifier detects duplicate token hash.
"""

from verifier.tally import ElectionTranscript



def test_duplicate_token_detection():
    ballots = [
        {"token_hash": "abc"},
        {"token_hash": "abc"} # Duplicate
    ]

    seen = set()

    for b in ballots:
        h = b["token_hash"]
        assert h not in seen 
        seen.add(h)
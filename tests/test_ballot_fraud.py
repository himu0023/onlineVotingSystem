"""
Invalid ballot injection attack

GOAL : Attackers submits encrypted vote = 5 instead of 1. 
Expected : Verifier must reject
"""
 

import pytest 

from crypto.elgamal import keygen, encrypt
from verifier.tally import Ballot, ElectionTranscript, verify_election


def test_invalid_vote_rejected():
    pk, sk, _ = keygen()


    # Bypass encode_vote and cheat 
    ct, proof = encrypt(pk, 1)  

    # Fake proof 
    fake_proof = ("fake",)

    ballot = Ballot(ct, fake_proof)
    
    transcript = ElectionTranscript(
        public_key = pk, 
        ballots = [ballot],
        shares=[]
    )

    with pytest.reaises(Exception):
        verify_election(transcript, threshold=1)
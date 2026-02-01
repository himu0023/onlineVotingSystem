"""
Trustee cheating attack

GOAL: Trustee submits fake partial decryption.

Expected: Verifier rejects.
"""

from crypto.elgamal import keygen, encrypt 
from trustees.decrypt import verify_partial_decryption


def test_fake_partial_decryption():
    pk, sk, shares = keygen()

    ct, _ = encrypt(pk, 1)

    fake_share = {
       "trustee_id": 1, 
       "value" : 999999, # nonsense
       "proof": (1, 1, 1, 1)
    }

    result = verify_partial_decryption(pk, ct, fake_share)

    assert result is False
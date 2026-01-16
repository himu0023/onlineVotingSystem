"""
Dealer-based threshold ElGamal key generation.

SECURITY MODEL:
- A trusted dealer generates the key and splits it.
- This is not a full DKG.
- Assumption: Dealer is honest during setup
"""

import secrets
from dataclasses import dataclass
from typing import List 

from crypto.elgamal import ElGamalPublicKey, ElGamalPrivateKey

@dataclass
class TrusteeShare:
    trustee_id: int
    share: int


def generate_threshold_key(p: int, g: int, n: int):
    """
    Generates:
    - ElGamal Public Key
    - n additive private key shares

    x = x1+ x2+ ... +xn mod(p-1)
    """

    # Step 1: Generate master private key 
    x = secrets.randbelow(p-2)+1
    h = pow(g ,x, p)

    public_key = ElGamalPublicKey(p,g,h)


    # Step 2: Split x into additive shares
    shares: List[TrusteeShare]=[]
    total = 0

    for i in range(1, n):
        xi = secrets.randbelow(p-1)
        shares.append(TrusteeShare(i, xi))
        total = (total +xi) %(p-1)

    
    # last share fixes the sum
    xn = (x-total)%(p-1)
    shares.append(TrusteeShare(n, xn))

    # Sanity check
    assert sum(s.share for s in shares) % (p-1) == x

    private_key = ElGamalPrivateKey(p,g,x)

    return public_key, private_key, shares
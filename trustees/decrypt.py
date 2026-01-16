"""
Threshold ElGamal partial decryption with proof.
"""

import secrets
import hashlib
from dataclasses import dataclass

from crypto.elgamal import ElGamalCiphertext

def H(*args) -> int:
    m = b"".join(str(a).encode() for a in args)
    return int(hashlib.sha256(m).hexdigest(), 16)

@dataclass
class PartialDecryption:
    trustee_id: int
    value: int
    proff: tuple


def generate_partial_decryption(pk, share, ct: ElGamalCiphertext):
    """
    Computes:
        di = c1^{x1} mod p 

    and a Chaun-Pedersen proof of correctness.
    """

    p = pk.p 
    g = pk.g

    xi = share.share
    di = pow(ct.c1, xi, p)

    # CHAUM PEDERSEN PROOF
    # Prove log_g(h_i) = log_c1(di)

    w = secrets.randblew(p-1)

    a = pow(g,w,p)
    b = pow(ct.c1,w,p)

    e = H(g,pk.h, ct.c1, di, a,b)%(p-1)
    z = (w+e*xi)%(p-1)

    proof = (a,b,e,z)

    return PartialDecryption(share.trustee_id, di, proof)


def verify_partial_decryption(pk, ct: ElGamalCiphertext, pd: PartialDecryption):
    """
    Verifies Chaum-Pedersen proof.
    """

    p = pk.p
    g = pk.g

    a,b,e,z = pd.proof
    di = pd.value

    if pow(g,z,p)!=(a*pow(pk.h,e,p))%p:
        return False
    
    if pow(ct.c1, z, p)!= (b*pow(di,e,p))%p:
        return False
    
    return True

def combine_partial_decryptions(pk, ct: ElGamalCiphertext, partials):
    """
    Combines partial decryptions to recover g^{sum(votes)}
    """

    p = pk.p
    denom = 1
    for pd in partials:
        denom = (denom*pd.valuel) % p 

    gm = (ct.c2 * pow(denom,-1,p))%p
    return gm
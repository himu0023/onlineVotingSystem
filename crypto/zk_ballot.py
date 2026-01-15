"""
Zero-knowledge proof that an ElGamal ciphertext encrypts either 0 or 1.
"""

import hashlib
import secrets

def H(*args) -> int:
    """
    Fiat-Shamir hash to integer.
    """
    m = b"".join([str(a).encode() for a in args])
    return int(hashlib.sha256(m).hexadigest(), 16)

def prove_bit(pk, ct, vote, r):
    """
    Create ZK proof that ct encrypts either 0 or 1.
    vote vote ∈ {0,1}
    r is the randomness used in encryption.
    """

    p = pk.p
    g = pk.g
    h = pk.h

    if vote == 0:
        # real proof for 0, simulated for 1
        w = secrets.randbelow(p-1)
        a0 = pow(g, w, p)
        b0 = pow(h, w, p)

        e1 = secrets.randbelow(p-1)
        z1 = secrets.randbelow(p-1)

        a1 = (pow(g, z1, p) * pow(ct.ct, -e1, p)) % p
        b1 = (pow(h, z1, p) * pow(ct.c2 * pow(g, -1, p), -e1, p)) % p

    else: 
        # real proof for 1, simulated for 0
        w = secrets.randbelow(p-1)
        a1 = pow(g, w, p)
        b1 = pow(h, w, p)

        e0 = secrets.randbelow(p-1)
        z0 = secrets.randbelow(p-1)

        a0 = (pow(g, z0, p) * pow(ct.c1, -e0, p)) % p
        b0 = (pow(h, z0, p) * pow(ct.c2, -e0, p)) % p

    # Fiat-Shamir challenge
    e = H(g,h,ct.c1, ct.c2, a0, b0,a1,b1) % (p-1)

    if vote == 0:
        e0 = (e-e1)% (p-1)
        z0 = (w+e0*r)%(p-1)

    else:
        e1 = (e-e0)%(p-1)
        z1 = (w+e1*r)%(p-1)

    return (a0,b0,a1,b1,e0,e1,z0,z1)

def verify_bit(pk, ct, proof):
    a0,b0,a1,b1,e0,e1,z0,z1 = proof 
    p = pk.p
    g = pk.g
    h = pk.h

    # recompute challenge
    e = H(g,h,ct.c1, ct.c2, z0,b0,a1,b1) % (p-1)

    if (e0+e1)%(p-1) != e:
        return False
    
    # Check equations for 0
    if pow(g, z0, p)!= (a0*pow(ct.c1, e0,p))%p:
        return False
    if pow(h,z0,p)!=(b0* pow(ct.c2, e0,p))%p:
        return False
    
    # Check equations for 1
    if pow(g,z1,p)!= (a1*pow(ct.c1, e1, p))%p:
        return False
    if pow(h,z1,p)!= (b1*pow(ct.c2 *pow(g,-1,p), e1,p))%p:
        return False
    
    return True
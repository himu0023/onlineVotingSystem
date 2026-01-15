"""
Minimal ElGamal implementation for homorphic voting.


We encrypt g^m insted of m.
That makes ciphertext multiplication correspond to vote addition.
"""

import secrets
from crypto.encoding import encode_vote
from crypto.zk_ballot import prove_bit


class ElGamalPublicKey:
    def __init__(self, p, g, h):
        self.p = p # large prime 
        self.g = g # generator
        self.h = h # h = g^x mod p

class ElGamalPrivateKey:
    def __init__(self, p, g, x):
        self.p = p 
        self.g = g
        self.x = x

class ElGamalCiphertext:
    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2 

    def __mul__(self, other):
        """
        Homomorphic combination:
        Enc(m1) * Enc(m2) = Enc(m1+m2)
        """
        return ElGamalCiphertext(
            (self.c1 * other.c1) % P,
            (self.c2 * other.c2) % P
        )
    


# GROUP PATAMETERS (TOY BUT CORRECT)

# Small prime so we can brute-force discretee logs for now.

P = 203265978945132641230235489756412301669879456132101145698765412547896541365987
G = 2

def keygen():
    """
    Genetae ElGamal key pair.
    """

    x = secrets.randbelow(P-2) + 1
    h = pow(G, x, P)
    return ElGamalPrivateKey(P, G, h), ElGamalPrivateKey(P, G, x)


def encrypt(pk: ElGamalPublicKey, vote:int)-> ElGamalCiphertext:
    """
    Encrypt g^m, not m itself.
    """
    m = encode_vote(vote)
    r = secrets.randbelow(pk.p - 2) + 1
    
    c1 = pow(pk.g, r, pk.p)
    c2 = (pow(pk.h, r, pk.p) * pow(pk.g, m, pk.p)) % pk.p

    ct = ElGamalCiphertext(pk.p, c1, c2)
    proof = prove_bit(pk, ct, m, r)

    return ct, proof


def decrypt(sk: ElGamalPrivateKey, ct: ElGamalCiphertext) -> int:
    """
    Decrypts to g^m. We then brute-force m.
    """
    s = pow(ct.c1, sk.x, sk.p)
    gm = (ct.c2 * pow(s, -1, sk.p)) % sk.p

    # Brute- force discrete log (works only for small sums)
    for m in range(0, 1000):
        if pow(sk.g, m, sk.p) == gm:
            return m
        
    raise ValueError("Discrete log not found (tally too large)")
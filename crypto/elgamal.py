"""
Minimal ElGamal implementation for homorphic voting.


We encrypt g^m insted of m.
That makes ciphertext multiplication correspond to vote addition.
"""

import secrets

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

def 
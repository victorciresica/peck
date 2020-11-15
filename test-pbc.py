from pypbc import *
from hashlib import sha256, sha3_256

stored_params = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
"""


class PECK:
    def __init__(self):
        self.params = Parameters(param_string=stored_params)
        self.pairing = Pairing(self.params)                             # Pairing Object
        self.r = 730750818665451621361119245571504901405976559617       # Group order
        self.g = Element.random(self.pairing, G1)                       # Generator
        self.x, self.y = self.keygen()                                  # Private and Public keys

    def keygen(self):
        x = get_random(self.r)
        y = self.g ** x
        return x, y

    def peck(self):
        w = ("Victor", "Iulian")                                        # KEYWORD SET
        s = get_random(self.r)                                          # RANDOM PARAM
        r = get_random(self.r)                                          # RANDOM PARAM

        A = self.g ** r
        B = self.y ** s
        C = list()
        for i in range(len(w)):
            hash1 = sha256()
            hash2 = sha3_256()
            hash1.update(bytearray(w[i], 'utf-8'))
            hash2.update(bytearray(w[i], 'utf-8'))
            h = Element.from_hash(self.pairing, G1, hash1.hexdigest())
            f = Element.from_hash(self.pairing, G1, hash2.hexdigest())
            C.append(h**r * f**s)

        return [A, B, C]

    def trapdoor(self):
        t = get_random(self.r)                                          # RANDOM PARAM
        TQ1 = self.g ** t

        w = ("Iulian", "Victor")                                        # KEYWORD SET
        TQ2 = Element.one(self.pairing, G1)
        for i in range(len(w)):
            hash1 = sha256()
            hash1.update(bytearray(w[i], 'utf-8'))
            TQ2 *= Element.from_hash(self.pairing, G1, hash1.hexdigest())
        TQ2 = TQ2 ** t

        TQ3 = Element.one(self.pairing, G1)
        for i in range(len(w)):
            hash2 = sha3_256()
            hash2.update(bytearray(w[i], 'utf-8'))
            TQ3 *= Element.from_hash(self.pairing, G1, hash2.hexdigest())
        TQ3 = TQ3 ** (t * pow(self.x, -1, self.r))

        return TQ1, TQ2, TQ3

    def test(self, TQ1, TQ2, TQ3, A, B, C):
        left = self.pairing.apply(TQ1, self.prod(C))
        right = self.pairing.apply(A, TQ2) * self.pairing.apply(B, TQ3)
        if left == right:
            print("Found!")

    def prod(self, C):
        prod = C[0]
        for i in range(1, len(C)):
            prod *= C[i]
        return prod


if __name__ == "__main__":
    peck_scheme = PECK()
    [A, B, C] = peck_scheme.peck()
    [TQ1, TQ2, TQ3] = peck_scheme.trapdoor()
    peck_scheme.test(TQ1, TQ2, TQ3, A, B, C)

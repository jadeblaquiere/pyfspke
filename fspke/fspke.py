# Copyright (c) 2017, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ecpy nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from Crypto.Random import random
import rabinmiller as rabinmiller
from pypbc import *
from simplebtree import SimpleBTree
from cwhash import CWHashFunction
from binascii import hexlify, unhexlify
import json

"""fspke implements a cryptosystem based on the Canetti, Halevi and Katz
   model as defined in "A Forward-Secure Public-Key Encryption Scheme",
   published in Eurocrypt2003, archived (https://eprint.iacr.org/2003/083).
   This asymmetric encryption model enables encryption of data based on a
   static public key and a defined set of intervals. The private key has
   the ability to evolve over time to "forget" the ability to decrypt
   messages from previous intervals (forward security) such that messages
   from previous intervals cannot be decrypted if the revised (pruned) public
   key is divulged.

   The Canetti-Halevi-Katz scheme uses symmetric pairings of Elliptic
   Curves (ECs), G1 X G1 -> G2, where elements in G1 are EC points and
   elements in G2 are polynomials in Fp2 (F-p-squared). Messages (M) are
   in Fp2. Ciphertexts include multiple EC points and an element in Fp2.
   The Public Key includes parameters of the curves, pairing and a universal
   hash function.
"""

class CHKPublicKey (object):
    def __init__(self, depth):
        if (depth != int(depth)) or (depth < 0):
            raise ValueError('Invalid Input: depth must be positive integer')
        self.depth = depth
        self.params = None
        self.pairing = None
        self.P = None
        self.Q = None
        self.cwH = None
        self.C = None
        self.H = self.hashFunc
        self.tree = SimpleBTree(init=CHKPublicKey._btree_init)
        self.eQH = None

    def publicKeyToJSON(self):
        pubkey = {}
        pubkey['params'] = str(self.params)
        pubkey['P'] = str(self.P)
        pubkey['Q'] = str(self.Q)
        pubkey['l'] = self.depth
        cwhf = {}
        cwhf['q'] = self.cwH.q
        cwhf['p'] = self.cwH.p
        cwhf['a'] = self.cwH.a
        cwhf['b'] = self.cwH.b
        hashfunc = {}
        hashfunc['C'] = str(self.C)
        hashfunc['cwH'] = cwhf
        pubkey['H'] = hashfunc
        pubkeyJ = json.dumps(pubkey)
        print('pubkey exported as:')
        print(pubkeyJ)
        print()
        return pubkeyJ

    @staticmethod
    def publicKeyFromJSON(pubkeyJ):
        pubkey = json.loads(pubkeyJ)
        pke = CHKPublicKey(pubkey['l'])
        pke._importPubkeyFromDict(pubkey)
        return pke

    def _importPubkeyFromDict(self, pubkey):
        print('pubkey imported as:')
        print(pubkey)
        print()
        self.params = Parameters(param_string=pubkey['params'])
        self._validateParams()
        self.pairing = Pairing(self.params)
        self.P = Element(self.pairing, G1, value=pubkey['P'])
        self.Q = Element(self.pairing, G1, value=pubkey['Q'])
        hashfunc = pubkey['H']
        self.C = Element(self.pairing, G1, value=hashfunc['C'])
        cwhf = hashfunc['cwH']
        self.cwH = CWHashFunction(cwhf['q'], cwhf['p'],
                                 cwhf['a'], cwhf['b'])
        self.H = self.hashFunc
        self.gt = self.pairing.apply(self.P, pke.Q)
        self.tree = SimpleBTree(init=CHKPublicKey._btree_init)
        self.eQH = self.pairing.apply(self.Q, self.H(self.tree.nodeId()))

    def _validateParams(self):
        strparams = str(self.params).split()
        # print(strparams.split())
        self.q = int(strparams[3])
        if rabinmiller.isPrime(self.q) != True:
            raise ValueError("q must be prime")
        self.h = int(strparams[5])
        self.r = int(strparams[7])
        if rabinmiller.isPrime(self.r) != True:
            raise ValueError("p must be prime")
        if (self.q + 1) != (self.h * self.r):
            raise ValueError("h * r must equal p + 1")

    @staticmethod
    def _btree_init(node):
        node.R = []
        node.S = None

    def hashFunc(self,x):
        """hashFunc uses the Carter Wegman hash function to has to Zr and
           then maps Zr -> Qp via scalar multiplication by generator P
        """
        return self.C * self.cwH.hashval(x)

    def _hashlist(self, depth, ordinal):
        node = self.tree.findByAddress(depth, ordinal)
        if depth == 0:
            return []
        else:
            phash = self._hashlist(depth-1, ordinal>>1)
            shash = phash[:]
            H = self.H(node.nodeId())
            # print("hash for node %d = %s" % (node.nodeId(), str(H)))
            shash.append(H)
            return shash

    def Enc(self, M, ordinal, lam=None):
        """Enc is the encryption function which takes a single element
           and encrypts it using the encryption key for specific interva
        """
        # assume M in GT
        # lambda is a python reserved word, so lam means lambda
        if lam is None:
            lam = Element.random(self.pairing, Zr)
        hlist = self._hashlist(self.depth, ordinal)
        Ct = []
        Ct.append(str(self.P * lam))
        for H in hlist:
            # print("type,h = ", type(h), h)
            # H = self.P * h
            # print("type,H = ", type(H), H)
            Ct.append(str(H * lam))
        d = pow(self.eQH, lam)
        # print("type,m = ", type(m), m)
        # print("type,d = ", type(d), d)
        Ct.append(str(M * d))
        return Ct


class CHKPrivateKey (CHKPublicKey):
    def __init__(self,depth,qbits, rbits):
        if (qbits != int(qbits)) or (qbits < 0):
            raise ValueError("Invalid Input: qbits must be positive integer")
        if (rbits != int(rbits)) or (rbits < 0):
            raise ValueError("Invalid Input: rbits must be positive integer")
        if rbits > (qbits - 4):
            raise ValueError("Invalid Input: rbits cannot be > qbits - 4")
        super(self.__class__, self).__init__(depth)
        self.Gen(depth,qbits,rbits)

    def Gen(self,depth,qbits,rbits):
        # parameters specify "type A" pairing (symmetric)
        self.depth = depth
        self.params = Parameters(qbits=qbits, rbits=rbits, short=False)
        self.pairing = Pairing(self.params)
        self.P = Element.random(self.pairing, G1)
        alpha = Element.random(self.pairing, Zr)
        self.Q = self.P * alpha
        self.gt = self.pairing.apply(self.P, self.Q)
        self._validateParams()
        self.cwH = CWHashFunction(self.q)
        self.C = Element.random(self.pairing, G1)
        self.H = self.hashFunc
        self.tree = SimpleBTree(init=CHKPublicKey._btree_init)
        # precaclulate the pairing of Q, H
        self.eQH = self.pairing.apply(self.Q, self.H(self.tree.nodeId()))
        R0 = []
        self.tree.R = R0
        S0 = self.H(self.tree.nodeId()) * alpha
        self.tree.S = (S0)

    def Der(self, ordinal):
        return self._der(self.depth, ordinal)

    def _der(self, depth, ordinal):
        node = self.tree.findByAddress(depth, ordinal)
        # print("_der(%d,%d) @ %s" % (depth, ordinal, node.nodeId()))
        if node.S is not None:
            # print("node %s returning %s" % (node.nodeId(), (node.R, node.S)))
            assert len(node.R) == depth
            return (node.R, node.S)
        parent_key = self._der(depth-1, ordinal>>1)
        # print("parent_key = ", parent_key)
        if parent_key is None:
            #cannot derive keys in the past
            return None
        parentR = parent_key[0]
        parentS = parent_key[1]
        # print("parent R = ", parentR)
        # print("parent S = ", parentS)
        pw = Element.random(self.pairing, Zr)
        Rpw = self.P * pw
        # print("updating key for node %s" % (node.nodeId()))
        node.R = parentR[:]
        node.R.append(Rpw)
        H = self.H(node.nodeId())
        # print("hash for node %d = %s" % (node.nodeId(), str(H)))
        node.S = parentS + (H * pw)
        return (node.R, node.S)

    def Dec(self, Ctin, ordinal):
        # importing the ciphertext as strings handles case
        # of strings or where points are coming from distinct
        # pairing object (e.g. test code with multiple pkes)
        C = []
        for Ct in Ctin[0:-1]:
            C.append(Element(self.pairing, G1, value=str(Ct)))
        C.append(Element(self.pairing, GT, value=str(Ctin[-1])))
        U0 = C[0]
        U = C[1:-1]
        V = C[-1]
        # print("U0 = ", U0)
        # print("Ui (i=1..t) = ", U)
        # print("V = ", V)
        SK = self.Der(ordinal)
        S = SK[1]
        R = SK[0]
        # print("S = ", S)
        # print("Ri = ", R)
        assert len(R) == len(U)
        pi = self.pairing.apply(R[0], U[0])
        for i in range(1,len(R)):
            ru = self.pairing.apply(R[i], U[i])
            pi = pi * ru
        us = self.pairing.apply(U0, S)
        d = us * pow(pi, self.r - 1)
        return V * pow(d, self.r - 1)

if __name__ == '__main__':
    set_point_format_uncompressed()
    pke = CHKPrivateKey(16, 9, 5)
    print("params =", pke.params)
    print("q =", pke.q)
    print("h =", pke.h)
    print("r =", pke.r)
    print("pairing =", pke.pairing)
    print("P =", str(pke.P))
    print("Q =", str(pke.Q))
    print("gt =", str(pke.gt))
    print("H =", str(pke.H))
    SK0 = pke._der(0,0)
    print("SK0 = ", SK0)
    SK10 = pke._der(1,0)
    print("SK10 = ", SK10)
    SK11 = pke._der(1,1)
    print("SK11 = ", SK11)
    SK20 = pke._der(2,0)
    print("SK20 = ", SK20)
    SK21 = pke._der(2,1)
    print("SK21 = ", SK21)
    SK22 = pke._der(2,2)
    print("SK22 = ", SK22)
    SK23 = pke._der(2,3)
    print("SK23 = ", SK23)
    # export/import pubkey
    pubkey = pke.publicKeyToJSON()
    pke2 = CHKPublicKey.publicKeyFromJSON(pubkey)
    # encrypt a message
    for i in range(0,10):
        m = random.randint(1,pke.r)
        me = pke.gt * m
        print("Random message = 0x%X" % (m))
        print("Random element = ", str(me))
        lam = Element.random(pke.pairing, Zr)
        C = pke2.Enc(me,0x1234,lam)
        C2 = pke2.Enc(me,0x5678,lam)
        C1 = pke.Enc(me,0x1234,lam)
        C3 = pke.Enc(me,0x5678,lam)
        print("ciphertext 1 = ", str(C))
        print("ciphertext 2 = ", str(C2))
        assert str(C) == str(C1)
        assert str(C2) == str(C3)
        if True:
            d = pke.Dec(C,0x1234)
            dn = pke.Dec(C,0x5678)
            d2 = pke.Dec(C3,0x5678)
            d2n = pke.Dec(C3,0x1234)
            print("decrypted 1 = ", str(d))
            print("decrypted 2 = ", str(d2))
            print("decrypted 1n = ", str(dn))
            print("decrypted 2n = ", str(d2n))
            assert d == me
            assert dn != me
            assert d2 == me
            assert d2n != me
    a = Element.random(pke.pairing, Zr)
    b = Element.random(pke.pairing, Zr)
    # pbc treats * and ** both as the group operation (scalar multiplication)
    # for elliptic curve points
    g1a = pke.P * a
    g2b = pke.Q * b
    g1aExp = pow(pke.P, a)
    g2bExp = pow(pke.Q, b)
    assert g1a == g1aExp
    assert g2b == g2bExp
    # the opposite bilinear mapping
    g1b = pke.P * b
    g2a = pke.Q * a
    bilin = pke.pairing.apply(g1a, g2b)
    bili2 = pke.pairing.apply(g1b, g2a)
    check = pow(pke.gt, (a*b))
    print("bilin = ", str(bilin))
    print("check = ", str(check))
    print("bili2 = ", str(bili2))
    assert bilin == check
    assert bilin == bili2
    # test order, cofactor
    rm1 = pke.r - 1 
    rm1P = pow(pke.P,rm1)
    rp1 = pke.r + 1 
    rp1P = pow(pke.P,rp1)
    z = pke.P + rm1P
    print("P =", str(pke.P))
    print("(r-1)P =", str(rm1P))
    print("(r+1)P =", str(rp1P))
    print("z =", str(z))
    pcheck = pke.pairing.apply(rm1P, pke.Q)
    print("e(P,q)      = ", str(pke.gt))
    print("e((r-1)P,q) = ", str(pcheck))
    print(" sum(above) = ", str(pcheck + pke.gt))
    gtm1 = pow(pke.gt, rm1)
    print("gt       =", str(pke.gt))
    print("gt ** -1 =", str(gtm1))
    gtone = pke.gt * gtm1
    print("gt * gti =", str(gtone))
    r5 = Element(pke.pairing, Zr, value=5)
    gtfive = pow(pke.gt,r5)
    print("5 = ", str(r5))
    print("gt ** 5 = ", str(gtfive))
    gtfiveinv = gtfive * gtm1
    print("(gt * 5) * gt ** -1 = ", str(gtfiveinv))

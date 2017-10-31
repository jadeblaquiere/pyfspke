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


def _btree_init(node):
    node.R = []
    node.S = None


class CHKForwardSecurePKE (object):
    def __init__(self,depth,qbits, rbits):
        assert depth == int(depth)
        assert depth > 0
        assert qbits == int(qbits)
        assert qbits > 0
        assert rbits == int(rbits)
        assert rbits > 0
        # minimum cofactor(h) is 12... so at least that many bits
        assert qbits > (rbits+4)
        self._gen(depth,qbits,rbits)

    def _gen(self,depth,qbits,rbits):
        # parameters specify "type A" pairing (symmetric)
        self.params = Parameters(qbits=qbits, rbits=rbits, short=False)
        self.pairing = Pairing(self.params)
        self.P = Element.random(self.pairing, G1)
        alpha = Element.random(self.pairing, Zr)
        self.Q = self.P * alpha
        self.gt = self.pairing.apply(self.P, self.Q)
        strparams = str(self.params).split()
        # print(strparams.split())
        self.q = int(strparams[3])
        assert rabinmiller.isPrime(self.q)
        self.h = int(strparams[5])
        self.r = int(strparams[7])
        assert rabinmiller.isPrime(self.r)
        assert (self.q + 1) == (self.h * self.r)
        self.H = CWHashFunction(self.q)
        self.tree = SimpleBTree(init=_btree_init)
        self.d_precalc = self.pairing.apply(self.Q, self.P * self.H.hashval(self.tree.nodeId()))
        R0 = []
        self.tree.R = R0
        S0 = self.P * (alpha * self.H.hashval(self.tree.nodeId()))
        self.tree.S = (S0)

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
        node.S = parentS + (self.P * (pw * self.H.hashval(ordinal)))
        return (node.R, node.S)

    def _hashlist(self, depth, ordinal):
        node = self.tree.findByAddress(depth, ordinal)
        if depth == 0:
            return []
        else:
            phash = self._hashlist(depth-1, ordinal>>1)
            shash = phash[:]
            shash.append(self.H.hashval(node.nodeId()))
            return shash

    def _enc(self, M, depth, ordinal):
        # assume M in GT
        # lambda is a reserved word, so lam means lambda
        lam = Element.random(self.pairing, Zr)
        hlist = self._hashlist(depth, ordinal)
        C = []
        C.append(self.P * lam)
        for h in hlist:
            # print("type,h = ", type(h), h)
            H = self.P * Element(self.pairing, Zr, value=h)
            # print("type,H = ", type(H), H)
            C.append(H * lam)
        d = pow(self.d_precalc, lam)
        # print("type,m = ", type(m), m)
        # print("type,d = ", type(d), d)
        C.append(M * d)
        return C

    def _dec(self, C, depth, ordinal):
        U0 = C[0]
        U = C[1:-1]
        V = C[-1]
        print("U0 = ", U0)
        print("Ui (i=1..t) = ", U)
        print("V = ", V)
        SK = self._der(depth, ordinal)
        S = SK[1]
        R = SK[0]
        print("S = ", S)
        print("Ri = ", R)
        assert len(R) == len(U)
        pi = self.pairing.apply(R[0], U[0])
        for i in range(1,len(R)):
            ru = self.pairing.apply(R[i], U[i])
            pi = pi * ru
        us = self.pairing.apply(U0, S)
        d = us * pow(pi, -1)
        return V * pow(d, -1)

    def _node_hash(self,node):
        return self.H.hashval(self.tree.nodeId())

    def der(self, interval):
        # derive secret key for interval, return None if impossible
        pass

if __name__ == '__main__':
    pke = CHKForwardSecurePKE(16, 512, 500)
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
    # encrypt a message
    m = random.randint(1,pke.r)
    me = pke.gt * m
    print("Random message = 0x%X" % (m))
    print("Random element = ", str(me))
    C = pke._enc(me,8,0x35)
    print("ciphertext = ", str(C))
    d = pke._dec(C,8,0x35)
    print("decrypted = ", str(d))
    print("m * gt = ", str(pke.gt * me))
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
    assert pow(pke.gt, (a*b)) != pke.gt * (a * b)
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
    if False:
        for i in range (0, pow(2,8)):
            print("i,h(i) = %d, %X" % (i, pke.H.hashval(i)))
            assert pke.H.hashval(i) < pke.q

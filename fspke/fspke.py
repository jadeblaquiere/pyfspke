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
from pypbc import *
import rabinmiller

class CWHashFunction (object):
    """Carter and Wegman Universal Hash Function Family implementation
       produces hash functions of the form:
       H = ((ax + b) mod p) mod q
       where p >= b
             a,b random in Fp
             a nonzero
    """
    # see https://en.wikipedia.org/wiki/Universal_hashing for detail
    def __init__(self, q):
        assert q == int(q)
        assert q > 0
        self.q = q
        while True:
            # choose q < p < q**2
            self.p = random.randint(q+1, q*q)
            # if not prime, draw again
            if rabinmiller.isPrime(self.p) == False:
                continue
            self.a = random.randint(1, self.p-1)
            self.b = random.randint(1, self.p-1)
            break
    
    def hashval(self, x):
        return (((self.a * x) + self.b) % self.p) % self.q

    def __str__(self):
        return ("(((" + str(self.a) + " * x + " + str(self.b) + ") % " + 
                str(self.p) + ") % " + str(self.q) + ")")

class CHKForwardSecurePKE (object):
    def __init__(self,depth,qbits, rbits):
        assert depth == int(depth)
        assert depth > 0
        assert qbits == int(qbits)
        assert qbits > 0
        assert rbits == int(rbits)
        assert rbits > 0
        assert qbits > (rbits * 2)
        # parameters specify "type A" pairing (symmetric)
        self.params = Parameters(qbits=qbits, rbits=rbits, short=False)
        self.pairing = Pairing(self.params)
        self.P = Element.random(self.pairing, G1)
        self.alpha = Element.random(self.pairing, Zr)
        self.Q = pow(self.P, self.alpha)
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

if __name__ == '__main__':
    pke = CHKForwardSecurePKE(16, 1024, 320)
    print("params =", pke.params)
    print("q =", pke.q)
    print("h =", pke.h)
    print("r =", pke.r)
    print("pairing =", pke.pairing)
    print("P =", str(pke.P))
    print("Q =", str(pke.Q))
    print("gt =", str(pke.gt))
    print("H =", str(pke.H))
    a = Element.random(pke.pairing, Zr)
    b = Element.random(pke.pairing, Zr)
    g1a = pow(pke.P, a)
    g2b = pow(pke.Q, b)
    g1b = pow(pke.P, b)
    g2a = pow(pke.Q, a)
    bilin = pke.pairing.apply(g1a, g2b)
    bili2 = pke.pairing.apply(g1b, g2a)
    check = pow(pke.gt, (a*b))
    print("bilin = ", str(bilin))
    print("check = ", str(check))
    print("bili2 = ", str(bili2))
    assert bilin == check
    for i in range (0, pow(2,8)):
        print("i,h(i) =", i, pke.H.hashval(i))
        assert pke.H.hashval(i) < pke.q

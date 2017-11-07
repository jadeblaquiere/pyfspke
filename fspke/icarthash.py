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

import fspke.rabinmiller as rabinmiller
from fspke.cwhash import CWHashFunction
from ecpy.point import Point, Generator
from Crypto.Random import random

def _modinv(a, m):
    # Extended Euclidean Algorithm for finding inverse
    lastr, r, x, lastx = a, m, 0, 1
    while r:
        lastr, (q, r) = r, divmod(lastr, r)
        x, lastx = lastx - q*x, x
    return lastx % m

class IcartHash (object):
    """IcartHash uses the method proposed by Thomas Icart(1) and extended by
    Eric Brier et. al.(2) to hash a N-bit integer value into to a elliptic
    curve group defined over a finite field, E(Fp), where 2**N > q and E is
    in the Short Weierstrass for y**2 = x**3 + ax + b with Generator G and 
    order n. 
    
    (1) : Thomas Icart, "How to Hash into Elliptic Curves", CRYPTO2009,
    https://eprint.iacr.org/2009/226.pdf
    (2) : Eric Brier et. al., "Efficient Indifferentiable Hashing into
    Ordinary Elliptic Curves", CRYPTO2010,
    https://eprint.iacr.org/2009/340.pdf
    """
    def __init__(self, q, a, b, G, n):
        """"""
        if (q != int(q)) or (q < 3):
            raise ValueError("Invalid Input: q should be a positive integer")
        if (a != int(a)) or (a < 0):
            raise ValueError("Invalid Input")
        if (b != int(b)) or (b < 0):
            raise ValueError("Invalid Input")
        if rabinmiller.isPrime(q) != True:
            raise ValueError("Invalid Input: q must be prime")
        if (q % 3) != 2:
            raise ValueError("Invalid Input: q must be congruent to 2 (mod 3)")
        if (G[0] != int(G[0])) or (G[0] < 0):
            raise ValueError("Invalid Input")
        if (G[1] != int(G[1])) or (G[1] < 0):
            raise ValueError("Invalid Input")
        if (n != int(n)) or (n < 0):
            raise ValueError("Invalid Input")
        self.q = int(q)
        self.a = int(a)
        self.b = int(b)
        self.curve = { "p" : self.q,
              "bits" : self.q.bit_length(),
              "n" : int(n),
              "a" : self.a,
              "b" : self.b,
              "G" : (G[0], G[1])}
        print("curve =", self.curve)
        self.G = Generator.init(G[0], G[1], curve=self.curve)
        # precalculate some constants (inverses of 3, 2, 27) in Fq
        self._3inv = pow(3, self.q - 2, self.q)
        # print("_3inv =", self._3inv)
        assert ((3 * self._3inv) % self.q) == 1
        self._cubeRtExp = _modinv(3, self.q - 1)
        # print("_cubeRtExp =", self._3inv)
        assert ((3 * self._cubeRtExp) % (self.q-1)) == 1
        self._27inv = pow(27, self.q - 2, self.q)
        # print("_27inv =", self._27inv)
        assert ((27 * self._27inv) % self.q) == 1
        self._3a = (3 * a) % self.q
        # set up H1, H2 as two random uniform hash functions based on 
        # the Carter and Wegman construction
        self.H1 = CWHashFunction(self.q)
        self.H2 = CWHashFunction(self.q)
        
    def serialize(self):
        config = {}
        config['q'] = self.q
        config['a'] = self.a
        config['b'] = self.b
        config['G'] = (self.G.affine()[0], self.G.affine()[1])
        config['n'] = self.curve['n']
        config['H1'] = self.H1.serialize()
        config['H2'] = self.H2.serialize()
        return config

    @staticmethod
    def deserialize(config):
        H = IcartHash(config['q'], config['a'], config['b'],
                      config['G'], config['n'])
        H.H1 = CWHashFunction.deserialize(config['H1'])
        H.H2 = CWHashFunction.deserialize(config['H2'])
        return H

    def _cubeRoot(self, x):
        return pow(x, self._cubeRtExp, self.q)
    
    def deterministicMap(self, n):
        """Using the original algorithm proposed by Thomas Icart, calculates
        a point on E(Fp) assuming n is a member of Fq. H(0) is mapped to O
        (point at infinity). Points are calculated in affine coordinates and
        returned as a Point Object.
        
        Note: deterministicMap reliably maps Fp to E(Fp), but as not all points
        on the curve can be parameterized, the results are not uniform and the
        distribution is differentiable from a collection of random points
        """
        if (n != int(n)) or (n < 0):
            raise ValueError("Invalid Input")
        if n == 0:
            return Point(infinity=True, curve=self.curve)
        # just to be sure, force x to be a member 
        u = int(n) % self.q
        # print("u = ", u)
        u6_inv = pow((6 * u) % self.q, self.q - 2, self.q)
        assert ((6 * u * u6_inv) % self.q) == 1
        v = ((self._3a  - pow(u, 4, self.q)) * u6_inv) % self.q
        u_6 = pow(u, 6, self.q)
        # print ("u_6 =", u_6)
        # print ("27_inv =",  self._27inv)
        u_6o27 = (pow(u, 6, self.q) * self._27inv) % self.q
        assert ((u_6o27 * 27) % self.q) == u_6
        foo = ((pow(v, 2, self.q) - self.b) - u_6o27) % self.q
        # print ("foo = ", foo)
        curootfoo = self._cubeRoot(foo)
        # print ("curootfoo = ", curootfoo)
        assert(pow(curootfoo, 3, self.q) == foo)
        u_2 = pow(u, 2, self.q)
        u_2o3 = (pow(u, 2, self.q) * self._3inv) % self.q
        assert ((u_2o3 * 3) % self.q) == u_2
        x = (curootfoo + u_2o3) % self.q
        y = ((u * x) + v) % self.q
        return Point(x, y, infinity=False, curve=self.curve)

    def uniformMap(self, n):
        """UniformMap maps values from Fp to E(Fp) in a uniform manner by
        elliptic curve point multiplication. While this does produce a uniform
        mapping within the ring of the generator point, using this map exposes
        the discrete logarithm of the resultant point (as log.G = n). 
        """
        if (n != int(n)) or (n < 0):
            raise ValueError("Invalid Input")
        if n == 0:
            return Point(infinity=True,curve=self.curve)
        # just to be sure, force x to be a member 
        u = int(n) % self.q
        return (self.G * u)

    def hashval(self,n):
        """hashval calculates a secure, uniform hash from an N-bit input
        by using two Universal Hash functions to hash from {0,1}**N -> Fp
        and the summing the results of mapping these values using the
        deterministic (Icart) map and the uniform (E.C. Point Multiplication)
        mappings. 
        
        hashval takes an integer as input and returns the compressed
        representation of the point as a string.
        """
        h = (self.deterministicMap(self.H1.hashval(n)) +
             self.uniformMap(self.H2.hashval(n)))
        if h.is_infinite:
            return ('0' * (2 + ((self.curve['bits'] + 7) // 8)), True)
        else:
            return (h.compress().decode(), False)

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

from fspke.icarthash import *
from ecpy.point import Point, Generator
from Crypto.Random import random

if __name__ == '__main__':
    import ecpy.curves as curves

    #_curve = curves.curve_secp112r1
    _curve = curves.curve_secp256k1
    #_curve = curves.curve_secp384r1
    #_curve = curves.curve_bauer9
    P = _curve['p']
    N = _curve['n']
    A = _curve['a']
    
    Generator.set_curve(_curve)


    #q = 1523
    #q = 491
    #q = 10667
    #q = 476039
    # a = 1
    # b = 0
    
    # q = 743
    # h = 24
    # r = 31
    # pairing = <pypbc.Pairing object at 0x1383630>
    # P = 04002B02E0
    q = 743
    a = 1
    b = 0
    n = 31

    curve743 = { "p" : 743,
              "bits" : 10,
              "n" : 31,
              "a" : 1,
              "b" : 0,
              "G" : (0x02B, 0x2E0),
              "h" : 24 }

    curve = curve743

    Generator.set_curve(curve)

    G = Generator.init(curve['G'][0], curve['G'][1])
    assert (G * (n)).is_infinite == True
    assert G.is_valid()

    iH = IcartHash(q, a, b, curve['G'], curve['n'])
    h0 = iH.hashval(0)
    iH2 = IcartHash.deserialize(iH.serialize())
    print("iH(0) = ", h0)
    for i in range(0, q):
        # n = random.randint(0,q-1)
        n = i
        hn = iH.hashval(n)
        assert hn == iH2.hashval(n)
        ncollisions = 0
        coll = []
        for j in range(0, q):
            hc = iH.hashval(j)
            if (i != j) and (hc == hn):
                ncollisions += 1
                # print("collision i, j, hash = ", i, j, hc)
                coll.append(j)
        hp = Point(infinity=True, curve=curve)
        if hn[1] == False:
            hp = Point.decompress(hn[0])
        ha = hp.affine()
        han = (ha[0], ha[1], hp.is_infinite)
        if ncollisions > 0:
            print("n, iH(n) = ", n, han, ":", ncollisions, "collisions", coll)
        else:
            print("n, iH(n) = ", n, han)
        x,y = han[0], han[1]
        R = Point(x, y, infinity=han[2])
        assert R.is_valid()
        Q = R + G
        assert Q.is_valid()
        rt = (pow(x, 3, q) + (a * x) + b) % q
        lf = pow(y, 2, q)
        if han[2] != True:
            assert rt == lf

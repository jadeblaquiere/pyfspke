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
from fspke.chk import *
from fspke.simplebtree import SimpleNTree
from fspke.icarthash import IcartHash

if __name__ == '__main__':
    set_point_format_compressed()
    pke = CHKPrivateKey(512, 400, 6, order=16)
    print("params  =", pke.params)
    assert pke._reconstructParams() == str(pke.params)
    print("q       =", pke.q)
    print("q hex   = %X " % (pke.q))
    print("q bits  =", pke.q.bit_length())
    print("h       =", pke.h)
    print("h hex   = %X" % (pke.h))
    print("r       =", pke.r)
    print("r hex   = %X" % (pke.r))
    print("pairing =", pke.pairing)
    print("P =", str(pke.P))
    set_point_format_uncompressed()
    print("P =", str(pke.P))
    set_point_format_compressed()
    print("Q =", str(pke.Q))
    print("gt=", str(pke.gt))
    print("H =", str(pke.H))
    SK0 = pke._der(0,0)
    print("SK0  =", SK0)
    SK10 = pke._der(1,0)
    print("SK10 =", SK10)
    SK11 = pke._der(1,1)
    print("SK11 =", SK11)
    SK20 = pke._der(2,0)
    print("SK20 =", SK20)
    SK21 = pke._der(2,1)
    print("SK21 =", SK21)
    SK22 = pke._der(2,2)
    print("SK22 =", SK22)
    SK23 = pke._der(2,3)
    print("SK23 =", SK23)
    # export privkey
    privkey = pke.privateKeyToJSON(0x000000)
    print()
    print("privkey =", privkey)
    print()
    privkeyDER = pke.privateKeyToDER(0x100000)
    print("privkey (DER)=", hexlify(privkeyDER).decode())
    print("DER key length =", len(privkeyDER))
    print()
    pke4 = CHKPrivateKey.privateKeyFromJSON(privkey)
    pke5 = CHKPrivateKey.privateKeyFromDER(privkeyDER)
    # export/import pubkey
    pubkey = pke.publicKeyToJSON()
    print('pubkey exported as (JSON):')
    print(pubkey)
    print()
    pubkeyDER = pke.publicKeyToDER()
    print('pubkey exported as (DER):')
    print(hexlify(pubkeyDER).decode())
    print("DER key length =", len(pubkeyDER))
    print()
    pke2 = CHKPublicKey.publicKeyFromJSON(pubkey)
    pubkey2 = pke2.publicKeyToJSON()
    pke3 = CHKPublicKey.publicKeyFromDER(pubkeyDER)
    pubkey3DER = pke3.publicKeyToDER()
    assert pubkey3DER == pubkeyDER
    assert pubkey2 == pubkey
    SK123456 = pke.Der(0x123456)
    SK56789A = pke.Der(0x56789A)
    SK9ABCDE = pke.Der(0x9ABCDE)
    SKDEF123 = pke.Der(0xDEF123)
    print("key(0x123456) = ", str(SK123456))
    print("key(0x56789A) = ", str(SK56789A))
    # encrypt a message
    for i in range(0,10):
        m = random.randint(1,pke.r)
        me = pke.gt * m
        print("Random message = 0x%X" % (m))
        print("Random element = ", str(me))
        lam = Element.random(pke.pairing, Zr)
        C = pke2.Enc(me,0x123456,lam)
        C2 = pke3.Enc(me,0x56789A,lam)
        C1 = pke.Enc(me,0x123456,lam)
        C3 = pke.Enc(me,0x56789A,lam)
        C4 = pke.Enc_DER(me,0x56789A,lam)
        print("ciphertext 1  = ", str(C))
        print("ciphertext 2  = ", str(C2))
        print("ciphertext 4  = ", hexlify(C4))
        assert str(C) == str(C1)
        assert str(C2) == str(C3)
        if True:
            d = pke.Dec(C,0x123456)
            d_4 = pke4.Dec(C,0x123456)
            d_5 = pke5.Dec(C,0x123456)
            dn = pke.Dec(C,0x56789A)
            d2 = pke.Dec(C3,0x56789A)
            d2_4 = pke4.Dec(C3,0x56789A)
            d2_5 = pke5.Dec(C3,0x56789A)
            d2n = pke.Dec(C3,0x123456)
            d4 = pke.Dec_DER(C4,0x56789A)
            print("decrypted 1 = ", str(d))
            print("decrypted 2 = ", str(d2))
            print("decrypted 1n = ", str(dn))
            print("decrypted 2n = ", str(d2n))
            assert d == d_4
            assert d == d_5
            assert d == me
            assert dn != me
            assert d2 == d2_4
            assert d2 == d2_5
            assert d2 == me
            assert d2n != me
    keyset = pke._exportKeyset(0x000000)
    print("Max keys = ", len(keyset))
    print("forgetting before 0x200000")
    pke.ForgetBefore(0x200000)
    keyset = pke._exportKeyset(0x200000)
    print("Keys @ 0x200000 = ", len(keyset))
    # for k in keyset:
    #     print("key @ %s = %s" % (k[0], k[1]))
    print("forgotten")
    SKx123456 = pke.Der(0x123456)
    SKx56789A = pke.Der(0x56789A)
    SKx9ABCDE = pke.Der(0x9ABCDE)
    SKxDEF123 = pke.Der(0xDEF123)
    assert SKx123456 is None
    assert SKx56789A == SK56789A
    assert SKx9ABCDE == SK9ABCDE
    assert SKxDEF123 == SKDEF123
    print("forgetting before 0x700000")
    pke.ForgetBefore(0x700000)
    keyset = pke._exportKeyset(0x700000)
    print("Keys @ 0x700000 = ", len(keyset))
    # for k in keyset:
    #     print("key @ %s = %s" % (k[0], k[1]))
    print("forgotten")
    SKx123456 = pke.Der(0x123456)
    SKx56789A = pke.Der(0x56789A)
    SKx9ABCDE = pke.Der(0x9ABCDE)
    SKxDEF123 = pke.Der(0xDEF123)
    assert SKx123456 is None
    assert SKx56789A is None
    assert SKx9ABCDE == SK9ABCDE
    assert SKxDEF123 == SKDEF123
    # Validation of groups, orders, EC, Pairing math
    if False:
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
        #print("check = ", str(check))
        #print("bili2 = ", str(bili2))
        assert bilin == check
        assert bilin == bili2
        # test order, cofactor
        rm1 = pke.r - 1 
        rm1P = pow(pke.P,rm1)
        rp1 = pke.r + 1 
        rp1P = pow(pke.P,rp1)
        z = pke.P + rm1P
        zG1 = Element.zero(pke.pairing, G1)
        print("     P =", str(pke.P))
        print("(r-1)P =", str(rm1P))
        print("(r+1)P =", str(rp1P))
        print("     z =", str(z))
        assert z == zG1
        pcheck = pke.pairing.apply(rm1P, pke.Q)
        zGT = Element.zero(pke.pairing, GT)
        print("e(P,q)      = ", str(pke.gt))
        print("e((r-1)P,q) = ", str(pcheck))
        print(" sum(above) = ", str(pcheck + pke.gt))
        assert zGT == (pcheck + pke.gt)
        gtm1 = pow(pke.gt, rm1)
        print("gt       =", str(pke.gt))
        print("gt ** -1 =", str(gtm1))
        gtone = pke.gt * gtm1
        assert zGT == gtone
        print("gt * gti =", str(gtone))

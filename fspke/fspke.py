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
import fspke.rabinmiller as rabinmiller
from pypbc import *
from fspke.simplebtree import SimpleNTree
from fspke.icarthash import IcartHash
from binascii import hexlify, unhexlify
import json
import asn1

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
   elements in G2 are curve points in Fp2 (F-p-squared). Messages (M) are
   in Fp2. Ciphertexts include multiple EC points and an element in Fp2.
   The Public Key includes parameters of the curves, pairing and a universal
   hash function.
   
   NOTE: This implementation forgoes the optimization (see Section 3.3) of
   using every node of the tree and instead only uses leaf nodes such that
   a constant ciphertext size is maintained. This optimization does not
   affect the security proofs provided by Canetti, Halevi and Katz and with
   larger btree orders the cost in storage is negligible.
"""

class CHKPublicKey (object):
    def __init__(self, depth, order=2):
        if (depth != int(depth)) or (depth < 0):
            raise ValueError('Invalid Input: depth must be positive integer')
        self.depth = depth
        self.order = order
        self.params = None
        self.pairing = None
        self.P = None
        self.Q = None
        #self.cwH = None
        #self.C = None
        self._H = None
        self.H = self._hashFunc
        self.tree = SimpleNTree(self.order, init=CHKPublicKey._btree_init)
        self.eQH = None
        self.q = None
        self.r = None
        self.h = None
        self.exp2 = None
        self.exp1 = None
        self.sign1 = None
        self.sign0 = None

    def publicKeyToJSON(self):
        pubkey = {}
        params = {}
        params['q'] = self.q
        params['h'] = self.h
        params['r'] = self.r
        params['exp2'] = self.exp2
        params['exp1'] = self.exp1
        params['sign1'] = self.sign1
        params['sign0'] = self.sign0
        # pubkey['params'] = str(self.params)
        pubkey['params'] = params
        pubkey['P'] = str(self.P)
        pubkey['Q'] = str(self.Q)
        pubkey['l'] = self.depth
        pubkey['o'] = self.order
        pubkey['H'] = self._H.serialize()
        pubkeyJ = json.dumps(pubkey)
        print('pubkey exported as:')
        print(pubkeyJ)
        print()
        return pubkeyJ

    @staticmethod
    def publicKeyFromJSON(pubkeyJ):
        pubkey = json.loads(pubkeyJ)
        pke = CHKPublicKey(pubkey['l'], pubkey['o'])
        pke._importPubkeyFromDict(pubkey)
        return pke

    def _importPubkeyFromDict(self, pubkey):
        print('pubkey imported as:')
        print(pubkey)
        print()
        params = pubkey['params']
        self.q = params['q']
        self.h = params['h']
        self.r = params['r']
        self.exp2 = params['exp2']
        self.exp1 = params['exp1']
        self.sign1 = params['sign1']
        self.sign0 = params['sign0']
        self.params = Parameters(param_string=self._reconstructParams())
        # self.params = Parameters(param_string=pubkey['params'])
        self._validateParams()
        self.pairing = Pairing(self.params)
        self.P = Element(self.pairing, G1, value=pubkey['P'])
        self.Q = Element(self.pairing, G1, value=pubkey['Q'])
        self._H = IcartHash.deserialize(pubkey['H'])
        self.H = self._hashFunc
        self.gt = self.pairing.apply(self.P, self.Q)
        self.tree = SimpleNTree(self.order, init=CHKPublicKey._btree_init)
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
        self.exp2 = int(strparams[9])
        if self.exp2 <= 0:
            raise ValueError("exp2 must be > 0")
        self.exp1 = int(strparams[11])
        if self.exp1 <= 0:
            raise ValueError("exp1 must be > 0")
        self.sign1 = int(strparams[13])
        if (self.sign1 != 1) and (self.sign1 != -1):
            raise ValueError("sign1 must be +/- 1")
        self.sign0 = int(strparams[15])
        if (self.sign0 != 1) and (self.sign0 != -1):
            raise ValueError("sign0 must be +/- 1")
        # self._reconstructParams()

    def _reconstructParams(self):
        params = 'type a\nq ' + str(self.q) + '\nh ' + str(self.h)
        params += "\nr " + str(self.r) + "\nexp2 " + str(self.exp2)
        params += "\nexp1 " + str(self.exp1) + "\nsign1 " + str(self.sign1)
        params += "\nsign0 " + str(self.sign0) + "\n"
        # assert params == str(self.params)
        return params

    @staticmethod
    def _btree_init(node):
        node.R = []
        node.S = None

    def _hexprint_q(self, x):
        """_hexprint_q prints a zero-padded fixed length hex representation
        based on the bit size of q
        """
        pfmt = '%%0%dx' % (int((self.q.bit_length() + 7) // 8) * 2)
        return (pfmt % x)

    def _byterep_q(self,x):
        return unhexlify(self._hexprint_q(x))

    def _hashFunc(self, x):
        """_hashfunc uses the Icart hash function and converts it to Element
        """
        h = self._H.hashval(x)
        if h[1] == True:
            return Element.zero(self.pairing, G1)
        else:
            return Element(self.pairing, G1, value=h[0])

    def _hashlist(self, depth, interval):
        node = self.tree.findByAddress(depth, interval)
        if depth == 0:
            return []
        else:
            phash = self._hashlist(depth-1, interval // self.order)
            shash = phash[:]
            H = self.H(node.nodeId())
            # print("hash for node %d = %s" % (node.nodeId(), str(H)))
            shash.append(H)
            return shash

    def Enc(self, M, interval, lam=None):
        """Enc is the encryption function which takes a single element
        and encrypts it using the encryption key for specific interval
        """
        ctraw = self._enc(M, interval, lam)
        ct = []
        for c in ctraw:
            ct.append(str(c))
        return ct

    def Enc_DER(self, M, interval, lam=None):
        """Enc is the encryption function which takes a single element
        and encrypts it using the encryption key for specific interval. 
        Enc_DER produces output in ASN.1 DER binary format
        """
        ctraw = self._enc(M, interval, lam)
        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        for c in ctraw[:-1]:
            byteval = unhexlify(str(c))
            encoder.write(byteval, asn1.Numbers.OctetString)
        encoder.enter(asn1.Numbers.Sequence)
        Md = ctraw[-1]
        for n in range(0,2):
            byteval = self._byterep_q(Md[n])
            encoder.write(byteval, asn1.Numbers.OctetString)
        encoder.leave()
        encoder.leave()
        return encoder.output()

    def _enc(self, M, interval, lam=None):
        # internal encryption function - returns list of Element types
        # which encode the ciphertext
        # assume M in GT
        # lambda is a python reserved word, so here lam means lambda
        if lam is None:
            lam = Element.random(self.pairing, Zr)
        hlist = self._hashlist(self.depth, interval)
        ct = []
        ct.append(self.P * lam)
        for H in hlist:
            # print("type,h = ", type(h), h)
            # H = self.P * h
            # print("type,H = ", type(H), H)
            ct.append(H * lam)
        d = pow(self.eQH, lam)
        # print("type,m = ", type(m), m)
        # print("type,d = ", type(d), d)
        ct.append(M * d)
        return ct


class CHKPrivateKey (CHKPublicKey):
    def __init__(self, qbits, rbits, depth, order=2):
        """
        """
        if (qbits != int(qbits)) or (qbits < 0):
            raise ValueError("Invalid Input: qbits must be positive integer")
        if (rbits != int(rbits)) or (rbits < 0):
            raise ValueError("Invalid Input: rbits must be positive integer")
        if rbits > (qbits - 4):
            raise ValueError("Invalid Input: rbits cannot be > qbits - 4")
        super(self.__class__, self).__init__(depth)
        self.Gen(qbits, rbits, depth, order)

    def Gen(self, qbits, rbits, depth, order=2):
        """The Gen function generates a pairing-based cryptosystem based on the
        CHK Model. The implementation leverages Ben Lynn's PBC library
        (https://crypto.stanford.edu/pbc/) to construct symmetric pairings.
        
        The values qbits rbits are the parameters passed to 
        pbc_param_init_a_gen() to derive the pairing. Refer to the PBC
        documentation for detail and/or security implications of these values.
        
        The values of depth and order define the BTree structure used to map
        intervals to keys. These parameters can be balanced to optimize for the
        requirements of a specific usage as they impact:
        
        Max # of intervals = order ** depth
        Ciphertext size is proportional to depth + 3
        Max secret key size is proportional to (depth * (order - 1)) + 1
        """
        # parameters specify "type A" pairing (symmetric)
        self.depth = depth
        self.order = order
        # parameters specify "type A" pairing (symmetric based on Tate pairing)
        self.params = Parameters(qbits=qbits, rbits=rbits, short=False)
        self.pairing = Pairing(self.params)
        self.P = Element.random(self.pairing, G1)
        # alpha is the seed of the primary secret key. alpha is not permanently
        # stored and is eligible for garbage collection following __init__
        alpha = Element.random(self.pairing, Zr)
        self.Q = self.P * alpha
        self.gt = self.pairing.apply(self.P, self.Q)
        self._validateParams()
        # self.cwH = CWHashFunction(self.q)
        pointFmtCompressed = PBC_EC_Compressed
        G = (self.P[0], self.P[1])
        # print("Generator = ", G)
        self._H = IcartHash(self.q, 1, 0, G, self.r)
        self.H = self._hashFunc
        self.tree = SimpleNTree(self.order, init=CHKPublicKey._btree_init)
        # precaclulate the pairing of Q, H
        self.eQH = self.pairing.apply(self.Q, self.H(self.tree.nodeId()))
        R0 = []
        self.tree.R = R0
        S0 = self.H(self.tree.nodeId()) * alpha
        self.tree.S = (S0)

    def Der(self, interval):
        """Der derives the secret key (Rw|1, ... Rw|n-1, Rw, S) for any
        specific interval.
        """
        return self._der(self.depth, interval)

    def _der(self, depth, interval):
        node = self.tree.findByAddress(depth, interval)
        # print("_der(%d,%d) @ %s" % (depth, interval, node.nodeId()))
        if node.S is not None:
            # print("node %s returning %s" % (node.nodeId(), (node.R, node.S)))
            assert len(node.R) == depth
            return (node.R, node.S)
        if depth == 0:
            # this is the root node and if node.S is None the key is forgotten
            return None
        parent_key = self._der(depth-1, interval // self.order)
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

    def ExportKeyset(self, interval):
        node = self.tree.findByAddress(self.depth, interval)
        keylist = self._deriveRightAndUpRight(node)
        ckey = self._der(node.address()[0], node.address()[1])
        keylist.append((node.address(), ckey))
        return keylist

    def ForgetBefore(self, interval):
        self._forgetBefore(interval)

    def _forgetBefore(self, interval):
        node = self.tree.findByAddress(self.depth, interval)
        nkey = self.Der(interval)
        if nkey is None:
            raise ValueError("Key cannot be derived for future interval")
        # ensure peers of later interval have derived their keys
        keylist = self._deriveRightAndUpRight(node)
        for k in keylist:
            # if we get None back then something is broken
            assert k is not None
        # clear anything not to the right or up-right
        self._clearLeftandDown(node)
        self._clearUp(node)

    def _deriveRightAndUpRight(self, node):
        # traverses the nodes "forward in time" - to the right amongst peers
        # and then right-peers of parent (and recursively up) - to derive
        # keys needed for "the future"
        if node.parent is None:
            return []
        # ensure peers of later interval (right) have derived their keys
        keylist = self._deriveRightAndUpRight(node.parent)
        # loop over peers, find Id>node.Id, Der and add to list
        for c in node.parent.children()[:]:
            if c.nodeId() > node.nodeId():
                ckey = self._der(c.address()[0], c.address()[1])
                keylist.append((c.address(), ckey))
        return keylist

    def _clearLeftandDown(self, node):
        # traverses tree to erase secret keys for "back in time"
        if node.parent is None:
            return
        # loop over peers, 
        for c in node.parent.children():
            if c.nodeId() < node.nodeId():
                c.S = None
                c.R = []
                # no need to descend and erase keys - prune the whole subtree
                c.pruneChildren()
        self._clearLeftandDown(node.parent)

    def _clearUp(self, node):
        # clears secret keys for parent node elements - back to the root
        # any parent node can derive keys for children
        parent = node.parent
        if parent is not None:
            parent.S = None
            parent.R = []
            self._clearUp(parent)

    def Dec(self, Ctin, interval):
        """Dec is the decryption function which translates a ciphertext into
        the message value (which is a point in Fp2) using the key for the
        specific interval.
        """
        C = []
        for Ct in Ctin[0:-1]:
            C.append(Element(self.pairing, G1, value=str(Ct)))
        C.append(Element(self.pairing, GT, value=str(Ctin[-1])))
        return self._dec(C, interval)
        
    def Dec_DER(self, CtinDER, interval):
        """Dec is the decryption function which translates a ciphertext into
        the message value (which is a point in Fp2) using the key for the
        specific interval.
        Dec_DER takes ciphertext input in ASN.1 DER binary format
        """
        # importing the ciphertext as strings handles case
        # of strings or where points are coming from distinct
        # pairing object (e.g. test code with multiple pkes)
        decoder = asn1.Decoder()
        decoder.start(CtinDER)
        tag = decoder.peek()
        if tag.nr != asn1.Numbers.Sequence:
            raise ValueError("Unexpected DER tag")
        decoder.enter()
        C = []
        tag = decoder.peek()
        while tag.nr != asn1.Numbers.Sequence:
            if tag.nr != asn1.Numbers.OctetString:
                raise ValueError("Unexpected DER tag")
            tag, val = decoder.read()
            C.append(Element(self.pairing, G1, value=hexlify(val).decode()))
            tag = decoder.peek()
        decoder.enter()
        tag = decoder.peek()
        if tag.nr != asn1.Numbers.OctetString:
            raise ValueError("Unexpected DER tag")
        tag, valx = decoder.read()
        tag = decoder.peek()
        if tag.nr != asn1.Numbers.OctetString:
            raise ValueError("Unexpected DER tag")
        tag, valy = decoder.read()
        decoder.leave()
        decoder.leave()
        if decoder.eof() != True:
            raise ValueError("Unexpected DER tag")
        Md = "(0x" + hexlify(valx).decode() + ", 0x" + hexlify(valy).decode() + ")"
        C.append(Element(self.pairing, GT, value=str(Md)))
        return self._dec(C, interval)
        
    def _dec(self, C, interval):
        # internal decryption function takes a list of elements (depth + 1
        # points in G1 followed by x,y coordinates in pairing target group)
        # and recovers the original (target group) message point
        U0 = C[0]
        U = C[1:-1]
        V = C[-1]
        # print("U0 = ", U0)
        # print("Ui (i=1..t) = ", U)
        # print("V = ", V)
        SK = self.Der(interval)
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

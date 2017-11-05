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

class CWHashFunction (object):
    """Carter and Wegman Universal Hash Function Family implementation
       produces hash functions of the form:
       H = ((ax + b) mod p) mod q
       where p >= b
             a,b random in Fp
             a nonzero
    """
    # see https://en.wikipedia.org/wiki/Universal_hashing for detail
    def __init__(self, q, p=None, a=None, b=None):
        if (q != int(q)) or (q < 0):
            raise ValueError("Invalid Input")
        if p is not None:
            if (p != int(p)) or (p < 0):
                raise ValueError("Invalid Input")
            if rabinmiller.isPrime(p) != True:
                raise ValueError("Invalid Input")
        self.q = q
        while True:
            # choose q < p < q**2
            if p is None:
                self.p = random.randint(q+1, q*q)
                # if not prime, draw again
                if rabinmiller.isPrime(self.p) == False:
                    continue
            else:
                self.p = p
            if a is None:
                self.a = random.randint(1, self.p-1)
            else:
                if p is None:
                    raise ValueError("Invalid Input")
                if b is None:
                    raise ValueError("Invalid Input")
                self.a = a
            if b is None:
                self.b = random.randint(1, self.p-1)
            else:
                if p is None:
                    raise ValueError("Invalid Input")
                if a is None:
                    raise ValueError("Invalid Input")
                self.b = b
            break
    
    def hashval(self, x):
        return (((self.a * x) + self.b) % self.p) % self.q

    def __str__(self):
        return ("(((" + str(self.a) + " * x + " + str(self.b) + ") % " + 
                str(self.p) + ") % " + str(self.q) + ")")

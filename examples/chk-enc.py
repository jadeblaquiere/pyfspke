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

import pypbc
from fspke.fspke import CHKPublicKey
from argparse import ArgumentParser
import base64
import sys
from hashlib import sha256
import Crypto.Random as Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
import asn1


def bxor(b1, b2): # use xor for bytes
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


desc = ('chk-enc encrypts a message using AES encryption based on a '
        'random key and then encrypts that random key using the CHK '
        'forward secure encryption scheme. Output is DER encoded '
        'and PEM-wrapped')

parser = ArgumentParser(description=desc)
parser.add_argument('pubkey', help='file path for file containing public key')
parser.add_argument('--interval', type=int, default=0, help='interval value to encrypt for')
parser.add_argument('-f', '--file', default=None, help='read message plaintext from file instead of stdin')
clargs = parser.parse_args()

with open(clargs.pubkey, 'r') as keyfile:
    PEMkey=keyfile.read()
DERkey = base64.b64decode(PEMkey.split('-----')[2].encode())
try:
    pubkey = CHKPublicKey.publicKeyFromDER(DERkey)
except ValueError:
    sys.exit('Error: Unable to import public key, aborting.')

if pubkey is None:
    sys.exit('Error: Unable to import public key, aborting.')

if clargs.file is None:
    message = sys.stdin.read()
else:
    with open(clargs.file, 'r') as msgfile:
        message=msgfile.read()

if (message is None) or (len(message) == 0):
    sys.exit('Error: Plaintext length 0, aborting.')

# generate a random 256 bit key for encryption, 128 bit counter for MODE_CTR
AESkey = Random.new().read(32)
# counter starts at 1... Secure so long as we don't re-use the key
counter = Counter.new(128)
aescipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)
# encrypt message (symmetric encryption)
aes_ct = aescipher.encrypt(message)

# because the plaintext space of the CHK algorithm is point coordinates
# we generate a secure random key, hash to get a byte string and use that
# as a one time pad to encrypt the AES key (by XOR)

# generate a random message for CHK (which is a point in Fp2)
chk_pt = pubkey.gt * Random.random.randint(1,pubkey.r)
# hash to create a string from point coordinates
randhash = sha256(str(chk_pt).encode()).digest()
assert len(randhash) == len(AESkey)
xorkey = bxor(AESkey, randhash)

# encode random element using CHK BTE algorithm
chk_ct = pubkey.Enc_DER(chk_pt, clargs.interval)

# encode PKE encrypted key, xor key, aes ciphertext in DER
encoder = asn1.Encoder()
encoder.start()
encoder.enter(asn1.Numbers.Sequence)
encoder.write(chk_ct, asn1.Numbers.OctetString)
encoder.write(xorkey, asn1.Numbers.OctetString)
encoder.write(aes_ct, asn1.Numbers.OctetString)
encoder.leave()
DERmsg = encoder.output()

print('-----BEGIN CHK ENCRYPTED MESSAGE-----')
print(base64.b64encode(DERmsg).decode())
print('-----END CHK ENCRYPTED MESSAGE-----')

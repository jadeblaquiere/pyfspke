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

from fspke.chk import CHKPrivateKey
from argparse import ArgumentParser
import base64
import sys
from hashlib import sha256
import Crypto.Random as Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
import asn1


def ensure_tag(decoder, expected):
    tag = decoder.peek()
    if tag.nr != expected:
        raise ValueError("Error in DER format, expected tag %d, got %d" %
                         (expected, tag.nr))


def bxor(b1, b2): # use xor for bytes
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


desc = ('chk-dec decrypts a message encrypted by chk-enc using the CHK '
        'forward secure encryption scheme.')

parser = ArgumentParser(description=desc)
parser.add_argument('privkey', help='file path for file containing private key')
parser.add_argument('--interval', type=int, default=0, help='interval value to encrypt for')
parser.add_argument('-f', '--file', default=None, help='read ciphertext from file instead of stdin')
clargs = parser.parse_args()

with open(clargs.privkey, 'r') as keyfile:
    PEMkey=keyfile.read()
DERkey = base64.b64decode(PEMkey.split('-----')[2].encode())
try:
    privkey = CHKPrivateKey.privateKeyFromDER(DERkey)
except ValueError:
    sys.exit('Error: Unable to import private key, aborting.')

if privkey is None:
    sys.exit('Error: Unable to import private key, aborting.')

if clargs.file is None:
    PEMtxt = sys.stdin.read()
else:
    with open(clargs.file, 'r') as msgfile:
        PEMtxt=msgfile.read()

DERtxt = base64.b64decode(PEMtxt.split('-----')[2].encode())

decoder = asn1.Decoder()
decoder.start(DERtxt)
ensure_tag(decoder, asn1.Numbers.Sequence)
decoder.enter()
ensure_tag(decoder, asn1.Numbers.OctetString)
tag, chk_ct = decoder.read()
ensure_tag(decoder, asn1.Numbers.OctetString)
tag, xorkey = decoder.read()
ensure_tag(decoder, asn1.Numbers.OctetString)
tag, aes_ct = decoder.read()

# recover plaintext point from CHK Decode, xor to get AESkey
chk_pt = privkey.Dec_DER(chk_ct, clargs.interval)
if chk_pt is None:
    sys.exit('Error: Unable to decrypt ciphertext, aborting.')
randhash = sha256(str(chk_pt).encode()).digest()
AESkey = bxor(xorkey, randhash)

# counter starts at 1... Secure so long as we don't re-use the key
counter = Counter.new(128)
aescipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)
# encrypt message (symmetric encryption)
message = aescipher.decrypt(aes_ct)

print(message.decode(), end='')

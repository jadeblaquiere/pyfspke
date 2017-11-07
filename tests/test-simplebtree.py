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

from fspke.simplebtree import *

if __name__ == '__main__':
    # example initializer - extends nodes with nodeId() % 5
    def initNode(node):
        #print("initializing node ", str(node.nodeId()))
        node.mod5 = node.nodeId() % 5
    # create 
    rootNode = SimpleBTree(init=initNode)
    l0 = rootNode.leftof()
    r0 = rootNode.rightof()
    def down(node, levels):
        print(str(node))
        if levels > 0:
            down(node.leftof(), levels-1)
            down(node.rightof(), levels-1)
    down(rootNode,3)
    nx912F = rootNode.findByAddress(16,0x912F)
    print("nx912F (%d) = %s" % (0x912F, str(nx912F)))
    print("nx912f.mod5 = ", str(nx912F.mod5))
    print("parent of nx912F = ", str(nx912F.parent))
    print("children of parent of nx912F:")
    for c in nx912F.parent.children():
        print("    ", str(c))
    assert nx912F.mod5 == (0x921F % 5)
    nrootNode = SimpleNTree(3,initNode)
    def downN(node, levels):
        print(str(node))
        if levels > 0:
            for c in node.children():
                downN(c, levels-1)
    downN(nrootNode,3)
    assert nrootNode.findByAddress(3,26).mod5 == 4
    assert nrootNode.findByAddress(2,6).mod5 == 0
    brootNode = SimpleNTree(2,init=initNode)
    crootNode = SimpleBTreeOld(init=initNode)
    def downNNN(anode, bnode, cnode, levels):
        print(str(anode))
        if levels > 0:
            assert anode.mod5 == bnode.mod5
            assert anode.address() == bnode.address()
            assert anode.nodeId() == bnode.nodeId()
            assert anode.mod5 == cnode.mod5
            assert anode.address() == cnode.address()
            assert anode.nodeId() == cnode.nodeId()
            downNNN(anode.leftof(), bnode.nthChild(0), cnode.leftof(), levels-1)
            downNNN(anode.rightof(),bnode.nthChild(1), cnode.rightof(),levels-1)
    downNNN(rootNode,brootNode,crootNode,4)

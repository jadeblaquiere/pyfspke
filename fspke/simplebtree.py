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

class SimpleBTree (object):
    """SimpleBTree implements a Simple Binary Tree with lazy allocation. Nodes
       are created when first referenced. Supports arbitrary depth initData
       provides a callback function which is called for each allocated node
       to initialize local data at the node. In this way SimpleBTree can be
       used to manage a tree of data without creating a derived class.
       the init callback 
    """
    def __init__(self, parent=None, left=True, init=None):
        self.parent = parent
        if parent is None:
            self._depth = 0
            self._ordinal = 0
        else:
            self._depth = parent._depth + 1
            if left:
                self._ordinal = (2 * parent._ordinal)
            else:
                self._ordinal = (2 * parent._ordinal) + 1
        self._left = None
        self._right = None
        self.init = init
        if init is not None:
            # print("calling init")
            self.init(self)

    def leftof(self):
        """find (or create if needed) the left child"""
        if self._left is None:
            self._left = SimpleBTree(parent=self,left=True,init=self.init)
        return self._left

    def rightof(self):
        """find (or create if needed) the left child"""
        if self._right is None:
            self._right = SimpleBTree(parent=self,left=False,init=self.init)
        return self._right

    def address(self):
        """address returns position in tree as a tuple (depth, width)"""
        return (self._depth, self._ordinal)

    def nodeId(self):
        """node_id returns unique node integer for each tree node. The root
           node is node 0, it's left is 1 and right is 2. Node 1's children
           are 3,4 and node 2's children are 5,6 (and so on)
        """
        return (pow(2,self._depth) + self._ordinal) - 1
    
    def findByAddress(self,depth,ordinal):
        """find node recursively"""
        if depth == 0:
            # print("seeking %X, found %X" % (ordinal, self._ordinal))
            assert ordinal == self._ordinal
            return self
        # print("depth = %d, testing bit %X" % (depth,pow(2,depth-1)))
        if (pow(2,depth-1) & ordinal) == 0:
            # print("from %s searching leftof()")
            return self.leftof().findByAddress(depth-1,ordinal)
        else:
            # print("from %s searching rightof()")
            return self.rightof().findByAddress(depth-1,ordinal)

    def __str__(self):
        return ("Node id %d @%s: left = id %d, right = id %d" %
              (self.nodeId(), str(self.address()), 
               self.leftof().nodeId(), self.rightof().nodeId()))

if __name__ == '__main__':
    # example initializer - extends nodes with nodeId() % 5
    def initNode(node):
        print("initializing node ", str(node.nodeId()))
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
    down(rootNode,8)
    nx912F = rootNode.findByAddress(16,0x912F)
    print("nx912F (%d) = %s" % (0x912F, str(nx912F)))
    print("nx912f.mod5 = ", str(nx912F.mod5))
    assert nx912F.mod5 == (0x921F % 5)

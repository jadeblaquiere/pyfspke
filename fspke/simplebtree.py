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

class SimpleNTree (object):
    """SimpleNTree implements an Order N B-Tree with lazy allocation where
    all non-leaf nodes have exactly N children. Nodes are created when first
    referenced. Supports arbitrary depth. The init parameter provides a
    callback function which is called for each allocated node to initialize
    local data at the node. In this way SimpleNTree can be used to manage a
    tree of data without creating a derived class.
    
    Tree traversal is via virtual Method nthChild(n), which can be overridden
    by subclass.
    """
    def __init__(self, N, init=None):
        """The __init__ function parameters """
        self.parent = None
        if (N != int(N)) or (N < 1):
            raise ValueError("N must be positive integer")
        self._depth = 0
        self._N = N
        self._ordinal = 0
        self._child = [None] * N
        self.nthChild = self._nthChild
        self._init = init
        if self._init is not None:
            # print("calling init")
            self._init(self)

    def _nthChild(self, n):
        """_nthChild is intended to be called as nthChild (no underbar)
           allowing this particular routine to be overridden by subclass"""
        if n > self._N:
            raise ValueError("Child n out of bounds")
        if self._child[n] is None:
            child = SimpleNTree(self._N)
            child.parent = self
            child._depth = self._depth + 1
            child._ordinal = (self._N * self._ordinal) + n
            child._init = self._init
            if child._init is not None:
                child._init(child)
            self._child[n] = child
        return self._child[n]

    def children(self):
        children = []
        for n in range(0, self._N):
            c = self.nthChild(n)
            children.append(c)
        return children

    def address(self):
        """address returns position in tree as a tuple (depth, width)"""
        return (self._depth, self._ordinal)

    def nodeId(self):
        """node_id returns unique node integer for each tree node. The root
           node is node 0, it's left is 1 and right is 2. Node 1's children
           are 3,4 and node 2's children are 5,6 (and so on)
        """
        # Id = (# in prev. rows) + ordinal (in row)
        # there are n**k elements in the kth row
        # from : http://homepages.gac.edu/~holte/courses/mcs256/documents/summation/top10sums.pdf
        # SUM:k=0 to n-1(an**k) = (1 - n**k) / (1 - n)
        if self.parent is None:
            return 0
        nInPrevRows = ((1 - pow(self._N, self._depth)) // (1 - self._N))
        # print (">>address %s, nPrevRows %d, ordinal %d" %
        #        (self.address(), nInPrevRows, self._ordinal))
        return int(((1 - pow(self._N, self._depth)) // (1 - self._N)) + self._ordinal)

    def findByAddress(self,depth,ordinal):
        """find node recursively"""
        if depth == 0:
            # print("seeking %X, found %X" % (ordinal, self._ordinal))
            assert ordinal == self._ordinal
            return self
        path = (ordinal // (pow(self._N, depth-1))) % self._N
        return self.nthChild(path).findByAddress(depth-1, ordinal)

    def pruneChildren(self):
        self._child = [None] * self._N

    def __str__(self):
        strval = "Node id %d @%s:" % (self.nodeId(), str(self.address()))
        for n in range(0,self._N):
            strval += " child[%d] = id %d," % (n, self.nthChild(n).nodeId())
        return strval[:-1]


class SimpleBTree (SimpleNTree):
    """SimpleBTree implements a Simple Binary Tree with lazy allocation as
       a subclass of SimpleNTree with N=2
    """
    def __init__(self, init=None):
        super(self.__class__, self).__init__(2,init=init)
        self.nthChild = self._nthChildBinary

    def leftof(self):
        """find (or create if needed) the left child"""
        return self._nthChildBinary(0)

    def rightof(self):
        """find (or create if needed) the left child"""
        return self._nthChildBinary(1)

    def _nthChildBinary(self, n):
        if n > self._N:
            raise ValueError("Child n out of bounds")
        if self._child[n] is None:
            child = SimpleBTree()
            child.parent = self
            child._depth = self._depth + 1
            child._ordinal = (2 * self._ordinal) + n
            child._init = self._init
            if child._init is not None:
                child._init(child)
            self._child[n] = child
        return self._child[n]

class SimpleBTreeOld (object):
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
            self._left = SimpleBTreeOld(parent=self,left=True,init=self.init)
        return self._left

    def rightof(self):
        """find (or create if needed) the left child"""
        if self._right is None:
            self._right = SimpleBTreeOld(parent=self,left=False,init=self.init)
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

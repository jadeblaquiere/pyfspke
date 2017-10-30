#!/usr/bin/env sh

#install gmp
echo "INSTALLING GMP LIBRARIES"
sudo apt-get install libgmp-dev

echo "INSTALLING PBC PREREQUISITES"
#install pbc
sudo apt-get install build-essential flex bison
echo "BUILDING PBC LIBRARIES"
git clone https://github.com/blynn/pbc.git
cd pbc
sh ./setup
./configure --prefix=/usr --enable-shared
make
echo "INSTALLING PBC LIBRARIES"
sudo make install
cd ..

echo "INSTALLING PBC PYTHON BINDINGS"
sudo pip3 install git+https://github.com/jadeblaquiere/pypbc.git

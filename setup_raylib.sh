#!/bin/bash

sudo apt update
sudo apt upgrade -y
sudo apt install git cmake build-essential -y

rm -rf raylib
git clone https://github.com/raysan5/raylib
cd raylib
mkdir build
cd build
sudo cmake -DSHARED=ON -DSTATIC=ON ..
make -j4
sudo make install
cp src/libraylib.so.2.0.0 ../../libs/
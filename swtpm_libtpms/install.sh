#!/bin/bash

pushd libtpms/
./autogen.sh --with-openssl --with-tpm2 --prefix=/usr 
make -j `nproc`
sudo make uninstall
./autogen.sh --with-openssl --with-tpm2 --prefix=/usr 
make -j `nproc`
sudo make install
popd

#compilação swtpm

pushd swtpm/
./autogen.sh
./configure --prefix=/usr
make -j `nproc`
sudo make uninstall
./autogen.sh
./configure --prefix=/usr
make -j `nproc`
sudo make install
popd

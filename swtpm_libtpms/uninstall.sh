#!/bin/bash

pushd libtpms/
sudo make uninstall
popd

#compilação swtpm

pushd swtpm/
sudo make uninstall
popd

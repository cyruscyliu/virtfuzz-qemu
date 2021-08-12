#!/bin/sh -x
cd build-clean
CC=clang CXX=clang++ ../configure --enable-fuzzing --enable-spice \
	--target-list="i386-softmmu arm-softmmu aarch64-softmmu" \
	--enable-debug 
ninja qemu-fuzz-i386 qemu-fuzz-arm qemu-fuzz-aarch64
cd ..

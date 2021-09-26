#!/bin/sh -x
cd build-clean
CC=clang CXX=clang++ ../configure --enable-fuzzing \
	--target-list="i386-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-fuzz-i386 qemu-fuzz-arm qemu-fuzz-aarch64
cd ..

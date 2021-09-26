#!/bin/sh -x
cd build-debug
CC=clang CXX=clang++ ../configure --enable-fuzzing --enable-debug \
	--target-list="i386-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-fuzz-i386 qemu-fuzz-arm qemu-fuzz-aarch64
cd ..

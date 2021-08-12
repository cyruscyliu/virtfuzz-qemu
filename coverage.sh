#!/bin/sh -x
cd build-coverage
CC=clang CXX=clang++ ../configure --enable-fuzzing --enable-spice \
	--extra-cflags="-fprofile-instr-generate -fcoverage-mapping" \
	--target-list="i386-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-fuzz-i386 qemu-fuzz-arm qemu-fuzz-aarch64
cd ..

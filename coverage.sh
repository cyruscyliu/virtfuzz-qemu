#!/bin/sh -x
cd build-coverage
CLANG_COV_DUMP=1 CC=clang CXX=clang++ ../configure --enable-fuzzing \
	--extra-cflags="-DCLANG_COV_DUMP -fprofile-instr-generate -fcoverage-mapping -Wno-error" \
	--extra-cxxflags="-DCLANG_COV_DUMP -Wno-error" \
	--extra-ldflags="-DCLANG_COV_DUMP" \
	--target-list="i386-softmmu" # arm-softmmu aarch64-softmmu"
ninja qemu-fuzz-i386 # qemu-fuzz-arm qemu-fuzz-aarch64
cd ..

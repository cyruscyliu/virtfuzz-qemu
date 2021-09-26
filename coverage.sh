#!/bin/sh -x
cd build-coverage
NDEBUG=1 G_DISABLE_ASSERT=1 CLANG_COV_DUMP=1 CC=clang CXX=clang++ ../configure --enable-fuzzing \
	--extra-cflags="-fprofile-instr-generate -fcoverage-mapping" \
	--target-list="i386-softmmu arm-softmmu aarch64-softmmu"
ninja qemu-fuzz-i386 qemu-fuzz-arm qemu-fuzz-aarch64
cd ..

#!/bin/sh -e
#
# OSS-Fuzz build script. See:
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh
#
# The file is consumed by:
# https://github.com/google/oss-fuzz/blob/master/projects/qemu/Dockerfiles
#
# This code is licensed under the GPL version 2 or later.  See
# the COPYING file in the top-level directory.
#

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     -fsanitize=fuzzer /path/to/library.a

fatal () {
    echo "Error : ${*}, exiting."
    exit 1
}

OSS_FUZZ_BUILD_DIR="./build-ubsan/"

# There seems to be a bug in clang-11 (used for builds on oss-fuzz) :
#   accel/tcg/cputlb.o: In function `load_memop':
#   accel/tcg/cputlb.c:1505: undefined reference to `qemu_build_not_reached'
#
# When building with optimization, the compiler is expected to prove that the
# statement cannot be reached, and remove it. For some reason clang-11 doesn't
# remove it, resulting in an unresolved reference to qemu_build_not_reached
# Undefine the __OPTIMIZE__ macro which compiler.h relies on to choose whether
# to " #define qemu_build_not_reached()  g_assert_not_reached() "
EXTRA_CFLAGS="$CFLAGS -U __OPTIMIZE__"

if ! { [ -e "./COPYING" ] &&
   [ -e "./MAINTAINERS" ] &&
   [ -e "./Makefile" ] &&
   [ -e "./docs" ] &&
   [ -e "./VERSION" ] &&
   [ -e "./linux-user" ] &&
   [ -e "./softmmu" ];} ; then
    fatal "Please run the script from the top of the QEMU tree"
fi

mkdir -p $OSS_FUZZ_BUILD_DIR || fatal "mkdir $OSS_FUZZ_BUILD_DIR failed"
cd $OSS_FUZZ_BUILD_DIR || fatal "cd $OSS_FUZZ_BUILD_DIR failed"


if [ -z ${OUT+x} ]; then
    DEST_DIR=$(realpath "./DEST_DIR")
else
    DEST_DIR=$OUT
fi

mkdir -p "$DEST_DIR/lib/"  # Copy the shared libraries here

# If not necessary, use TARGET_LIST_32 for speed
TARGET_LIST_64="aarch64-softmmu mips64-softmmu mips64el-softmmu \
    ppc64-softmmu riscv64-softmmu sparc64-softmmu x86_64-softmmu"
TARGET_LIST_64_NECESSARY=aarch64-softmmu
TARGET_LIST_32="i386-softmmu arm-softmmu" # \
    # alpha-softmmu avr-softmmu cris-softmmu \
    # hppa-softmmu m68k-softmmu microblaze-softmmu \
    # microblazeel-softmmu mips-softmmu mipsel-softmmu moxie-softmmu \
    # nios2-softmmu or1k-softmmu ppc-softmmu riscv32-softmmu rx-softmmu \
    # s390x-softmmu sh4-softmmu sh4eb-softmmu sparc-softmmu tricore-softmmu \
    # xtensa-softmmu xtensaeb-softmmu"
TARGET_LIST="$TARGET_LIST_32 $TARGET_LIST_64_NECESSARY"
FUZZ_TARGET_LIST=$(echo $TARGET_LIST | sed "s/-softmmu//g" | \
    sed -E "s/(\S)(\s|$)/\1  /g;s/(\s|^)(\S)/qemu-fuzz-\2/g")

# Build once to get the list of dynamic lib paths, and copy them over
../configure --disable-werror --cc="$CC" --cxx="$CXX" --enable-fuzzing \
    --prefix="$DEST_DIR" --bindir="$DEST_DIR" --datadir="$DEST_DIR/data/" \
    --extra-cflags="$EXTRA_CFLAGS" --target-list="i386-softmmu" --enable-spice

if ! make "-j$(nproc)" qemu-fuzz-i386; then
    fatal "Build failed. Please specify a compiler with fuzzing support"\
          "using the \$CC and \$CXX environment variables"\
          "\nFor example: CC=clang CXX=clang++ $0"
fi

for i in $(ldd ./qemu-fuzz-i386 | cut -f3 -d' '); do
    cp "$i" "$DEST_DIR/lib/"
done
rm qemu-fuzz-i386

# Build a second time to build the final binary with correct rpath
../configure --disable-werror --cc="$CC" --cxx="$CXX" --enable-fuzzing \
    --prefix="$DEST_DIR" --bindir="$DEST_DIR" --datadir="$DEST_DIR/data/" \
    --extra-cflags="$EXTRA_CFLAGS" --extra-ldflags="-Wl,-rpath,\$ORIGIN/lib" \
    --target-list="$TARGET_LIST" --enable-spice
make "-j$(nproc)" $FUZZ_TARGET_LIST V=1

# Copy over the datadir
cp  -r ../pc-bios/ "$DEST_DIR/pc-bios"

for arch in $(echo $TARGET_LIST | sed "s/-softmmu//g"); do
    targets=$(./qemu-fuzz-$arch | awk '$1 ~ /\*/  {print $2}')
    base_copy="$DEST_DIR/qemu-fuzz-$arch-target-$(echo "$targets" | head -n 1)"

    cp "./qemu-fuzz-$arch" "$base_copy"

    # Run the fuzzer with no arguments, to print the help-string and get the list
    # of available fuzz-targets. Copy over the qemu-fuzz-i386, naming it according
    # to each available fuzz target (See 05509c8e6d fuzz: select fuzz target using
    # executable name)
    for target in $(echo "$targets" | tail -n +2); do
        # Ignore the generic-fuzz target, as it requires some environment variables
        # to be configured. We have some generic-fuzz-{pc-q35, floppy, ...} targets
        # that are thin wrappers around this target that set the required
        # environment variables according to predefined configs.
        if [ "$target" != "generic-fuzz"  ] && [ "$target" != "stateful-fuzz" ]; then
            ln -f $base_copy \
                "$DEST_DIR/qemu-fuzz-$arch-target-$target"
        fi
    done
done

echo "Done. The fuzzers are located in $DEST_DIR"
exit 0

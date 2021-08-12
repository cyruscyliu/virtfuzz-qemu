TARGET=$1
cp default.profraw $TARGET.profraw
llvm-profdata merge -output=$TARGET.profdata $TARGET.profraw
ln -f qemu-fuzz-i386 qemu-fuzz-i386-target-stateful-fuzz-$TARGET
llvm-cov show ./qemu-fuzz-i386-target-stateful-fuzz-$TARGET -instr-profile=$TARGET.profdata --format html -output-dir=/report/qemu-fuzz-target-stateful-fuzz-$TARGET/

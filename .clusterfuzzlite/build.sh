#!/bin/bash
set -euxo pipefail
cd "$SRC/blockforge"
mkdir -p "$WORK/obj" "$OUT"
sources=(
  src/analysis.cc src/base.cc src/block.cc src/checker.cc src/codec.cc
  src/directory.cc src/filesystem.cc src/inode.cc src/journal.cc src/path.cc
)
objects=()
for source in "${sources[@]}"; do
  object="$WORK/obj/$(basename "${source%.cc}").o"
  "$CXX" $CXXFLAGS -std=c++17 -I"$SRC/blockforge/include" \
    -c "$SRC/blockforge/$source" -o "$object"
  objects+=("$object")
done
targets=(
  filesystem_mount_fuzzer filesystem_walk_fuzzer filesystem_read_fuzzer
  filesystem_repair_fuzzer filesystem_operation_fuzzer
)
for target in "${targets[@]}"; do
  "$CXX" $CXXFLAGS -std=c++17 -I"$SRC/blockforge/include" \
    "$SRC/blockforge/fuzz/$target.cc" "${objects[@]}" \
    "$LIB_FUZZING_ENGINE" -o "$OUT/$target"
done

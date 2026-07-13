#!/bin/bash
# macOS aarch64 (Apple Silicon M1/M2/M3)
# Usage: ./build-macos-aarch64.sh [JAVA_HOME]

JAVA_HOME="${1:-${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null)}}"
INC="$JAVA_HOME/include"
INC_MAC="$JAVA_HOME/include/darwin"
OUT="../src/main/resources/native/macos-aarch64/libnat256mul.dylib"

mkdir -p "$(dirname "$OUT")"
# clang on Apple Silicon; gcc may be clang alias
clang -shared -O3 -mcpu=apple-m1 -fPIC -arch arm64 -I"$INC" -I"$INC_MAC" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

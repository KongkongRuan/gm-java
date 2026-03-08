#!/bin/bash
# macOS x86_64 (Intel)
# Usage: ./build-macos-x64.sh [JAVA_HOME]

JAVA_HOME="${1:-${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null)}}"
INC="$JAVA_HOME/include"
INC_MAC="$JAVA_HOME/include/darwin"
OUT="../src/main/resources/native/macos-x86_64/libnat256mul.dylib"

mkdir -p "$(dirname "$OUT")"
gcc -shared -O3 -march=native -fPIC -arch x86_64 -I"$INC" -I"$INC_MAC" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

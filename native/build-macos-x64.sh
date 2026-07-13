#!/bin/bash
# macOS x86_64 (Intel)
# Usage: ./build-macos-x64.sh [JAVA_HOME]

JAVA_HOME="${1:-${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null)}}"
INC="$JAVA_HOME/include"
INC_MAC="$JAVA_HOME/include/darwin"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/../src/main/resources/native/macos-x86_64/libnat256mul.dylib"
SRC="$SCRIPT_DIR/native_mul.c"

mkdir -p "$(dirname "$OUT")"
gcc -shared -O3 -march=x86-64 -fPIC -arch x86_64 -I"$INC" -I"$INC_MAC" -o "$OUT" "$SRC"
echo "Build OK: $OUT"

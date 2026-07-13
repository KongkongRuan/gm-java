#!/bin/bash
# Linux x86_64
# Usage: ./build-sm4gcm-linux-x64.sh [JAVA_HOME]

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/../src/main/resources/native/linux-x86_64/libsm4gcm.so"
SRC="$SCRIPT_DIR/native_sm4_gcm.c"

mkdir -p "$(dirname "$OUT")"
gcc -shared -O3 -march=x86-64 -mpclmul -msse2 -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" "$SRC"
echo "Build OK: $OUT"

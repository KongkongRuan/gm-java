#!/bin/bash
# Linux x86_64
# Usage: ./build-linux-x64.sh [JAVA_HOME]
# JAVA_HOME defaults to $JAVA_HOME or /usr/lib/jvm/default-java

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/../src/main/resources/native/linux-x86_64/libnat256mul.so"
SRC="$SCRIPT_DIR/native_mul.c"

mkdir -p "$(dirname "$OUT")"
gcc -shared -O3 -march=x86-64 -mtune=generic -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" "$SRC"
echo "Build OK: $OUT"

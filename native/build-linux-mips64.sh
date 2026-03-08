#!/bin/bash
# Linux MIPS64 (龙芯 3A4000 及更早型号)
# Usage: ./build-linux-mips64.sh [JAVA_HOME]
# Run on Loongson MIPS machine

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
OUT="../src/main/resources/native/linux-mips64/libnat256mul.so"

mkdir -p "$(dirname "$OUT")"
gcc -shared -O3 -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

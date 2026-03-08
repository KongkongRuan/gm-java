#!/bin/bash
# Linux LoongArch64 (龙芯 3A5000+)
# Usage: ./build-linux-loongarch64.sh [JAVA_HOME]
# Run on Loongson machine, or cross-compile with loongarch64-linux-gnu-gcc

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
OUT="../src/main/resources/native/linux-loongarch64/libnat256mul.so"

if command -v loongarch64-linux-gnu-gcc &>/dev/null; then
    CC=loongarch64-linux-gnu-gcc
elif uname -m | grep -q loongarch; then
    CC=gcc
else
    echo "Need loongarch64-linux-gnu-gcc for cross-compile, or run on Loongson"
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
$CC -shared -O3 -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

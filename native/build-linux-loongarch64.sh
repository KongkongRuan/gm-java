#!/bin/bash
# Linux LoongArch64 (龙芯 3A5000+)
# Usage: ./build-linux-loongarch64.sh [JAVA_HOME]
# Run on Loongson machine, or cross-compile with loongarch64-linux-gnu-gcc

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
OUT="../src/main/resources/native/linux-loongarch64/libnat256mul.so"

# Prefer native gcc on Loongson; for x86 host use loongarch64-linux-gnu-gcc (or versioned gcc-14 etc.)
CC=""
for TRY in loongarch64-linux-gnu-gcc loongarch64-linux-gnu-gcc-14 loongarch64-linux-gnu-gcc-13 loongarch64-linux-gnu-gcc-12; do
    if command -v "$TRY" &>/dev/null; then
        CC="$TRY"
        break
    fi
done
if [ -z "$CC" ] && uname -m | grep -q loongarch; then
    CC=gcc
fi
if [ -z "$CC" ]; then
    echo "Need loongarch64-linux-gnu-gcc for cross-compile, or run on Loongson"
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
$CC -shared -O3 -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

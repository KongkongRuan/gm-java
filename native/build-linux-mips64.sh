#!/bin/bash
# Linux MIPS64 (龙芯 3A4000 及更早型号)
# Usage: ./build-linux-mips64.sh [JAVA_HOME]
# Run on Loongson MIPS machine

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
OUT="../src/main/resources/native/linux-mips64/libnat256mul.so"

# Prefer native gcc on MIPS; for x86 host use mips64el-linux-gnuabi64-gcc (or versioned gcc-14 etc.)
CC=""
for PREFIX in mips64el-linux-gnuabi64 mips64-linux-gnuabi64; do
    for SUFFIX in "" "-14" "-13" "-12"; do
        TRY="${PREFIX}-gcc${SUFFIX}"
        if command -v "$TRY" &>/dev/null; then
            CC="$TRY"
            break 2
        fi
    done
done
if [ -z "$CC" ] && uname -m | grep -q mips64; then
    CC=gcc
fi
if [ -z "$CC" ]; then
    echo "Need mips64el-linux-gnuabi64-gcc (or mips64-linux-gnuabi64-gcc) for cross-compile, or run on MIPS64"
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
$CC -shared -O3 -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

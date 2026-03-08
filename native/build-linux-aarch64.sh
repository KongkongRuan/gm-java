#!/bin/bash
# Linux aarch64 (ARM64)
# Usage: ./build-linux-aarch64.sh [JAVA_HOME]
# Cross-compile: use aarch64-linux-gnu-gcc, or run on ARM machine

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"
OUT="../src/main/resources/native/linux-aarch64/libnat256mul.so"

# Prefer native gcc on ARM; for x86 host use aarch64-linux-gnu-gcc
if command -v aarch64-linux-gnu-gcc &>/dev/null; then
    CC=aarch64-linux-gnu-gcc
elif uname -m | grep -q aarch64; then
    CC=gcc
else
    echo "Need aarch64-linux-gnu-gcc for cross-compile, or run on ARM64"
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
$CC -shared -O3 -fPIC -I"$INC" -I"$INC_LINUX" -o "$OUT" native_mul.c
echo "Build OK: $OUT"

#!/bin/bash
# Cross-compile sm3native for Linux architectures without a native runner.
# Usage: ./build-sm3-linux-cross.sh <arch> <cross-prefix>
# Example: ./build-sm3-linux-cross.sh aarch64 aarch64-linux-gnu

set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <arch> <cross-prefix>"
    echo "  arch: aarch64 | loongarch64 | mips64"
    echo "  cross-prefix: e.g. aarch64-linux-gnu-"
    exit 1
fi

ARCH="$1"
CROSS_PREFIX="$2"

# 尝试无版本后缀的 gcc，再尝试带版本后缀的（Ubuntu 24.04 的 LoongArch 编译器为 gcc-14-loongarch64-linux-gnu）
CC=""
for SUFFIX in "" "-14" "-13" "-12"; do
    TRY="${CROSS_PREFIX}gcc${SUFFIX}"
    if command -v "$TRY" &>/dev/null; then
        CC="$TRY"
        break
    fi
done
if [ -z "$CC" ]; then
    echo "No usable cross compiler found for prefix: $CROSS_PREFIX"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/sm3_native.c"

JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/default-java}"
INC="$JAVA_HOME/include"
INC_LINUX="$JAVA_HOME/include/linux"

OUT_DIR="$SCRIPT_DIR/../src/main/resources/native/linux-$ARCH"
mkdir -p "$OUT_DIR"

OUT="$OUT_DIR/libsm3native.so"

# AVX2 only on x86_64; cross targets use scalar fallback.
EXTRA_FLAGS=""

echo "Building $OUT (arch=$ARCH, cc=$CC) ..."
"$CC" -shared -O3 -fPIC $EXTRA_FLAGS -I"$INC" -I"$INC_LINUX" -o "$OUT" "$SRC"
echo "Build OK: $OUT"

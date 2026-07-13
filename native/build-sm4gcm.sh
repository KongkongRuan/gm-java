#!/bin/bash
# Build sm4gcm for Linux/macOS.
# Usage: ./build-sm4gcm.sh [JAVA_HOME]
# To cross-compile for a different architecture (e.g. x86_64 on Apple Silicon):
#   TARGET_ARCH=x86_64 ./build-sm4gcm.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/native_sm4_gcm.c"

OS=$(uname -s)
ARCH="${TARGET_ARCH:-$(uname -m)}"

case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    loongarch64) ARCH="loongarch64" ;;
    mips64*) ARCH="mips64" ;;
    *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

JAVA_HOME="${1:-${JAVA_HOME:-/usr/lib/jvm/default-java}}"
INC="$JAVA_HOME/include"
case "$PLATFORM" in
    linux)  INC_OS="$JAVA_HOME/include/linux" ;;
    macos)  INC_OS="$JAVA_HOME/include/darwin" ;;
esac

OUT_DIR="$SCRIPT_DIR/../src/main/resources/native/$PLATFORM-$ARCH"
mkdir -p "$OUT_DIR"

case "$PLATFORM" in
    linux)  LIB_NAME="libsm4gcm.so" ;;
    macos)  LIB_NAME="libsm4gcm.dylib" ;;
esac

OUT="$OUT_DIR/$LIB_NAME"

# PCLMUL/SSE2 is only available on x86_64; other architectures use the scalar fallback.
if [ "$ARCH" = "x86_64" ]; then
    EXTRA_FLAGS="-march=x86-64 -mpclmul -msse2"
else
    EXTRA_FLAGS=""
fi

# On macOS, explicitly target the requested architecture to allow cross-compilation.
if [ "$PLATFORM" = "macos" ]; then
    EXTRA_FLAGS="$EXTRA_FLAGS -arch $ARCH"
fi

echo "Building $OUT (platform=$PLATFORM, arch=$ARCH, javahome=$JAVA_HOME) ..."
gcc -shared -O3 -fPIC $EXTRA_FLAGS -I"$INC" -I"$INC_OS" -o "$OUT" "$SRC"
echo "Build OK: $OUT"

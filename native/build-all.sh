#!/bin/bash
# Build for current platform only (detect and build)
# Usage: ./build-all.sh

case "$(uname -s)" in
    Linux)
        case "$(uname -m)" in
            x86_64)         ./build-linux-x64.sh ;;
            aarch64)        ./build-linux-aarch64.sh ;;
            loongarch64)    ./build-linux-loongarch64.sh ;;
            mips64*)        ./build-linux-mips64.sh ;;
            *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$(uname -m)" in
            x86_64)     ./build-macos-x64.sh ;;
            arm64)      ./build-macos-aarch64.sh ;;
            *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $(uname -s)"
        exit 1
        ;;
esac

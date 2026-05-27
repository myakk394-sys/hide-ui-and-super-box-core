#!/usr/bin/env bash
#
# OpenWrt Static Musl Cross-Compilation Script for Hidekey (Super Box)
#
# Usage:
#   ./build.sh <architecture>
#   Examples:
#     ./build.sh aarch64
#     ./build.sh mips
#     ./build.sh mipsel
#     ./build.sh x86_64

set -e

ARCH=$1

if [ -z "$ARCH" ]; then
    echo "❌ Error: Please specify target architecture!"
    echo "Usage:"
    echo "  $0 <aarch64 | mips | mipsel | x86_64>"
    exit 1
fi

echo "=========================================================="
echo "🛡️  Hidekey Router Musl Cross-Compilation Builder"
echo "=========================================================="

case $ARCH in
    aarch64)
        TARGET="aarch64-unknown-linux-musl"
        ;;
    mips)
        TARGET="mips-unknown-linux-musl"
        ;;
    mipsel)
        TARGET="mipsel-unknown-linux-musl"
        ;;
    x86_64)
        TARGET="x86_64-unknown-linux-musl"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "[*] TARGET: $TARGET"
echo "[*] Adding rust target toolchain..."
rustup target add $TARGET || true

echo "[*] Building release static binary using Cargo..."
# Compile with size optimizations configured in Cargo.toml release profile
cargo build --release --target $TARGET --lib --bin super_box

BIN_PATH="../target/$TARGET/release/super_box"

if [ -f "$BIN_PATH" ]; then
    echo "[SUCCESS] Core successfully compiled!"
    echo "File location: $BIN_PATH"
    
    # Show file size
    SIZE=$(du -h "$BIN_PATH" | cut -f1)
    echo "Compiled Binary Size: $SIZE"
    
    # Suggest compression using UPX if installed
    if command -v upx &> /dev/null; then
        echo "[*] Compressing binary with UPX for embedded devices..."
        upx --best --lzma "$BIN_PATH"
        COMPRESSED_SIZE=$(du -h "$BIN_PATH" | cut -f1)
        echo "UPX Compressed Binary Size: $COMPRESSED_SIZE"
    else
        echo "💡 Tip: Install 'upx' utility to shrink binary size even further (~1.2MB) for small router flash storage!"
    fi
else
    echo "❌ Error: Compiled binary not found!"
    exit 1
fi

echo "=========================================================="

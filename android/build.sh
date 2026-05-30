#!/usr/bin/env bash
#
# Android NDK Cross-Compilation Automation Script for Hidekey (Super Box)
# 
# Usage:
#   export ANDROID_NDK_HOME="/path/to/android-sdk/ndk/version"
#   ./build.sh

set -e

# Verify NDK path is set
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "❌ Error: ANDROID_NDK_HOME environment variable is not defined!"
    echo "Please set it before running, e.g.:"
    echo "  export ANDROID_NDK_HOME=\"/Users/username/Library/Android/sdk/ndk/25.1.8937393\""
    exit 1
fi

echo "=========================================================="
echo "🛡️  Hidekey Core Android Cross-Compilation Builder"
echo "=========================================================="
echo "NDK Path: $ANDROID_NDK_HOME"

# Install target tools if missing
echo "[*] Checking target toolchains..."
rustup target add aarch64-linux-android || true
rustup target add armv7-linux-androideabi || true

# Verify cargo-ndk is installed
if ! command -v cargo-ndk &> /dev/null; then
    echo "[*] Installing cargo-ndk cargo extension..."
    cargo install cargo-ndk
fi

# Build for modern 64-bit ARM architectures (arm64-v8a)
echo "[*] Compiling libsuper_box JNI for aarch64-linux-android (Release)..."
cargo ndk --target aarch64-linux-android --platform 21 -- build --release --lib

# Build for older 32-bit ARM architectures (armeabi-v7a)
echo "[*] Compiling libsuper_box JNI for armv7-linux-androideabi (Release)..."
cargo ndk --target armv7-linux-androideabi --platform 21 -- build --release --lib

echo "=========================================================="
echo "✅ Compilation Successful!"
echo "=========================================================="
echo "Your JNI libraries are compiled and ready:"
echo "👉 ARM64: target/aarch64-linux-android/release/libsuper_box.so"
echo "👉 ARM32: target/armv7-linux-androideabi/release/libsuper_box.so"
echo "=========================================================="

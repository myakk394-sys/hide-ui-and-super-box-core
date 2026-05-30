#!/bin/bash
# ==============================================================================
#  iOS Compilation Automation Script for SuperBox VPN Core
#  Generates optimized Apple iOS Static Libraries and Xcode XCFramework
# ==============================================================================

set -e

# Make sure we run in the project root directory
cd "$(dirname "$0")/.."

echo "🚀 Installing Apple iOS Targets..."
rustup target add aarch64-apple-ios           # Physical iPhones
rustup target add aarch64-apple-ios-sim       # Apple Silicon M1/M2/M3 Simulators
rustup target add x86_64-apple-ios            # Intel Simulators

echo "⚙️ Compiling optimized iOS targets in release mode..."

# Build physical arm64 iOS library
cargo build --release --target aarch64-apple-ios

# Build Apple Silicon simulator library
cargo build --release --target aarch64-apple-ios-sim

# Build Intel simulator library
cargo build --release --target x86_64-apple-ios

echo "📦 Creating Xcode Simulator Universal Library..."
mkdir -p target/ios-simulator

lipo -create \
  target/x86_64-apple-ios/release/libsuper_box.a \
  target/aarch64-apple-ios-sim/release/libsuper_box.a \
  -output target/ios-simulator/libsuper_box.a

echo "🏗 Building Universal Apple XCFramework..."
rm -rf target/super_box.xcframework

# Create XCFramework wrapping physical + simulator libs for easy drag-and-drop in Xcode
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsuper_box.a \
  -headers include \
  -library target/ios-simulator/libsuper_box.a \
  -headers include \
  -output target/super_box.xcframework

echo "=============================================================================="
echo "  ✅ Success! Apple Xcode XCFramework generated successfully!"
echo "  Location: target/super_box.xcframework"
echo "  This folder is ready to drag-and-drop directly into Xcode!"
echo "=============================================================================="

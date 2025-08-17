#!/usr/bin/env bash
set -euo pipefail

# Step 1: Clean and build with PGO.
cargo clean
cargo pgo build

# Step 2: Download the latest Linux kernel release.
echo "Fetching latest Linux kernel release..."
KERNEL_URL=$(curl -s https://www.kernel.org/ | grep -Eo 'https://cdn.kernel.org/pub/linux/kernel/v[0-9]+\.x/linux-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.xz' | head -n1)
KERNEL_FILE="tests/data/$(basename "$KERNEL_URL")"

mkdir -p tests/data
if [ ! -f "$KERNEL_FILE" ]; then
    echo "Downloading $KERNEL_URL ..."
    curl -L "$KERNEL_URL" -o "$KERNEL_FILE"
else
    echo "Kernel tarball already exists: $KERNEL_FILE"
fi

# Step 3: Detect OS and adjust binary path/extension.
OS=$(uname -s)
ARCH=$(uname -m)

TARGET_DIR="target"
BINARY_NAME="slz"
EXT=""

case "$OS" in
    Linux)
        TARGET="$TARGET_DIR/$ARCH-unknown-linux-gnu/release"
        ;;
    Darwin)
        TARGET="$TARGET_DIR/$ARCH-apple-darwin/release"
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        TARGET="$TARGET_DIR/x86_64-pc-windows-msvc/release"
        EXT=".exe"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

BIN="$TARGET/$BINARY_NAME$EXT"

if [ ! -f "$BIN" ]; then
    echo "Error: binary not found at $BIN"
    exit 1
fi

# Step 4: Run compression and decompression to create a PGO profile.
"$BIN" --preset 7 --keep "$KERNEL_FILE"
"$BIN" --decompress --keep "$KERNEL_FILE.slz"

# Step 5: Optimize with PGO.
cargo pgo optimize

# Step 6: Copy final binary to current directory.
cp "$BIN" .
echo "Final binary copied to ./$(basename "$BIN")"

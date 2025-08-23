#!/usr/bin/env bash
set -euo pipefail

# Step 1: Clean and build with PGO.
cargo clean
cargo pgo build

# Step 2: Download the latest Linux kernel release.
echo "Fetching latest Linux kernel release..."
KERNEL_URL=$(curl -s https://www.kernel.org/ | grep -Eo 'https://cdn.kernel.org/pub/linux/kernel/v[0-9]+\.x/linux-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.xz' | head -n1)
KERNEL_XZ="tests/data/$(basename "$KERNEL_URL")"
KERNEL_TAR="${KERNEL_XZ%.xz}"   # remove .xz -> .tar

mkdir -p tests/data
if [ ! -f "$KERNEL_TAR" ]; then
    if [ ! -f "$KERNEL_XZ" ]; then
        echo "Downloading $KERNEL_URL ..."
        curl -L "$KERNEL_URL" -o "$KERNEL_XZ"
    else
        echo "Compressed kernel tarball already exists: $KERNEL_XZ"
    fi

    echo "Decompressing $KERNEL_XZ ..."
    xz --decompress --keep "$KERNEL_XZ"
else
    echo "Kernel tar already exists: $KERNEL_TAR"
fi

# Step 3: Detect OS and adjust binary path/extension.
OS=$(uname -s)
ARCH=$(uname -m)

TARGET_DIR="target"
BINARY_NAME="toa"
EXT=""

case "$OS-$ARCH" in
    Linux-x86_64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    Linux-aarch64)
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    Darwin-x86_64)
        RUST_TARGET="x86_64-apple-darwin"
        ;;
    Darwin-arm64)
        RUST_TARGET="aarch64-apple-darwin"
        ;;
    MINGW*-*|MSYS*-*|CYGWIN*-*|Windows_NT-*)
        RUST_TARGET="x86_64-pc-windows-msvc"
        EXT=".exe"
        ;;
    *)
        echo "Unsupported OS-ARCH combination: $OS-$ARCH"
        exit 1
        ;;
esac

TARGET_SPECIFIC="$TARGET_DIR/$RUST_TARGET/release"
BIN="$TARGET_SPECIFIC/$BINARY_NAME$EXT"

# Step 4: Run compression and decompression to create a PGO profile
"$BIN" --threads=2 --preset 6 --keep "$KERNEL_TAR"
"$BIN" --threads=2 --decompress --keep "$KERNEL_TAR.toa"
"$BIN" --threads=2 --preset 1 --ecc light --keep tests/data/executable.exe
"$BIN" --threads=2 --decompress --keep tests/data/executable.exe.toa
"$BIN" --threads=2 --preset 3 --ecc medium --keep tests/data/executable.exe
"$BIN" --threads=2 --decompress --keep tests/data/executable.exe.toa
"$BIN" --threads=2 --preset 4 --ecc heavy --keep tests/data/executable.exe
"$BIN" --threads=2 --decompress --keep tests/data/executable.exe.toa

# Step 5: Optimize with PGO
cargo pgo optimize

# Step 6: Copy final binary to current directory
cp "$BIN" .
echo "Final binary copied to ./$(basename "$BIN")"

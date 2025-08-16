#!/usr/bin/env bash

cargo clean
cargo pgo build
./target/x86_64-pc-windows-msvc/release/slz.exe --preset 7 --keep tests/data/linux-6.16.tar
./target/x86_64-pc-windows-msvc/release/slz.exe --decompress --keep tests/data/linux-6.16.tar.slz
#./target/x86_64-pc-windows-msvc/release/slz.exe --preset 3 --keep tests/data/ubuntu-24.04.3-desktop-amd64.iso
#./target/x86_64-pc-windows-msvc/release/slz.exe --decompress --keep tests/data/ubuntu-24.04.3-desktop-amd64.iso.slz
cargo pgo optimize

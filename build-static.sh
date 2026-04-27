#!/bin/bash
# build-static.sh — produce the production static accel binary.
#
# Every binary published on the `binaries` orphan branch is built by
# this script. It enforces full static linking (glibc + libelf + libbpf
# + zlib + zstd all baked in), so the resulting executable runs on any
# x86_64 Linux ≥ 6.4 regardless of the system's glibc version.
#
# This avoids the recurring trap of "binary built on Ubuntu 24.04 dev
# VM (glibc 2.39) refuses to run on Debian 12 VPS (glibc 2.36)" — the
# fix7 regression that triggered this script's creation.
#
# REQUIREMENTS (Ubuntu / Debian):
#   apt install -y build-essential clang pkg-config \
#                  libelf-dev zlib1g-dev libzstd-dev linux-libc-dev
#
# USAGE:
#   ./build-static.sh
#
# OUTPUT:
#   target/x86_64-unknown-linux-gnu/release/accel
#     — statically linked, no dynamic dependencies.
#
# VERIFY:
#   file ...    → "statically linked"
#   ldd ...     → "not a dynamic executable"
#   objdump -T  → no GLIBC_ symbol version requirements
#
# NOTE: do NOT use musl target. We tried; Ubuntu's libelf-dev only
# ships glibc-ABI headers (musl's elf.h lacks Elf64_Relr), and there's
# no apt-installable musl-compatible libelf. Static glibc gives the
# same self-contained result for our use case (no DNS / no NSS / no
# locale-dependent code paths).

set -euo pipefail

cd "$(dirname "$0")"

echo "==> cargo build --release  (uses .cargo/config.toml)"
cargo build --release

BIN=target/x86_64-unknown-linux-gnu/release/accel

echo ""
echo "==> verifying static linkage"

if file "$BIN" | grep -q "statically linked"; then
    echo "  ✓ file:    statically linked"
else
    echo "  ✗ file does NOT report statically linked:"
    file "$BIN"
    exit 1
fi

# ldd exits non-zero on static binaries even when output is correct;
# capture both, then grep, instead of piping (would trip pipefail).
LDD_OUT=$(ldd "$BIN" 2>&1 || true)
if echo "$LDD_OUT" | grep -q "not a dynamic executable"; then
    echo "  ✓ ldd:     not a dynamic executable"
else
    echo "  ✗ ldd reports dynamic dependencies:"
    echo "$LDD_OUT"
    exit 1
fi

GLIBC_SYMS=$(objdump -T "$BIN" 2>/dev/null | grep -oP 'GLIBC_[0-9.]+' | sort -V -u || true)
if [ -z "$GLIBC_SYMS" ]; then
    echo "  ✓ objdump: no GLIBC_ symbol version requirements"
else
    echo "  ✗ binary still references glibc symbol versions:"
    echo "$GLIBC_SYMS"
    exit 1
fi

echo ""
echo "==> binary stats"
ls -la "$BIN"
md5sum "$BIN"

echo ""
echo "==> ready to publish to binaries branch:"
echo "  git checkout binaries"
echo "  cp $BIN ./accel"
echo "  md5sum accel  # paste this into binaries-branch README"
echo "  git add accel README.md && git commit && git push -u origin binaries"

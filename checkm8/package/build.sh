#!/bin/sh
set -e

DYLIB="$1"
OUT_DIR="${2:-dist}"
VERSION="${3:-1.0.0}"

if [ -z "$DYLIB" ] || [ ! -f "$DYLIB" ]; then
    echo "usage: $0 <myjb_loader.dylib> [out_dir] [version]" >&2
    exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb not found (brew install dpkg / apt install dpkg)" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/DEBIAN"
cp -R "$ROOT/var" "$STAGE/"

cp "$ROOT/DEBIAN/postinst" "$STAGE/DEBIAN/postinst"
chmod 755 "$STAGE/DEBIAN/postinst"

cp "$ROOT/DEBIAN/prerm" "$STAGE/DEBIAN/prerm"
chmod 755 "$STAGE/DEBIAN/prerm"

sed "s/^Version: .*/Version: $VERSION/" "$ROOT/DEBIAN/control" > "$STAGE/DEBIAN/control"
chmod 644 "$STAGE/DEBIAN/control"

cp "$DYLIB" "$STAGE/var/jb/usr/lib/TweakInject/myjb_loader.dylib"
chmod 755 "$STAGE/var/jb/usr/lib/TweakInject/myjb_loader.dylib"

mkdir -p "$OUT_DIR"
PKG="com.wmua1.myjb.checkm8_${VERSION}_iphoneos-arm64.deb"
if dpkg-deb --help 2>&1 | grep -q root-owner-group; then
    dpkg-deb --root-owner-group -Zgzip --build "$STAGE" "$OUT_DIR/$PKG"
else
    dpkg-deb -Zgzip --build "$STAGE" "$OUT_DIR/$PKG"
fi
echo "built: $OUT_DIR/$PKG"

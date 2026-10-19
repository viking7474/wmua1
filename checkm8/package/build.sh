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
mkdir -p "$OUT_DIR"

# Rootless (Procursus, iphoneos-arm64): ElleKit injects from
# /var/jb/usr/lib/TweakInject; an empty Filter means "all processes".
ROOTLESS_STAGE="$(mktemp -d)"
# Rootful (checkra1n 12-14, iphoneos-arm): the loader must NOT live under
# /var/jb -- anti-JB SDKs (MB Bank) abort on that path alone (verified on
# 13.5.1) -- so the payload goes to /usr/lib/myjb_loader.dylib (the same path
# Amethyst base_hook dlopens) and postinst mirrors it into substrate/libhooker
# dirs only when that engine is actually installed.
ROOTFUL_STAGE="$(mktemp -d)"
trap 'rm -rf "$ROOTLESS_STAGE" "$ROOTFUL_STAGE"' EXIT

for STAGE in "$ROOTLESS_STAGE" "$ROOTFUL_STAGE"; do
    mkdir -p "$STAGE/DEBIAN"
    cp "$ROOT/DEBIAN/postinst" "$STAGE/DEBIAN/postinst"
    chmod 755 "$STAGE/DEBIAN/postinst"
    cp "$ROOT/DEBIAN/prerm" "$STAGE/DEBIAN/prerm"
    chmod 755 "$STAGE/DEBIAN/prerm"
done

mkdir -p "$ROOTLESS_STAGE/var/jb/usr/lib/TweakInject"
cp "$ROOT/var/jb/usr/lib/TweakInject/myjb_loader.plist" "$ROOTLESS_STAGE/var/jb/usr/lib/TweakInject/myjb_loader.plist"
chmod 644 "$ROOTLESS_STAGE/var/jb/usr/lib/TweakInject/myjb_loader.plist"
cp "$DYLIB" "$ROOTLESS_STAGE/var/jb/usr/lib/TweakInject/myjb_loader.dylib"
chmod 755 "$ROOTLESS_STAGE/var/jb/usr/lib/TweakInject/myjb_loader.dylib"

mkdir -p "$ROOTFUL_STAGE/usr/lib"
cp "$DYLIB" "$ROOTFUL_STAGE/usr/lib/myjb_loader.dylib"
chmod 755 "$ROOTFUL_STAGE/usr/lib/myjb_loader.dylib"

build_one() {
    STAGE="$1"
    ARCH="$2"
    sed -e "s/^Version: .*/Version: $VERSION/" -e "s/^Architecture: .*/Architecture: $ARCH/" "$ROOT/DEBIAN/control" > "$STAGE/DEBIAN/control"
    chmod 644 "$STAGE/DEBIAN/control"
    PKG="com.wmua1.myjb.checkm8_${VERSION}_${ARCH}.deb"
    if dpkg-deb --help 2>&1 | grep -q root-owner-group; then
        dpkg-deb --root-owner-group -Zgzip --build "$STAGE" "$OUT_DIR/$PKG"
    else
        dpkg-deb -Zgzip --build "$STAGE" "$OUT_DIR/$PKG"
    fi
    echo "built: $OUT_DIR/$PKG"
}

build_one "$ROOTLESS_STAGE" iphoneos-arm64
build_one "$ROOTFUL_STAGE" iphoneos-arm

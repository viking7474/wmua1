#!/bin/sh
# Deploy myJB substrate-free injector (Amethyst basebins) to a checkra1n rootful device.
# Run from WSL / macOS / Linux:
#   sh deploy_injector.sh [ssh_target] [ssh_port] [basebins_tar]
# Defaults: root@localhost 44 /mnt/e/winrain/amethyst/basebins/basebins.tar
#
# Requirements:
#   - basebins.tar built on macOS (make stage) or downloaded from CI artifact
#   - device reachable: dropbear/iproxy on localhost:44 (iproxy 44 44 for checkra1n usbmux)
#   - root login (checkra1n rootful: root/alpine by default)
#
# After deploy: /amethyst/jbutil -k injects launchd_hook into launchd (pid 1);
# launchd_hook hooks dyld spawn env -> every new process loads /usr/lib/base_hook.dylib
# -> base_hook dlopens /usr/lib/myjb_loader.dylib (spoof layer).
# On checkra1n there is no handoff.plist (no hsp4) -> kernel features degrade gracefully.

set -e

TARGET="${1:-root@localhost}"
PORT="${2:-44}"
TAR="${3:-/mnt/e/winrain/amethyst/basebins/basebins.tar}"
DEBUG_MARK="${MYJB_DEBUG:-0}"

[ -f "$TAR" ] || {
    echo "[-] missing $TAR"
    echo "    build on macOS: cd amethyst/basebins && make all stage"
    echo "    or grab basebins.tar from the CI artifact"
    exit 1
}

SSH="ssh -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SCP="scp -P $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "[*] copying basebins.tar -> $TARGET:/var/mobile/"
$SCP "$TAR" "$TARGET:/var/mobile/basebins.tar"

echo "[*] installing basebins on device..."
$SSH "$TARGET" 'sh -s' <<'DEVICE'
set -e
cd /
tar --numeric-owner -x -f /var/mobile/basebins.tar
rm -f /var/mobile/basebins.tar

chmod 0755 /amethyst/jbutil /amethyst/launchd_hook.dylib
chmod 0755 /usr/lib/base_hook.dylib /usr/lib/libjailbreak.dylib /usr/lib/myjb_loader.dylib
chown 0:0 /amethyst/jbutil /amethyst/launchd_hook.dylib
chown 0:0 /usr/lib/base_hook.dylib /usr/lib/libjailbreak.dylib /usr/lib/myjb_loader.dylib
sync

ls -l /amethyst/ /usr/lib/base_hook.dylib /usr/lib/myjb_loader.dylib
DEVICE

if [ "$DEBUG_MARK" = "1" ]; then
    echo "[*] enabling loader debug marker..."
    $SSH "$TARGET" 'mkdir -p /var/mobile/Library/MyJB && touch /var/mobile/Library/MyJB/.myjb_debug'
fi

echo "[*] kickstart: injecting launchd_hook into launchd (pid 1)..."
$SSH "$TARGET" '/amethyst/jbutil -k || /amethyst/jbutil -i 1 /amethyst/launchd_hook.dylib'

echo "[*] respring to refresh running processes..."
$SSH "$TARGET" 'killall -9 SpringBoard || killall SpringBoard || true'

echo "[+] done."
echo "    verify:"
echo "      ssh -p $PORT $TARGET 'ls -l /usr/lib/myjb_loader.dylib'"
echo "      ps -A | grep -i springboard   (must respawn shortly after respring)"
echo "      log (if MYJB_DEBUG=1): ssh ... 'cat /var/mobile/Library/MyJB/loader.log'"
echo "    rollback:"
echo "      ssh -p $PORT $TARGET 'rm -f /usr/lib/base_hook.dylib /usr/lib/myjb_loader.dylib /usr/lib/libjailbreak.dylib /amethyst/launchd_hook.dylib /amethyst/jbutil'"
echo "      then reboot (launchd reverts to stock)"

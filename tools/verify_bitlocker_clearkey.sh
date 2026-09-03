#!/usr/bin/env bash
# Round-trip test for the BitLocker clear-key ("suspended volume") unlock.
#
# Suspending BitLocker leaves the volume encrypted but writes a clear-key
# protector: the key that unwraps the VMK sits in the metadata in the open, so
# the disk opens with no password or recovery key. Drives reach a recovery
# bench in that state often enough - service interrupted mid-update - that it
# is always worth trying before asking a customer for a key.
#
# Builds a real NTFS volume, encrypts it AES-XTS-128 behind a clear-key
# protector (tools/mkbitlocker.py, written from the format spec rather than
# from the reader, so the two are independent), and checks de-cli opens it with
# no credential and reads the files back byte for byte.
#
# Needs sudo for mount/umount. Usage: tools/verify_bitlocker_clearkey.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
PLAIN="$WORK/plain.img"
ENC="$WORK/bde.img"
MNT="$WORK/mnt"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }
command -v mkfs.ntfs >/dev/null || { echo "need ntfs-3g (mkfs.ntfs)"; exit 1; }
python3 -c 'import cryptography' 2>/dev/null || { echo "need python3-cryptography"; exit 1; }

echo "== building a 64 MB NTFS volume =="
truncate -s 64M "$PLAIN"
mkfs.ntfs -F -f -L Suspended "$PLAIN" >/dev/null 2>&1
mkdir -p "$MNT"
sudo mount -o loop,uid=$(id -u),gid=$(id -g) "$PLAIN" "$MNT"
mkdir -p "$MNT/Documents"
head -c 200000 /dev/urandom > "$MNT/Documents/artwork.psd"
echo "readable without any credential" > "$MNT/Documents/note.txt"
sudo umount "$MNT"
# Keep a reference copy of the file contents to compare against.
sudo mount -o loop,ro "$PLAIN" "$MNT"
cp "$MNT/Documents/artwork.psd" "$WORK/ref.psd"
sudo umount "$MNT"

echo "== encrypting it behind a clear-key protector =="
python3 "$ROOT/tools/mkbitlocker.py" "$PLAIN" "$ENC"

echo "== the volume must really be encrypted =="
if cmp -s <(dd if="$PLAIN" bs=1M skip=1 count=4 2>/dev/null) \
          <(dd if="$ENC"   bs=1M skip=1 count=4 2>/dev/null); then
    echo "FAIL: ciphertext matches plaintext - nothing was encrypted"; exit 1
fi
grep -q "readable without any credential" "$ENC" && {
    echo "FAIL: plaintext file content still visible in the image"; exit 1; }
echo "   ok - body is ciphertext"

echo "== de-cli must report it as suspended =="
INFO="$("$CLI" "$ENC" bde 1)"
echo "$INFO" | sed 's/^/   | /'
echo "$INFO" | grep -q "clear key (0x0000)" || { echo "FAIL: clear key not listed"; exit 1; }
echo "$INFO" | grep -q "SUSPENDED"          || { echo "FAIL: not reported as suspended"; exit 1; }

echo "== and open it with NO credential =="
"$CLI" "$ENC" ls 1 | grep -q Documents || { echo "FAIL: cannot list root"; exit 1; }
REC="$("$CLI" "$ENC" find 1 artwork.psd | grep -oE '[0-9]+' | head -1)"
"$CLI" "$ENC" export-list 1 <(echo -e "$REC\tartwork.psd") "$WORK/out" >/dev/null 2>&1 || true
if [ -f "$WORK/out/artwork.psd" ]; then
    cmp "$WORK/out/artwork.psd" "$WORK/ref.psd" || { echo "FAIL: file content differs"; exit 1; }
    echo "   ok - 200000-byte file recovered byte for byte"
else
    # export-list needs the MFT record number; fall back to the path-based export.
    "$CLI" "$ENC" export 1 5 "$WORK/out2" >/dev/null 2>&1
    cmp "$WORK/out2/Documents/artwork.psd" "$WORK/ref.psd" || {
        echo "FAIL: file content differs"; exit 1; }
    echo "   ok - 200000-byte file recovered byte for byte"
fi

echo
echo "PASS: a suspended BitLocker volume opened with no credential."

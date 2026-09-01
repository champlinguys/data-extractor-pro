#!/usr/bin/env bash
# Regression test for lost-partition recovery.
#
# Deleting a partition does not touch the volume it pointed at, so a scanner
# that trusts the partition table reports "free space" over a perfectly intact
# filesystem. This builds a GPT disk laid out like the Windows laptop that
# motivated the feature (case brian: a small EFI partition, a large NTFS C:, a
# recovery partition at the tail), erases the middle GPT entry, and checks
# de-cli still finds the volume - at the right offset, with the right length,
# and mountable well enough to list its root.
#
# It then re-runs with --no-scan to confirm the volume really was invisible
# from the table alone, so a pass cannot be an artefact of the table surviving.
#
# Needs sudo for mount/umount. Usage: tools/verify_lost_partition.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
IMG="$WORK/lost.img"
MNT="$WORK/mnt"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }
command -v sgdisk     >/dev/null || { echo "need gdisk (sgdisk)"; exit 1; }
command -v mkfs.ntfs  >/dev/null || { echo "need ntfs-3g (mkfs.ntfs)"; exit 1; }

echo "== building a 640 MB GPT disk: EFI + NTFS data + recovery =="
truncate -s 640M "$IMG"
sgdisk -o \
       -n 1:2048:+64M   -t 1:ef00 -c 1:"EFI"      \
       -n 2:264192:+448M -t 2:0700 -c 2:"Data"     \
       -n 3:0:0         -t 3:0700 -c 3:"Recovery" "$IMG" >/dev/null

# Offsets of partition 2, so the test asserts against the real geometry rather
# than numbers hard-coded here.
P2_START=$(( 264192 * 512 ))
P2_LEN=$(( 448 * 1024 * 1024 ))

# mkfs.ntfs cannot format at an offset inside a larger file, so the volume is
# built standalone and then placed at the partition's byte offset.
FSIMG="$WORK/ntfs.img"
truncate -s "$P2_LEN" "$FSIMG"
mkfs.ntfs -F -f -L LostVol "$FSIMG" >/dev/null 2>&1
mkdir -p "$MNT"
sudo mount -o loop,uid=$(id -u),gid=$(id -g) "$FSIMG" "$MNT"
echo "the file that has to survive losing the partition table" > "$MNT/canary.txt"
mkdir -p "$MNT/Documents"
head -c 4096 /dev/urandom > "$MNT/Documents/artwork.psd"
sudo umount "$MNT"
dd if="$FSIMG" of="$IMG" bs=1M seek=$(( P2_START / 1048576 )) conv=notrunc status=none

echo "== erasing the GPT entry for partition 2 (primary + backup) =="
sgdisk --delete=2 "$IMG" >/dev/null
# sgdisk rewrites both copies; confirm the table really no longer lists it.
if sgdisk -p "$IMG" | awk '$1=="2"{found=1} END{exit !found}'; then
    echo "FAIL: partition 2 still present in the table"; exit 1
fi

echo "== --no-scan must NOT see it (the table is genuinely gone) =="
if "$CLI" "$IMG" --no-scan | grep -q "@ $P2_START,"; then
    echo "FAIL: table-only scan still reported the deleted partition"; exit 1
fi
echo "   ok - invisible from the table alone"

echo "== default scan must find it =="
OUT="$("$CLI" "$IMG")"
echo "$OUT"
LINE="$(echo "$OUT" | grep "^  \[.*found .*@ $P2_START," || true)"
[ -n "$LINE" ] || { echo "FAIL: lost volume not found at byte $P2_START"; exit 1; }

echo "$LINE" | grep -q "fs=NTFS" || { echo "FAIL: found, but not identified as NTFS"; exit 1; }

# The reported length must come from the volume's own boot record, not from the
# size of the hole it happens to sit in.
WANT_MIB="$(awk -v b="$P2_LEN" 'BEGIN{printf "%.2f", b/1048576}')"
echo "$LINE" | grep -q "$WANT_MIB MiB" || {
    echo "FAIL: wrong length, wanted $WANT_MIB MiB"; exit 1; }
echo "   ok - offset and self-declared length both correct"

echo "== and it must be browsable =="
PART="$(echo "$LINE" | sed 's/^ *\[\([0-9]*\)\].*/\1/')"
"$CLI" "$IMG" ls "$PART" | grep -q canary.txt || {
    echo "FAIL: cannot list the root of the recovered volume"; exit 1; }
"$CLI" "$IMG" find "$PART" artwork.psd | grep -qi 'Documents' || {
    echo "FAIL: cannot find Documents/artwork.psd"; exit 1; }
echo "   ok - root listed and Documents/artwork.psd located"

echo
echo "PASS: a partition erased from the GPT was found, sized and read back."

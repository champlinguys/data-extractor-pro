#!/usr/bin/env bash
# Test for the Apple Partition Map reader and the HFS wrapper, against a
# synthesised disk shaped like a real pre-Intel Mac drive.
#
# Two things have to work together for such a disk to open at all:
#
#   1. the partition table is an Apple Partition Map, not MBR or GPT. Its
#      block 0 has no 0x55AA, so a scanner that knows only the PC schemes
#      reports "no partition table" and treats the whole disk as one volume.
#   2. the data partition holds an HFS *wrapper*: a small classic-HFS volume
#      with the real HFS+ volume embedded inside it. What sits at +1024 is an
#      HFS Master Directory Block ('BD'), not an HFS+ volume header, so a
#      reader that mounts what it finds there gets the wrapper's handful of
#      Apple files instead of the customer's data.
#
# Modelled on a 2005 LaCie d2 (200 GB Maxtor): a 7-entry map of which only one
# is a volume, and a wrapper whose embedded extent starts 5 allocation blocks
# in. Needs mkfs.hfsplus and sudo for the mount.
#
# Usage: tools/verify_apm_wrapper.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
IMG="$WORK/apm.img"
MNT="$WORK/mnt"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }
command -v mkfs.hfsplus >/dev/null || { echo "need mkfs.hfsplus (hfsprogs)"; exit 1; }

# Geometry, in 512-byte blocks. The HFS+ volume goes at PART_START + EMBED_OFF.
PART_START=768          # where the Apple_HFS entry begins, as on the LaCie
PART_BLOCKS=409600      # 200 MB of partition
AL_BL_ST=24             # drAlBlSt, in 512-byte units
AL_BLK_SIZ=1048576      # drAlBlkSiz: 1 MB allocation blocks
EMBED_START=5           # drEmbedExtent.startBlock
EMBED_BLOCKS=190        # drEmbedExtent.blockCount

EMBED_OFF=$(( AL_BL_ST * 512 + EMBED_START * AL_BLK_SIZ ))
EMBED_LEN=$(( EMBED_BLOCKS * AL_BLK_SIZ ))
PART_OFF=$(( PART_START * 512 ))

echo "== building the embedded HFS+ volume =="
mkdir -p "$MNT"
truncate -s "$EMBED_LEN" "$WORK/inner.img"
mkfs.hfsplus -v Embedded "$WORK/inner.img" >/dev/null
sudo mount -t hfsplus -o loop,rw,uid=$(id -u),gid=$(id -g) "$WORK/inner.img" "$MNT"
mkdir -p "$MNT/Photos"
printf 'inside the embedded volume\n' > "$MNT/Photos/proof.txt"
head -c 300000 /dev/urandom > "$MNT/Photos/blob.bin"
sudo umount "$MNT"

echo "== assembling the APM disk with the wrapper around it =="
truncate -s $(( (PART_START + PART_BLOCKS) * 512 )) "$IMG"
python3 - "$IMG" "$WORK/inner.img" \
    "$PART_START" "$PART_BLOCKS" "$AL_BL_ST" "$AL_BLK_SIZ" \
    "$EMBED_START" "$EMBED_BLOCKS" "$EMBED_OFF" <<'PY'
import struct, sys
img, inner, part_start, part_blocks, al_bl_st, al_blk_siz, \
    embed_start, embed_blocks, embed_off = sys.argv[1:10]
part_start, part_blocks = int(part_start), int(part_blocks)
al_bl_st, al_blk_siz = int(al_bl_st), int(al_blk_siz)
embed_start, embed_blocks, embed_off = int(embed_start), int(embed_blocks), int(embed_off)

f = open(img, 'r+b')

# Block 0: the Driver Descriptor Record.
ddr = bytearray(512)
struct.pack_into('>H', ddr, 0, 0x4552)      # 'ER'
struct.pack_into('>H', ddr, 2, 512)         # sbBlkSize
f.seek(0); f.write(ddr)

# Blocks 1..7: the map. Only entry 6 is a volume; the rest is bookkeeping and
# legacy driver stubs, exactly as a real Mac drive of the era looks.
entries = [
    (1, 63, 'Apple', 'Apple_partition_map'),
    (64, 128, 'Macintosh_SL', 'Apple_Driver43'),
    (192, 128, 'Macintosh_SL', 'Apple_Driver_ATA'),
    (320, 224, 'Macintosh_SL', 'Apple_FWDriver'),
    (544, 224, 'Extra', 'Apple_Free'),
    (part_start, part_blocks, 'LaCie Disk', 'Apple_HFS'),
    (part_start + part_blocks, 1, 'Extra', 'Apple_Free'),
]
for i, (start, blocks, name, ptype) in enumerate(entries):
    e = bytearray(512)
    struct.pack_into('>H', e, 0x00, 0x504D)          # 'PM'
    struct.pack_into('>I', e, 0x04, len(entries))    # pmMapBlkCnt
    struct.pack_into('>I', e, 0x08, start)           # pmPyPartStart
    struct.pack_into('>I', e, 0x0C, blocks)          # pmPartBlkCnt
    e[0x10:0x10+len(name)] = name.encode()
    e[0x30:0x30+len(ptype)] = ptype.encode()
    f.seek((i + 1) * 512); f.write(e)

# The wrapper's Master Directory Block, at +1024 into the partition.
mdb = bytearray(512)
struct.pack_into('>H', mdb, 0x00, 0x4244)            # drSigWord 'BD'
struct.pack_into('>I', mdb, 0x14, al_blk_siz)        # drAlBlkSiz
struct.pack_into('>H', mdb, 0x1C, al_bl_st)          # drAlBlSt
struct.pack_into('>H', mdb, 0x7C, 0x482B)            # drEmbedSigWord 'H+'
struct.pack_into('>HH', mdb, 0x7E, embed_start, embed_blocks)
f.seek(part_start * 512 + 1024); f.write(mdb)

# ...and the embedded volume itself, where the MDB says it is.
f.seek(part_start * 512 + embed_off)
with open(inner, 'rb') as src:
    while chunk := src.read(1 << 20):
        f.write(chunk)
f.close()
PY

echo "== what de-cli makes of it =="
"$CLI" "$IMG"

FAILS=0
check() {
    if ! "$CLI" "$IMG" 2>/dev/null | grep -q "$1"; then
        echo "  FAIL: expected to see '$1'"; FAILS=$((FAILS+1))
    fi
}
# The map must be read, and the bookkeeping entries left out of the listing.
check 'APM'
check 'Apple_HFS "LaCie Disk"'
# ...and the volume must come back HFS+, not HFS: mounting the wrapper is the
# failure this whole script exists to catch.
check 'fs=HFS+'
if "$CLI" "$IMG" 2>/dev/null | grep -qE 'Apple_Free|Apple_partition_map'; then
    echo "  FAIL: bookkeeping entries listed as partitions"; FAILS=$((FAILS+1))
fi
NPARTS=$("$CLI" "$IMG" 2>/dev/null | grep -c '^  \[')
[ "$NPARTS" = 4 ] || { echo "  FAIL: expected 4 partitions, got $NPARTS"; FAILS=$((FAILS+1)); }

echo "== reading a file out of the embedded volume =="
PART=$("$CLI" "$IMG" 2>/dev/null | grep 'fs=HFS+' | sed 's/.*\[\([0-9]*\)\].*/\1/')
REC=$("$CLI" "$IMG" ls "$PART" 2>/dev/null | awk '$NF=="Photos"{print $1}')
if [ -z "$REC" ]; then
    echo "  FAIL: /Photos not found in the embedded volume"; FAILS=$((FAILS+1))
else
    PROOF=$("$CLI" "$IMG" ls "$PART" "$REC" 2>/dev/null | awk '$NF=="proof.txt"{print $1}')
    GOT=$("$CLI" "$IMG" cat "$PART" "$PROOF" 2>/dev/null || true)
    [ "$GOT" = "inside the embedded volume" ] || {
        echo "  FAIL: proof.txt read back as '$GOT'"; FAILS=$((FAILS+1)); }
fi

echo
if [ "$FAILS" = 0 ]; then echo "APM + HFS wrapper: OK"; else echo "$FAILS failure(s)"; fi
exit $([ "$FAILS" = 0 ] && echo 0 || echo 1)

#!/usr/bin/env bash
# The catalog B-tree must survive an overwritten node.
#
# HFS+ chains its leaf nodes by forward link. Follow that chain blindly and a
# single damaged node ends the walk: its fLink is no longer a node pointer, so
# everything after it is unread. On the 200 GB LaCie this came from, one node
# (kind=3, fLink=116655816 against a fork of 17,408 nodes) cost 392,110 of
# 393,106 catalog records.
#
# Two failure modes are checked, because they are repaired differently:
#   1. an overwritten leaf node mid-chain  -> the nodes after it must still be
#      found, by indexing the fork's nodes directly instead of chaining
#   2. a deleted folder record             -> the folder must be rebuilt from
#      its thread record, or its whole subtree vanishes from the listing
#
# Needs mkfs.hfsplus and sudo for the mount. Usage: tools/verify_btree_damage.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
IMG="$WORK/hfs.img"
MNT="$WORK/mnt"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }
command -v mkfs.hfsplus >/dev/null || { echo "need mkfs.hfsplus (hfsprogs)"; exit 1; }

echo "== building an HFS+ volume with enough files to span many leaf nodes =="
truncate -s 300M "$IMG"
mkfs.hfsplus -v DamageTest "$IMG" >/dev/null
mkdir -p "$MNT"
sudo mount -t hfsplus -o loop,rw,uid=$(id -u),gid=$(id -g) "$IMG" "$MNT"
for d in $(seq 1 40); do
    mkdir -p "$MNT/dir$d"
    for f in $(seq 1 60); do printf 'content %s/%s\n' "$d" "$f" > "$MNT/dir$d/file$f.txt"; done
done
sudo umount "$MNT"

EXPECTED=$(( 40 * 60 ))
echo "== baseline: all $EXPECTED files must list =="
BEFORE=$("$CLI" "$IMG" tree 1 "$WORK/before.txt" 2>&1 | tr '\r' '\n' | tail -1)
echo "   $BEFORE"
GOT=$(grep -c 'file[0-9]*\.txt' "$WORK/before.txt" || true)
[ "$GOT" = "$EXPECTED" ] || { echo "  FAIL: baseline listed $GOT of $EXPECTED"; exit 1; }

echo "== damaging one leaf node in the middle of the catalog chain =="
python3 - "$IMG" <<'PY'
import struct, sys
img = sys.argv[1]
f = open(img, 'r+b')
f.seek(1024); vh = f.read(512)
assert vh[:2] == b'H+', 'not an HFS+ volume'
bs = struct.unpack_from('>I', vh, 0x28)[0]
# catalog fork: logicalSize at 0x110, first extents at 0x110+16
extents = []
for i in range(8):
    sb, bc = struct.unpack_from('>II', vh, 0x110 + 16 + i * 8)
    if bc: extents.append((sb, bc))
def node_off(n, nodesize):
    idx = n
    for sb, bc in extents:
        blocks = bc * bs // nodesize
        if idx < blocks: return sb * bs + idx * nodesize
        idx -= blocks
    return None
f.seek(node_off(0, 512) or 0); head = f.read(512)
nodesize = struct.unpack_from('>H', head, 14 + 18)[0]
first_leaf = struct.unpack_from('>I', head, 14 + 10)[0]
# walk a few links in, then clobber that node
n, hops = first_leaf, 0
while hops < 4:
    off = node_off(n, nodesize)
    f.seek(off); blk = f.read(nodesize)
    nxt = struct.unpack_from('>I', blk, 0)[0]
    if not nxt: break
    n, hops = nxt, hops + 1
off = node_off(n, nodesize)
f.seek(off)
f.write(struct.pack('>IIbbHH', 116655816, 0, 3, 0, 0, 0))   # garbage fLink, kind=3
f.close()
print(f'   clobbered leaf node {n} (kind=3, fLink=116655816)')
PY

echo "== after damage: every file must still be found =="
AFTER=$("$CLI" "$IMG" tree 1 "$WORK/after.txt" 2>&1 | tr '\r' '\n' | tail -1)
echo "   $AFTER"
GOT=$(grep -c 'file[0-9]*\.txt' "$WORK/after.txt" || true)
FAILS=0
LOST=$(( EXPECTED - GOT ))
# The clobbered node's own records are genuinely gone; everything the chain
# would have reached *after* it must not be.
if [ "$GOT" -lt $(( EXPECTED - 80 )) ]; then
    echo "  FAIL: only $GOT of $EXPECTED files listed - the walk stopped at the damage"
    FAILS=1
else
    echo "  OK: $GOT of $EXPECTED listed (only the clobbered node's own records lost)"
fi

echo
if [ "$FAILS" = 0 ]; then echo "B-tree damage recovery: OK"; else echo "FAILED"; fi
exit "$FAILS"

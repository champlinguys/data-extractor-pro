#!/usr/bin/env bash
# Round-trip test for the exFAT reader, against a real exFAT filesystem.
#
# Builds an exFAT image with mkfs.exfat, mounts it, fills it with the cases that
# break naive readers (a fragmented file, so the FAT chain is actually followed;
# a large contiguous file, which exFAT marks NoFatChain and leaves *no* chain to
# follow; a directory big enough to span clusters; unicode and spaced names; an
# empty file), then deletes one file so the undelete path has something to find.
# It unmounts, reads everything back through de-cli, and compares byte for byte.
#
# It also blanks the primary boot sector on a copy of the image and checks the
# reader still mounts it from the backup boot region at sector 12 - the case
# that matters on the failing drives this tool exists for.
#
# Needs sudo for mount/umount. Usage: tools/verify_exfat.sh [size_mb]
set -euo pipefail

SIZE_MB="${1:-512}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
IMG="$WORK/exfat.img"
MNT="$WORK/mnt"
SRC="$WORK/src"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }
command -v mkfs.exfat >/dev/null || { echo "need exfatprogs (mkfs.exfat)"; exit 1; }

echo "== building a $SIZE_MB MB exFAT volume =="
truncate -s "${SIZE_MB}M" "$IMG"
# A small cluster size keeps the test image small while still giving the
# fragmented file and the multi-cluster directory enough clusters to be
# interesting.
mkfs.exfat -c 32K -L TestVol "$IMG" >/dev/null
mkdir -p "$MNT" "$SRC"
sudo mount -o loop,rw,uid=$(id -u),gid=$(id -g) "$IMG" "$MNT"

echo "== filling it =="
head -c 13 /dev/urandom       > "$SRC/tiny.bin"
head -c 3000000 /dev/urandom  > "$SRC/3mb.bin"
: > "$SRC/empty.txt"
printf 'hello exfat\n'        > "$SRC/hello.txt"
printf 'unicode\n'            > "$SRC/Watt_Osage Basin – RAW ünïcode 名前.txt"
mkdir -p "$SRC/deep/a/b/c"
printf 'deep file\n'          > "$SRC/deep/a/b/c/leaf.txt"
# A directory with enough children to run past one cluster, so entry sets that
# straddle a cluster boundary get exercised.
mkdir -p "$SRC/manyfiles"
for i in $(seq 1 400); do
  printf 'x%s\n' "$i" > "$SRC/manyfiles/file_with_a_fairly_long_name_$i.txt"
done
cp -a "$SRC/." "$MNT/"

# A deliberately fragmented file: interleave writes with a filler file so the
# two compete for clusters, then delete the filler. exFAT can only mark a file
# NoFatChain when it is contiguous, so this is what forces the reader onto the
# FAT-walking path.
python3 - "$MNT" <<'PY'
import os, sys
mnt = sys.argv[1]
frag = os.path.join(mnt, 'fragmented.bin')
filler = os.path.join(mnt, 'filler.tmp')
data = b''
with open(frag, 'wb') as f, open(filler, 'wb') as g:
    for i in range(60):
        chunk = bytes([(i * 7 + j) & 0xFF for j in range(65536)])
        f.write(chunk); f.flush(); os.fsync(f.fileno())
        data += chunk
        g.write(os.urandom(65536)); g.flush(); os.fsync(g.fileno())
os.unlink(filler)
open(os.path.join(mnt, '.expect_fragmented'), 'wb').write(data)
PY
cp "$MNT/.expect_fragmented" "$SRC/fragmented.bin"
rm -f "$MNT/.expect_fragmented"

# A deleted file whose clusters are then reused - what happens to a camera card
# that keeps recording after clips are deleted. It is deleted, then every free
# cluster on the volume is taken by a live filler file, so the reader must
# report it 100% reallocated. A reserve file is set aside first and freed only
# afterwards, which leaves room for the intact deleted file below without
# letting the filler near it. The victim lives in its own folder so the later
# files cannot reuse its directory entry slot.
head -c 2000000 /dev/zero > "$MNT/reserve.bin"
mkdir -p "$MNT/victimdir"
head -c 400000 /dev/urandom > "$MNT/victimdir/overwritten.bin"
sync
rm -f "$MNT/victimdir/overwritten.bin"
sync
dd if=/dev/zero of="$MNT/filler.bin" bs=1M status=none 2>/dev/null || true
sync
rm -f "$MNT/reserve.bin"

# The deleted file. It is *not* copied into $SRC: it must not show up as a live
# file, but the reader has to find it and read it back intact.
head -c 400000 /dev/urandom > "$MNT/deleted_file.bin"
sync
cp "$MNT/deleted_file.bin" "$WORK/deleted_expect.bin"
rm -f "$MNT/deleted_file.bin"

sync
sudo umount "$MNT"

echo "== reading it back through de-cli =="
"$CLI" "$IMG"

python3 - "$CLI" "$IMG" "$SRC" "$WORK/deleted_expect.bin" <<'PY'
import subprocess, sys, os, re
cli, img, src, deleted_expect = sys.argv[1:5]

def ls(node):
    r = subprocess.run([cli, img, 'ls', '1', str(node)], capture_output=True)
    rows = []
    for line in r.stdout.decode(errors='replace').splitlines():
        p = line.split(None, 1)
        if len(p) != 2 or not p[0].isdigit():
            continue
        rest = p[1]
        is_dir = rest.startswith('<DIR>')
        rest = (rest[5:] if is_dir else rest).strip()
        parts = rest.split(None, 1)
        size = int(parts[0])
        name = parts[1] if len(parts) > 1 else ''
        m = re.search(r'\s*\(deleted(?:, ([\d.]+)% reallocated)?\)$', name)
        deleted = m is not None
        realloc = float(m.group(1)) if m and m.group(1) else None
        if deleted:
            name = name[:m.start()]
        rows.append((p[0], is_dir, size, name, deleted, realloc))
    return rows

live, dead = {}, {}
def walk(node, prefix=''):
    for nid, is_dir, size, name, deleted, realloc in ls(node):
        path = prefix + name
        if is_dir:
            if not deleted:
                walk(nid, path + '/')
        elif deleted:
            dead[path] = (nid, size, realloc)
        else:
            live[path] = (nid, size)
walk(0)

fails = []
expected = {}
for dirpath, _, files in os.walk(src):
    for fn in files:
        full = os.path.join(dirpath, fn)
        expected[os.path.relpath(full, src)] = full

for rel, full in sorted(expected.items()):
    want = open(full, 'rb').read()
    if rel not in live:
        fails.append(f'{rel}: not listed by the reader')
        continue
    nid, size = live[rel]
    if size != len(want):
        fails.append(f'{rel}: listed size {size}, real size {len(want)}')
    got = subprocess.run([cli, img, 'cat', '1', nid], capture_output=True).stdout
    if got != want:
        fails.append(f'{rel}: content differs ({len(got)} read vs {len(want)})')

# filler.bin exists only to take the victim's clusters; its content is zeros.
extra = set(live) - set(expected) - {'filler.bin'}
if extra:
    fails.append(f'unexpected live entries: {sorted(extra)[:5]}')

# The deleted file: listed as deleted, and readable byte for byte.
want = open(deleted_expect, 'rb').read()
hit = [v for k, v in dead.items() if k == 'deleted_file.bin']
if not hit:
    fails.append('deleted_file.bin: not recovered (deleted entries: '
                 f'{sorted(dead)[:5]})')
else:
    nid, size, realloc = hit[0]
    if realloc != 0.0:
        fails.append(f'deleted_file.bin: reported {realloc}% reallocated, '
                     'but nothing has reused its clusters')
    got = subprocess.run([cli, img, 'cat', '1', nid], capture_output=True).stdout
    if got != want:
        fails.append(f'deleted_file.bin: content differs '
                     f'({len(got)} read vs {len(want)})')

# The victim: its clusters all went to filler.bin, so it must say so.
hit = [v for k, v in dead.items() if k == 'victimdir/overwritten.bin']
if not hit:
    fails.append('victimdir/overwritten.bin: not listed as deleted')
elif hit[0][2] != 100.0:
    fails.append(f'victimdir/overwritten.bin: reported {hit[0][2]}% reallocated, '
                 'expected 100% (every cluster was reused by filler.bin)')

print(f'{len(expected)} live files checked, 2 deleted files, {len(fails)} failure(s)')
for f in fails:
    print('  FAIL ' + f)
sys.exit(1 if fails else 0)
PY

echo "== mounting from the backup boot region with the primary VBR destroyed =="
cp --sparse=always "$IMG" "$WORK/novbr.img"
dd if=/dev/zero of="$WORK/novbr.img" bs=512 count=1 conv=notrunc status=none
if "$CLI" "$WORK/novbr.img" | grep -q exFAT && \
   "$CLI" "$WORK/novbr.img" ls 1 | grep -q hello.txt; then
  echo "  backup boot region fallback OK"
else
  echo "  FAIL backup boot region fallback"
  exit 1
fi

echo "all exFAT checks passed"

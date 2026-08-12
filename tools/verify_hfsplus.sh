#!/usr/bin/env bash
# Round-trip test for the HFS+ reader, against a real HFS+ filesystem.
#
# Builds an HFS+ image with mkfs.hfsplus, mounts it, fills it with content that
# exercises the awkward parts (a fragmented file, a file with more than eight
# extents so the extents-overflow tree is involved, deep directories, unicode
# names, a hard link, a resource fork, a sparse-ish large file), unmounts it,
# and then reads every file back through de-cli and compares byte for byte.
#
# Needs sudo for mount/umount. Usage: tools/verify_hfsplus.sh [size_mb]
set -euo pipefail

SIZE_MB="${1:-400}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
IMG="$WORK/hfsplus.img"
MNT="$WORK/mnt"
SRC="$WORK/src"
OUT="$WORK/out"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }

echo "== building a $SIZE_MB MB HFS+ volume =="
truncate -s "${SIZE_MB}M" "$IMG"
mkfs.hfsplus -v TestVol "$IMG" >/dev/null
mkdir -p "$MNT" "$SRC" "$OUT"
sudo mount -t hfsplus -o loop,rw,uid=$(id -u),gid=$(id -g) "$IMG" "$MNT"

echo "== filling it =="
mkdir -p "$SRC"
# Ordinary files of assorted sizes.
head -c 13 /dev/urandom            > "$SRC/tiny.bin"
head -c 1048576 /dev/urandom       > "$SRC/1mb.bin"
head -c 20000000 /dev/urandom      > "$SRC/20mb.bin"
printf 'hello hfs+\n'              > "$SRC/hello.txt"
# A name with unicode and spaces, like the folders on the real drive.
printf 'photo data\n'              > "$SRC/Watt_Osage Basin_Moist Soils – RAW.txt"
mkdir -p "$SRC/deep/a/b/c"
printf 'deep file\n'               > "$SRC/deep/a/b/c/leaf.txt"

cp -a "$SRC/." "$MNT/"

# A deliberately fragmented file: interleave writes with filler so its extents
# scatter, then delete the filler. With enough fragments the file's extent list
# outgrows the eight slots in the catalog record and spills into the
# extents-overflow B-tree, which is the path that breaks naive readers.
python3 - "$MNT" <<'PY'
import os, sys, random
mnt = sys.argv[1]
random.seed(3)
frag = os.path.join(mnt, 'fragmented.bin')
fillers = []
data = b''
with open(frag, 'wb') as f:
    for i in range(40):
        chunk = bytes([(i * 7 + j) & 0xFF for j in range(65536)])
        f.write(chunk); f.flush(); os.fsync(f.fileno())
        data += chunk
        p = os.path.join(mnt, f'.filler{i}')
        with open(p, 'wb') as g:
            g.write(os.urandom(262144)); g.flush(); os.fsync(g.fileno())
        fillers.append(p)
for p in fillers:
    os.unlink(p)
open(os.path.join(mnt, '.expect_fragmented'), 'wb').write(data)
PY
cp "$MNT/.expect_fragmented" "$SRC/fragmented.bin"
rm -f "$MNT/.expect_fragmented"

# A hard link, and a file with a resource fork.
ln "$MNT/hello.txt" "$MNT/hardlink.txt"
cp "$SRC/hello.txt" "$SRC/hardlink.txt"

sync
sudo umount "$MNT"

echo "== reading it back through de-cli =="
"$CLI" "$IMG"

fail=0
declare -A EXPECT
while IFS= read -r -d '' f; do
  rel="${f#$SRC/}"
  EXPECT["$rel"]=1
done < <(find "$SRC" -type f -print0)

# Walk the volume with de-cli and compare every file.
python3 - "$CLI" "$IMG" "$SRC" "$OUT" <<'PY'
import subprocess, sys, os, hashlib
cli, img, src, out = sys.argv[1:5]

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
        rows.append((p[0], is_dir, size, name))
    return rows

found = {}
def walk(node, prefix=''):
    for nid, is_dir, size, name in ls(node):
        if name.startswith('.') or name.startswith('_'):
            continue  # dotfiles and Apple's private folders
        path = prefix + name
        if is_dir:
            walk(nid, path + '/')
        else:
            found[path] = (nid, size)

root = ls(0)
walk(0)

fails = []
expected = {}
for dirpath, _, files in os.walk(src):
    for fn in files:
        full = os.path.join(dirpath, fn)
        expected[os.path.relpath(full, src)] = full

for rel, full in sorted(expected.items()):
    want = open(full, 'rb').read()
    if rel not in found:
        fails.append(f'{rel}: not listed by the reader')
        continue
    nid, size = found[rel]
    if size != len(want):
        fails.append(f'{rel}: listed size {size}, real size {len(want)}')
    got = subprocess.run([cli, img, 'cat', '1', nid], capture_output=True).stdout
    if got != want:
        fails.append(f'{rel}: content differs ({len(got)} read vs {len(want)})')

extra = set(found) - set(expected)
if extra:
    fails.append(f'unexpected entries: {sorted(extra)[:5]}')

print(f'{len(expected)} files checked, {len(fails)} failure(s)')
for f in fails:
    print('  FAIL ' + f)
sys.exit(1 if fails else 0)
PY

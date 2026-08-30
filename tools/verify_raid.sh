#!/usr/bin/env bash
# End-to-end test of the RAID reassembly, shaped like a real two-drive case.
#
# Builds a GPT disk with an HFS+ volume on it, fills the volume with files,
# then physically splits the disk into two "drives" - striped at a size the
# detector is not told - and checks that:
#   * `de-cli raid` works the geometry out on its own, and
#   * every file reads back byte for byte through the reassembled set.
#
# It repeats this for several stripe sizes and for a concatenated set, since
# guessing the geometry is the part that has to be right.
#
# Needs sudo for mount/umount. Usage: tools/verify_raid.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
MNT="$WORK/mnt"
SRC="$WORK/src"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT
[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }

VOL_MB=300
DISK_MB=320

echo "== building a GPT disk with an HFS+ volume =="
DISK="$WORK/disk.img"
truncate -s "${DISK_MB}M" "$DISK"
# Partition it the way a Mac would: a small EFI partition, then the data volume.
sgdisk -o -n 1:2048:+20M -t 1:EF00 -c 1:EFI \
          -n 2:0:0      -t 2:AF00 -c 2:"OWC Gemini" "$DISK" >/dev/null

# Size the volume image to the partition exactly: overflowing it would
# overwrite the backup GPT at the end of the disk, which is one of the things
# the detector relies on.
START=$(sgdisk -i 2 "$DISK" | awk '/First sector/{print $3}')
END=$(sgdisk -i 2 "$DISK" | awk '/Last sector/{print $3}')
PART_SECTORS=$(( END - START + 1 ))
PART="$WORK/part.img"
truncate -s $(( PART_SECTORS * 512 )) "$PART"
mkfs.hfsplus -v "OWC Gemini" "$PART" >/dev/null

mkdir -p "$MNT" "$SRC"
sudo mount -t hfsplus -o loop,rw,uid=$(id -u),gid=$(id -g) "$PART" "$MNT"
echo "== filling the volume =="
python3 - "$MNT" "$SRC" <<'PY'
import os, sys, random
mnt, src = sys.argv[1], sys.argv[2]
random.seed(11)
# Folders of "photos", like the drive this was written for.
for folder in ['RIG EM RIGHT 24', 'Watt_Osage Basin_RAW', 'Stormy Sky']:
    d = os.path.join(mnt, folder)
    os.makedirs(d, exist_ok=True)
    for i in range(12):
        # Files big enough to span many stripes, so a wrong stripe size cannot
        # accidentally produce the right bytes. A real .NEF is a TIFF
        # container, so give them a genuine TIFF header - the detector
        # confirms a geometry by checking that files contain what their names
        # promise, and random bytes would (rightly) fail that.
        data = b'II\x2a\x00\x08\x00\x00\x00' + \
               bytes(random.getrandbits(8) for _ in range(200000))
        open(os.path.join(d, f'_LTK{5285+i}.NEF'), 'wb').write(data)
        os.makedirs(os.path.join(src, folder), exist_ok=True)
        open(os.path.join(src, folder, f'_LTK{5285+i}.NEF'), 'wb').write(data)
PY
sync
sudo umount "$MNT"
dd if="$PART" of="$DISK" bs=512 seek="$START" conv=notrunc status=none

overall=0
check_set () {
  local label="$1" expect="$2"
  echo
  echo "== $label =="
  # Ask the tool to work it out with no hints at all.
  if ! "$CLI" raid "$WORK/m0.img" "$WORK/m1.img" > "$WORK/raid.txt" 2>&1; then
    echo "  FAIL: detection did not settle on a geometry"; sed 's/^/    /' "$WORK/raid.txt"
    overall=1; return
  fi
  local result spec
  result=$(grep '^RESULT:' "$WORK/raid.txt" || true)
  spec=$(grep -A1 '^use it with:' "$WORK/raid.txt" | tail -1 | tr -d " '" | sed "s/^de-cli//")
  echo "  ${result}"
  if ! echo "$result" | grep -qi "$expect"; then
    echo "  FAIL: expected a $expect geometry"; overall=1; return
  fi
  # Read every file back through the reassembled set.
  python3 - "$CLI" "$spec" "$SRC" <<'PY' || overall=1
import subprocess, sys, os
cli, spec, src = sys.argv[1:4]
def ls(node):
    r = subprocess.run([cli, spec, 'ls', '2', str(node)], capture_output=True)
    rows = []
    for line in r.stdout.decode(errors='replace').splitlines():
        p = line.split(None, 1)
        if len(p) != 2 or not p[0].isdigit(): continue
        rest = p[1]; is_dir = rest.startswith('<DIR>')
        rest = (rest[5:] if is_dir else rest).strip()
        parts = rest.split(None, 1)
        rows.append((p[0], is_dir, int(parts[0]), parts[1] if len(parts) > 1 else ''))
    return rows
found = {}
def walk(node, prefix=''):
    for nid, is_dir, size, name in ls(node):
        if name.startswith('.') or name.startswith('_LTK') is False and is_dir is False and name.startswith('_'):
            continue
        path = prefix + name
        if is_dir: walk(nid, path + '/')
        else: found[path] = (nid, size)
walk(0)
expected = {}
for dp, _, files in os.walk(src):
    for fn in files:
        full = os.path.join(dp, fn)
        expected[os.path.relpath(full, src)] = full
fails = []
for rel, full in sorted(expected.items()):
    want = open(full, 'rb').read()
    if rel not in found:
        fails.append(f'{rel}: not listed'); continue
    nid, size = found[rel]
    got = subprocess.run([cli, spec, 'cat', '2', nid], capture_output=True).stdout
    if got != want:
        fails.append(f'{rel}: content differs ({len(got)} vs {len(want)})')
print(f'  {len(expected)} files checked, {len(fails)} failure(s)')
for f in fails[:5]: print('    FAIL ' + f)
sys.exit(1 if fails else 0)
PY
}

# 512 is the single-sector stripe some hardware bridges use (a G-RAID pair was
# found doing it). It splits even the boot region across both drives, so it is
# the case most likely to defeat detection - keep it in the regression set.
for STRIPE in 512 32768 65536 131072 524288; do
  python3 - "$DISK" "$WORK" "$STRIPE" <<'PY'
import sys
disk, work, stripe = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = open(disk, 'rb').read()
members = [open(f'{work}/m{i}.img', 'wb') for i in range(2)]
for i in range(0, len(data), stripe):
    members[(i // stripe) % 2].write(data[i:i + stripe])
for m in members: m.close()
PY
  if [ "$STRIPE" -ge 1024 ]; then LBL="$((STRIPE / 1024)) KiB"; else LBL="$STRIPE B"; fi
  check_set "RAID 0, $LBL stripe (detector is not told)" "RAID 0"
done

python3 - "$DISK" "$WORK" <<'PY'
import sys
disk, work = sys.argv[1], sys.argv[2]
data = open(disk, 'rb').read()
half = len(data) // 2
open(f'{work}/m0.img', 'wb').write(data[:half])
open(f'{work}/m1.img', 'wb').write(data[half:])
PY
check_set "concatenated (spanned) set" "Concatenated"

echo
[ "$overall" = 0 ] && echo "ALL RAID CASES OK" || echo "SOME RAID CASES FAILED"
exit "$overall"

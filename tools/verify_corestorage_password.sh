#!/usr/bin/env bash
# Round-trip test for the FileVault 2 (CoreStorage) password unlock.
#
# What a bench actually has is the customer's password, not the 64-hex-digit
# volume key, so the whole chain has to work: decrypt the CoreStorage metadata
# with the key written in the volume header, find the key store in it, stretch
# the password with PBKDF2, unwrap the KEK and then the volume key, derive the
# AES-XTS tweak key, and read the HFS+ volume with the result.
#
# tools/mkcorestorage.py builds the volume from the format up, doing the *
# forward * operations with Python's own PBKDF2 and AES key wrap - so the
# reader is checked against another implementation of the cryptography, not
# against itself. libfvde reads the same image as far as the decrypted
# metadata, which is the part that was read off libfvde in the first place.
#
# Needs sudo for mount/umount. Usage: tools/verify_corestorage_password.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/de-cli"
WORK="$(mktemp -d)"
PLAIN="$WORK/plain.img"
ENC="$WORK/cs.img"
MNT="$WORK/mnt"
PASSWORD="correct horse battery staple"
trap 'sudo umount "$MNT" 2>/dev/null || true; rm -rf "$WORK"' EXIT

[ -x "$CLI" ] || { echo "build de-cli first"; exit 1; }
command -v mkfs.hfsplus >/dev/null || { echo "need hfsprogs (mkfs.hfsplus)"; exit 1; }
python3 -c 'import cryptography' 2>/dev/null || { echo "need python3-cryptography"; exit 1; }

echo "== building a 48 MB HFS+ volume =="
truncate -s 48M "$PLAIN"
mkfs.hfsplus -v "Macintosh HD" "$PLAIN" >/dev/null
mkdir -p "$MNT"
sudo mount -o loop,uid=$(id -u),gid=$(id -g) "$PLAIN" "$MNT"
mkdir -p "$MNT/Documents"
head -c 200000 /dev/urandom > "$MNT/Documents/artwork.psd"
echo "only readable with the password" > "$MNT/Documents/note.txt"
cp "$MNT/Documents/artwork.psd" "$WORK/ref.psd"
sudo umount "$MNT"

# Run everything twice: with the key store stored as plain XML, and deflated
# across a chain of metadata blocks, which is the shape a real volume with
# several accounts on it uses.
for LAYOUT in plain compressed; do
echo
echo "###### key store stored $LAYOUT ######"
[ "$LAYOUT" = compressed ] && COMPRESS=--compress-plist || COMPRESS=

echo "== locking it behind a FileVault 2 password =="
BUILD="$(python3 "$ROOT/tools/mkcorestorage.py" "$ENC" --password "$PASSWORD" \
                 --from "$PLAIN" $COMPRESS)"
echo "$BUILD" | sed 's/^/   | /'
KEY="$(echo "$BUILD" | awk '/volume key/ {print $4}')"

echo "== the volume must really be encrypted =="
grep -q "only readable with the password" "$ENC" && {
    echo "FAIL: plaintext file content still visible in the image"; exit 1; }
"$CLI" "$ENC" cs 1 | grep -q "AES-XTS" || { echo "FAIL: not seen as CoreStorage"; exit 1; }
echo "   ok - body is ciphertext, header reads as FileVault 2"

echo "== a wrong password must be refused, not guessed at =="
if "$CLI" "$ENC" cs 1 --password "hunter2" >/dev/null 2>&1; then
    echo "FAIL: a wrong password unlocked the volume"; exit 1
fi
echo "   ok"

echo "== the right password must unlock it =="
INFO="$("$CLI" "$ENC" cs 1 --password "$PASSWORD")"
echo "$INFO" | sed 's/^/   | /'
echo "$INFO" | grep -q "password accepted" || { echo "FAIL: password rejected"; exit 1; }
echo "$INFO" | grep -q "HFS+"              || { echo "FAIL: no HFS+ behind the key"; exit 1; }

echo "== and the derived key must be the volume's actual key =="
"$CLI" "$ENC" cs 1 --volume-key "$KEY" | grep -q "HFS+" || {
    echo "FAIL: the key the image was built with does not open it"; exit 1; }
echo "   ok - password and volume key open the same volume"

echo "== browse and export through the password =="
"$CLI" "$ENC" ls 1 --password "$PASSWORD" 2>/dev/null | grep -q Documents || {
    echo "FAIL: cannot list the root of the unlocked volume"; exit 1; }
REC="$("$CLI" "$ENC" find 1 artwork.psd --password "$PASSWORD" 2>/dev/null | head -1)"
[ -n "$REC" ] || { echo "FAIL: search found nothing on the unlocked volume"; exit 1; }
rm -rf "$WORK/out"
"$CLI" "$ENC" export 1 2 "$WORK/out" --password "$PASSWORD" >/dev/null 2>&1
cmp "$WORK/out/Documents/artwork.psd" "$WORK/ref.psd" || {
    echo "FAIL: file content differs"; exit 1; }
echo "   ok - 200000-byte file recovered byte for byte"
done

echo
echo "PASS: a FileVault 2 volume opened with the password alone."

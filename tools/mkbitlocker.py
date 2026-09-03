#!/usr/bin/env python3
"""Build a synthetic BitLocker volume protected by a *clear key*.

This is what a disk looks like when BitLocker was left suspended: the volume is
genuinely AES-XTS encrypted, but the key that unwraps the VMK is written into
the FVE metadata in the clear, so it opens with no credential at all.

Real suspended volumes are awkward to produce on demand (they need Windows, and
a reboot), so the format is built here directly from the libbde documentation.
That makes the test independent of the C++ reader: if the two disagree, one of
them is wrong about the on-disk format, which is exactly what a test should
catch.

Usage: mkbitlocker.py <plain-ntfs.img> <out.img>
"""
import os, struct, sys, uuid
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SECTOR = 512
HDR_SIZE = 8192          # bytes of the original volume BitLocker relocates
META_OFFS = (32 << 20, 40 << 20, 48 << 20)
HDR_BLOCK_OFF = 56 << 20

def entry(etype, vtype, data, version=1):
    """One FVE metadata entry: size, entry type, value type, version, data."""
    return struct.pack('<HHHH', 8 + len(data), etype, vtype, version) + data

def ccm_wrap(key, nonce, plain):
    """AES-CCM encrypt, stored as nonce || MAC || ciphertext (libbde order)."""
    blob = AESCCM(key, tag_length=16).encrypt(nonce, plain, None)
    ct, mac = blob[:-16], blob[-16:]
    return nonce + mac + ct

def keyblob(raw):
    """The plaintext of a wrapped key: 8-byte entry header, 4-byte key header,
    then the key itself - the reader takes everything from offset 12."""
    return struct.pack('<HHHH', 12 + len(raw), 0x0000, 0x0001, 1) \
         + struct.pack('<HH', 0x0000, 0x0000) + raw

def xts_encrypt(fvek, data, first_unit):
    """AES-XTS-128 per 512-byte sector, tweak = the volume-relative sector."""
    out = bytearray()
    for i in range(0, len(data), SECTOR):
        tweak = struct.pack('<Q', first_unit + i // SECTOR) + b'\x00' * 8
        enc = Cipher(algorithms.AES(fvek), modes.XTS(tweak)).encryptor()
        out += enc.update(data[i:i + SECTOR]) + enc.finalize()
    return bytes(out)

def build(plain, out_path):
    vol_size = len(plain)
    clear_key = os.urandom(32)          # the "blank" key, stored in the open
    vmk       = os.urandom(32)
    fvek      = os.urandom(32)          # AES-XTS-128 => key1||key2

    # Encrypt the whole volume, then lay the plaintext structures back on top.
    ct = bytearray(xts_encrypt(fvek, plain, 0))

    # The first HDR_SIZE bytes are displaced by the BitLocker header, so their
    # ciphertext is relocated - still keyed to its *new* physical sector.
    ct[HDR_BLOCK_OFF:HDR_BLOCK_OFF + HDR_SIZE] = \
        xts_encrypt(fvek, plain[:HDR_SIZE], HDR_BLOCK_OFF // SECTOR)

    # --- metadata entries ---------------------------------------------------
    vmk_entry_body = (
        uuid.uuid4().bytes_le + struct.pack('<Q', 0) + struct.pack('<HH', 0, 0x0000)
        + entry(0x0000, 0x0001, struct.pack('<I', 0) + clear_key)      # the clear key
        + entry(0x0000, 0x0005, ccm_wrap(clear_key, os.urandom(12), keyblob(vmk)))
    )
    entries = (
        entry(0x0007, 0x0002, "SYNTHETIC SUSPENDED VOLUME".encode('utf-16-le') + b'\x00\x00')
        + entry(0x0002, 0x0008, vmk_entry_body)
        + entry(0x0003, 0x0005, ccm_wrap(vmk, os.urandom(12), keyblob(fvek)))
        + entry(0x000F, 0x000F, struct.pack('<QQ', HDR_BLOCK_OFF, HDR_SIZE))
    )
    header_size, meta_size = 0x30, 0x30 + len(entries)
    meta = bytearray(0x40 + meta_size)
    meta[0:8] = b'-FVE-FS-'
    struct.pack_into('<Q', meta, 0x10, vol_size)                 # encrypted volume size
    struct.pack_into('<IIII', meta, 0x40, meta_size, 1, header_size, meta_size)
    meta[0x50:0x60] = uuid.uuid4().bytes_le                      # volume GUID
    struct.pack_into('<H', meta, 0x64, 0x8004)                   # AES-XTS-128
    meta[0x70:0x70 + len(entries)] = entries

    # --- BitLocker volume boot record --------------------------------------
    boot = bytearray(SECTOR)
    boot[0:3]   = b'\xeb\x58\x90'
    boot[3:11]  = b'-FVE-FS-'
    struct.pack_into('<H', boot, 0x0B, SECTOR)
    boot[0x0D]  = 8
    boot[0xA0:0xB0] = uuid.UUID('4967d63b-2e29-4ad8-8399-f6a339e3d001').bytes_le
    for i, mo in enumerate(META_OFFS):
        struct.pack_into('<Q', boot, 0xB0 + 8 * i, mo)
    boot[0x1FE:0x200] = b'\x55\xaa'

    ct[0:SECTOR] = boot
    for mo in META_OFFS:                       # all three copies, as Windows writes
        ct[mo:mo + len(meta)] = meta

    open(out_path, 'wb').write(bytes(ct))
    print(f"wrote {out_path}: {vol_size} bytes, AES-XTS-128, clear-key protector")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    build(open(sys.argv[1], 'rb').read(), sys.argv[2])

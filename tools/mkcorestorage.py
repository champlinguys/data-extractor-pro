#!/usr/bin/env python3
"""Build a small CoreStorage (FileVault 2) volume locked with a password.

macOS is the only thing that writes these, and a real FileVault disk is not
something a test can conjure - so this writes one from the format up, the way
tools/mkbitlocker.py does for BitLocker. Everything a password has to walk is
present and genuinely produced by the forward operations:

    password -> PBKDF2-SHA256 -> passphrase key
             -> AES key wrap   -> KEK          (in PassphraseWrappedKEKStruct)
             -> AES key wrap   -> volume key   (in KEKWrappedVolumeKeyStruct)
    volume key + logical volume family UUID -> the AES-XTS pair

so a reader that gets the password wrong, hashes the wrong bytes, or derives
the tweak key differently cannot open the image by accident.

The image holds: the CoreStorage volume header, one copy of the plaintext
metadata that says where the key store lives, the AES-XTS encrypted metadata
carrying the EncryptedRoot plist and the logical volume's family UUID, and an
HFS+ filesystem encrypted with the volume key the password derives.

libfvde reads this image as far as the decrypted metadata - the volume header,
the plaintext metadata, and the AES-XTS decryption of the key store all satisfy
it - and then stops for want of the logical volume segment map, which nothing
here needs: the reader under test finds the logical volume by decrypting for it.

Usage:
    mkcorestorage.py <out.img> [--password PW] [--size-mb N] [--from FS.img]
"""

import argparse
import base64
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib
from hashlib import pbkdf2_hmac, sha256

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

SECTOR = 512
BLOCK_SIZE = 8192           # CoreStorage block size; metadata blocks are this big
METADATA_SIZE = 65536       # bytes of metadata at each copy
BLOCK_HEADER = 64

# Block numbers, in BLOCK_SIZE units.
METADATA_BLOCKS = (1, 9, 17, 25)   # four copies, as macOS writes
ENCRYPTED_METADATA_BLOCK = 33
ENCRYPTED_METADATA_BLOCKS = METADATA_SIZE // BLOCK_SIZE
LOGICAL_VOLUME_OFFSET = 1 << 20     # where the filesystem starts

ITERATIONS = 41000          # what macOS uses; kept so the test costs what it costs


def crc32c(data, initial=0xFFFFFFFF):
    """The 'weak CRC-32' CoreStorage stamps on every metadata block."""
    table = crc32c.table
    checksum = initial
    for byte in data:
        checksum = table[(checksum ^ byte) & 0xFF] ^ (checksum >> 8)
    return checksum


def _build_table(polynomial=0x82F63B78):
    table = []
    for index in range(256):
        checksum = index
        for _ in range(8):
            checksum = (polynomial ^ (checksum >> 1)) if checksum & 1 else checksum >> 1
        table.append(checksum)
    return table


crc32c.table = _build_table()


def xts_encrypt(key, tweak_key, unit, data):
    """AES-128-XTS over one data unit, the tweak taken from `unit`."""
    tweak = struct.pack("<Q", unit) + b"\x00" * 8
    cipher = Cipher(algorithms.AES(key + tweak_key), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def metadata_block(block_type, body, serial, number=0, object_id=0):
    """A metadata block: the 64-byte header, its checksum, and `body`."""
    block = bytearray(BLOCK_SIZE)
    struct.pack_into("<I", block, 4, 0xFFFFFFFF)        # checksum initial value
    struct.pack_into("<H", block, 8, 1)                 # version
    struct.pack_into("<H", block, 10, block_type)
    struct.pack_into("<I", block, 12, serial)
    struct.pack_into("<Q", block, 16, 1)                # transaction identifier
    struct.pack_into("<Q", block, 24, object_id)
    struct.pack_into("<Q", block, 32, number)
    struct.pack_into("<I", block, 48, BLOCK_SIZE)
    block[BLOCK_HEADER:BLOCK_HEADER + len(body)] = body
    struct.pack_into("<I", block, 0, crc32c(block[8:]))
    return bytes(block)


def volume_header(pv_uuid, vg_uuid, key_data, volume_size, serial):
    head = bytearray(SECTOR)
    struct.pack_into("<I", head, 4, 0xFFFFFFFF)         # checksum initial value
    struct.pack_into("<H", head, 8, 1)                  # format version
    struct.pack_into("<H", head, 10, 0x0010)            # block type: volume header
    struct.pack_into("<I", head, 12, serial)
    struct.pack_into("<I", head, 48, SECTOR)            # bytes per sector
    struct.pack_into("<Q", head, 64, volume_size)
    head[88:90] = b"CS"
    struct.pack_into("<I", head, 90, 1)                 # checksum algorithm
    struct.pack_into("<I", head, 96, BLOCK_SIZE)
    struct.pack_into("<I", head, 100, METADATA_SIZE)
    for index, block in enumerate(METADATA_BLOCKS):
        struct.pack_into("<Q", head, 104 + index * 8, block)
    struct.pack_into("<I", head, 168, len(key_data))
    struct.pack_into("<I", head, 172, 2)                # encryption: AES-XTS
    head[176:176 + len(key_data)] = key_data
    head[304:320] = pv_uuid
    head[320:336] = vg_uuid
    struct.pack_into("<I", head, 0, crc32c(head[8:]))
    return bytes(head)


def volume_groups_block(serial, pv_uuid, vg_uuid):
    """The plaintext 0x0011 block: it says where the encrypted metadata is.

    The volume group plist that follows the descriptor is not something this
    reader needs - it takes the physical volume it was handed - but libfvde
    insists on it, and the point of the image is to be readable by both.
    """
    xml = (
        "<dict>\n"
        "\t<key>com.apple.corestorage.lvg.uuid</key>\n"
        f"\t<string>{vg_uuid}</string>\n"
        "\t<key>com.apple.corestorage.lvg.name</key>\n"
        "\t<string>Macintosh HD</string>\n"
        "\t<key>com.apple.corestorage.lvg.physicalVolumes</key>\n"
        "\t<array>\n"
        f"\t\t<string>{pv_uuid}</string>\n"
        "\t</array>\n"
        "</dict>\n"
    )
    body = bytearray(BLOCK_SIZE - BLOCK_HEADER)
    struct.pack_into("<I", body, 0, METADATA_SIZE)
    descriptor = 512                                    # from the block's start
    xml_offset = 1024                                   # likewise
    struct.pack_into("<I", body, 156, descriptor)
    struct.pack_into("<I", body, 160, xml_offset)
    struct.pack_into("<I", body, 184, 0)                # no entries follow

    at = descriptor - BLOCK_HEADER
    struct.pack_into("<Q", body, at + 8, ENCRYPTED_METADATA_BLOCKS)
    struct.pack_into("<Q", body, at + 32, ENCRYPTED_METADATA_BLOCK)
    struct.pack_into("<Q", body, at + 40, ENCRYPTED_METADATA_BLOCK)

    data = xml.encode() + b"\x00"
    at = xml_offset - BLOCK_HEADER
    body[at:at + len(data)] = data
    return metadata_block(0x0011, bytes(body), serial)


def plist_block(serial, xml):
    """A 0x0019 block holding the EncryptedRoot plist, stored uncompressed."""
    body = bytearray(BLOCK_SIZE - BLOCK_HEADER)
    data = xml.encode() + b"\x00"
    at = 80                                             # after the entry table
    struct.pack_into("<Q", body, 32, 0)                 # no continuation block
    struct.pack_into("<I", body, 40, len(data))         # compressed size ...
    struct.pack_into("<I", body, 44, len(data))         # ... equal: not compressed
    struct.pack_into("<I", body, 48, at + BLOCK_HEADER)
    struct.pack_into("<I", body, 52, len(data))
    struct.pack_into("<H", body, 62, 0)                 # no entries
    body[at:at + len(data)] = data
    return metadata_block(0x0019, bytes(body), serial)


def compressed_plist_blocks(serial, xml, chunk_size=384):
    """The same plist deflated and split across a 0x0019 + 0x0024 chain.

    This is the shape a real volume tends to use - a key store with several
    accounts in it does not fit in one block - so it is worth being able to
    build, even though the uncompressed form is easier to read. The chunk size
    is deliberately small: a chain of blocks is the case worth testing.
    """
    plain = xml.encode() + b"\x00"
    compressed = zlib.compress(plain, 9)
    chunks = [compressed[i:i + chunk_size]
              for i in range(0, len(compressed), chunk_size)] or [b""]

    # Each block names the one that continues it; the last names nobody.
    ids = [0x4000 + index for index in range(len(chunks))]
    blocks = []

    body = bytearray(BLOCK_SIZE - BLOCK_HEADER)
    at = 80
    struct.pack_into("<Q", body, 32, ids[1] if len(chunks) > 1 else 0)
    struct.pack_into("<I", body, 40, len(compressed))
    struct.pack_into("<I", body, 44, len(plain))
    struct.pack_into("<I", body, 48, at + BLOCK_HEADER)
    struct.pack_into("<I", body, 52, len(chunks[0]))
    struct.pack_into("<H", body, 62, 0)
    body[at:at + len(chunks[0])] = chunks[0]
    blocks.append(metadata_block(0x0019, bytes(body), serial, object_id=ids[0]))

    for index in range(1, len(chunks)):
        body = bytearray(BLOCK_SIZE - BLOCK_HEADER)
        following = ids[index + 1] if index + 1 < len(chunks) else 0
        struct.pack_into("<Q", body, 0, following)
        struct.pack_into("<I", body, 8, len(chunks[index]))
        body[16:16 + len(chunks[index])] = chunks[index]
        blocks.append(metadata_block(0x0024, bytes(body), serial,
                                     object_id=ids[index]))
    return blocks


def family_uuid_block(serial, family_uuid):
    """A 0x001a block: the logical volume descriptor, family UUID and all."""
    xml = (
        "<dict>\n"
        "\t<key>com.apple.corestorage.lv.familyUUID</key>\n"
        f"\t<string>{family_uuid}</string>\n"
        "\t<key>com.apple.corestorage.lv.name</key>\n"
        "\t<string>Macintosh HD</string>\n"
        "</dict>\n"
    )
    body = bytearray(BLOCK_SIZE - BLOCK_HEADER)
    data = xml.encode() + b"\x00"
    at = 96
    struct.pack_into("<I", body, 56, len(data))
    struct.pack_into("<I", body, 60, len(data))
    struct.pack_into("<I", body, 64, at + BLOCK_HEADER)
    struct.pack_into("<I", body, 68, len(data))
    body[at:at + len(data)] = data
    return metadata_block(0x001A, bytes(body), serial)


def encrypted_root_plist(password, volume_key):
    """Wrap the volume key for `password` the way macOS's key store does."""
    salt = os.urandom(16)
    kek = os.urandom(16)
    passphrase_key = pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, 16)

    wrapped_kek = bytearray(284)
    struct.pack_into("<I", wrapped_kek, 0, 3)           # value type: salt
    struct.pack_into("<I", wrapped_kek, 4, 16)
    wrapped_kek[8:24] = salt
    struct.pack_into("<I", wrapped_kek, 24, 0x10)       # value type: wrapped key
    struct.pack_into("<I", wrapped_kek, 28, 24)
    wrapped_kek[32:56] = aes_key_wrap(passphrase_key, kek)
    struct.pack_into("<I", wrapped_kek, 168, ITERATIONS)

    wrapped_volume_key = bytearray(256)
    struct.pack_into("<I", wrapped_volume_key, 0, 0x10)
    struct.pack_into("<I", wrapped_volume_key, 4, 24)
    wrapped_volume_key[8:32] = aes_key_wrap(kek, volume_key)

    def data_element(blob):
        text = base64.b64encode(blob).decode()
        lines = [text[i:i + 68] for i in range(0, len(text), 68)]
        return "\n".join("\t\t\t" + line for line in lines)

    return (
        "<dict>\n"
        "\t<key>ConversionInfo</key>\n"
        "\t<dict>\n"
        "\t\t<key>ConversionStatus</key>\n"
        "\t\t<string>complete</string>\n"
        "\t</dict>\n"
        "\t<key>CryptoUsers</key>\n"
        "\t<array>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>PassphraseWrappedKEKStruct</key>\n"
        "\t\t\t<data>\n"
        f"{data_element(bytes(wrapped_kek))}\n"
        "\t\t\t</data>\n"
        "\t\t</dict>\n"
        "\t</array>\n"
        "\t<key>WrappedVolumeKeys</key>\n"
        "\t<array>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>KEKWrappedVolumeKeyStruct</key>\n"
        "\t\t\t<data>\n"
        f"{data_element(bytes(wrapped_volume_key))}\n"
        "\t\t\t</data>\n"
        "\t\t</dict>\n"
        "\t</array>\n"
        "</dict>\n"
    )


def make_hfsplus(size, label="Macintosh HD"):
    """An HFS+ filesystem with a few files in it, as a plain byte string."""
    with tempfile.TemporaryDirectory() as work:
        path = os.path.join(work, "hfs.img")
        with open(path, "wb") as handle:
            handle.truncate(size)
        subprocess.run(["mkfs.hfsplus", "-v", label, path],
                       check=True, stdout=subprocess.DEVNULL)
        with open(path, "rb") as handle:
            return handle.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--password", default="opensesame")
    parser.add_argument("--size-mb", type=int, default=48)
    parser.add_argument("--compress-plist", action="store_true",
                        help="store the key store deflated across a chain of "
                             "metadata blocks, as a real volume tends to")
    parser.add_argument("--from", dest="source", metavar="FS.img",
                        help="encrypt this filesystem image instead of making "
                             "an empty HFS+ one")
    args = parser.parse_args()

    if args.source is None and shutil.which("mkfs.hfsplus") is None:
        sys.exit("mkfs.hfsplus not found (apt install hfsprogs)")

    serial = struct.unpack("<I", os.urandom(4))[0]
    pv_uuid = uuid.uuid4()
    vg_uuid = uuid.uuid4()
    family_uuid = uuid.uuid4()

    # The metadata's own key: written in the clear in the volume header, which
    # is how a password can be checked before any key is known.
    metadata_key = os.urandom(16)
    key_data = metadata_key + os.urandom(112)

    # The volume key the password will have to produce, and the AES-XTS pair
    # derived from it - the tweak key is SHA-256 over the key and the family.
    volume_key = os.urandom(16)
    tweak_key = sha256(volume_key + family_uuid.bytes).digest()[:16]

    if args.source:
        with open(args.source, "rb") as handle:
            filesystem = handle.read()
        total = LOGICAL_VOLUME_OFFSET + len(filesystem)
    else:
        total = args.size_mb << 20
        filesystem = None
    image = bytearray(total)
    image[0:SECTOR] = volume_header(pv_uuid.bytes, vg_uuid.bytes, key_data,
                                    total, serial)

    plaintext_metadata = volume_groups_block(serial, pv_uuid, vg_uuid)
    for block in METADATA_BLOCKS:
        at = block * BLOCK_SIZE
        image[at:at + BLOCK_SIZE] = plaintext_metadata

    xml = encrypted_root_plist(args.password, volume_key)
    blocks = (compressed_plist_blocks(serial, xml) if args.compress_plist
              else [plist_block(serial, xml)])
    blocks.append(family_uuid_block(serial, family_uuid))
    for index, block in enumerate(blocks):
        at = (ENCRYPTED_METADATA_BLOCK + index) * BLOCK_SIZE
        image[at:at + BLOCK_SIZE] = xts_encrypt(metadata_key, pv_uuid.bytes,
                                                index, block)

    # The filesystem, encrypted a sector at a time with the logical sector
    # number as the tweak - the volume's own coordinate system, which is why
    # the reader has to find where the logical volume starts.
    if filesystem is None:
        filesystem = make_hfsplus(total - LOGICAL_VOLUME_OFFSET)
    for offset in range(0, len(filesystem), SECTOR):
        sector = filesystem[offset:offset + SECTOR]
        at = LOGICAL_VOLUME_OFFSET + offset
        image[at:at + SECTOR] = xts_encrypt(volume_key, tweak_key,
                                            offset // SECTOR, sector)

    with open(args.output, "wb") as handle:
        handle.write(image)

    print(f"wrote {args.output} ({args.size_mb} MiB)")
    print(f"  password     : {args.password}")
    print(f"  volume key   : {(volume_key + tweak_key).hex()}")
    print(f"  physical UUID: {pv_uuid}")
    print(f"  family UUID  : {family_uuid}")


if __name__ == "__main__":
    main()

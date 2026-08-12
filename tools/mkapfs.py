#!/usr/bin/env python3
"""Build a small but structurally valid APFS container, for testing the reader.

There is no way to create an APFS filesystem on Linux, and a real Mac disk is
not something you can commit to a repository - so this writes one by hand:
a container superblock in a checkpoint area, an object map, a volume, and a
filesystem B-tree holding directories, multi-extent files, a sparse file, and
decmpfs-compressed files. Everything carries a real Fletcher-64 checksum, so
the reader's validation path is exercised exactly as it would be on real media.

It also writes a manifest of what it put in, so the test script can check the
extracted files byte for byte.

Usage:  mkapfs.py OUT.img [--files N]
"""
import argparse
import json
import struct
import zlib

BS = 4096                     # container block size
OBJ_HDR = 32

# Object types / storage classes.
T_NX_SUPERBLOCK = 0x01
T_BTREE = 0x02
T_BTREE_NODE = 0x03
T_OMAP = 0x0B
T_FS = 0x0D
T_FSTREE = 0x0E
OBJ_VIRTUAL = 0x00000000
OBJ_EPHEMERAL = 0x80000000
OBJ_PHYSICAL = 0x40000000

# B-tree node flags.
BTNODE_ROOT = 0x0001
BTNODE_LEAF = 0x0002
BTNODE_FIXED_KV_SIZE = 0x0004
BTREE_INFO_SIZE = 40

# Filesystem record types (top 4 bits of the key's obj_id_and_type).
TYPE_INODE = 3
TYPE_XATTR = 4
TYPE_FILE_EXTENT = 8
TYPE_DIR_REC = 9

INO_EXT_TYPE_NAME = 4
INO_EXT_TYPE_DSTREAM = 8

DT_DIR = 4
DT_REG = 8

S_IFDIR = 0o040000
S_IFREG = 0o100000

XATTR_DATA_STREAM = 0x0001
XATTR_DATA_EMBEDDED = 0x0002

XID = 4
ROOT_INO = 2
TIME_NS = 1_700_000_000_000_000_000


def fletcher64(data, init=0):
    s1 = init & 0xFFFFFFFF
    s2 = init >> 32
    for i in range(0, len(data) - len(data) % 4, 4):
        s1 = (s1 + struct.unpack_from('<I', data, i)[0]) % 0xFFFFFFFF
        s2 = (s2 + s1) % 0xFFFFFFFF
    return s1 | (s2 << 32)


def seal(block):
    """Stamp a block with the checksum APFS expects over its own contents."""
    body = fletcher64(block[8:])
    s1, s2 = body & 0xFFFFFFFF, body >> 32
    c1 = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
    c2 = 0xFFFFFFFF - ((s1 + c1) % 0xFFFFFFFF)
    return struct.pack('<Q', c1 | (c2 << 32)) + block[8:]


def hdr(oid, otype, storage, subtype=0, xid=XID):
    return struct.pack('<QQQII', 0, oid, xid, otype | storage, subtype)


class Image:
    def __init__(self):
        self.blocks = {}
        self.next_free = 0

    def alloc(self, n=1):
        b = self.next_free
        self.next_free += n
        return b

    def put(self, paddr, data, checksum=True):
        assert len(data) <= BS, len(data)
        data = data.ljust(BS, b'\0')
        self.blocks[paddr] = seal(data) if checksum else data

    def write(self, path, total_blocks):
        with open(path, 'wb') as f:
            for i in range(total_blocks):
                f.write(self.blocks.get(i, b'\0' * BS))


def jkey(oid, rtype, extra=b''):
    return struct.pack('<Q', (rtype << 60) | oid) + extra


def build_btree(img, records, subtype, virtual_oids=None, fixed=None):
    """Lay a sorted record list out as a B-tree; return (root_oid_or_paddr, map).

    `virtual_oids` is a counter object for allocating virtual node ids when the
    tree is a virtual one (the filesystem tree); the returned map is
    {virtual oid: block address} for the caller to put in an object map. For a
    physical tree (an object map's own tree) nodes are addressed directly and
    the map comes back empty.
    """
    omap_entries = {}

    def node_bytes(entries, is_root, is_leaf, level):
        """Pack entries [(key, val)] into one node block."""
        flags = (BTNODE_ROOT if is_root else 0) | (BTNODE_LEAF if is_leaf else 0)
        if fixed:
            flags |= BTNODE_FIXED_KV_SIZE
        toc_len = max(64, len(entries) * (4 if fixed else 8))
        toc_len = (toc_len + 7) & ~7
        key_base = 56 + toc_len
        val_end = BS - (BTREE_INFO_SIZE if is_root else 0)

        toc, keys, vals = b'', b'', b''
        for k, v in entries:
            if fixed:
                toc += struct.pack('<HH', len(keys), len(vals) + len(v))
            else:
                toc += struct.pack('<HHHH', len(keys), len(k),
                                   len(vals) + len(v), len(v))
            keys += k
            vals = v + vals          # values are packed from the end backwards
        assert key_base + len(keys) <= val_end - len(vals), 'node overflow'

        body = struct.pack('<HHI', flags, level, len(entries))
        body += struct.pack('<HH', 0, toc_len)              # btn_table_space
        body += struct.pack('<HH', 0, 0)                    # btn_free_space
        body += struct.pack('<HH', 0, 0)                    # btn_key_free_list
        body += struct.pack('<HH', 0, 0)                    # btn_val_free_list
        assert len(body) == 56 - OBJ_HDR
        blk = bytearray(BS)
        blk[OBJ_HDR:56] = body
        blk[56:56 + len(toc)] = toc
        blk[key_base:key_base + len(keys)] = keys
        blk[val_end - len(vals):val_end] = vals
        if is_root:
            info = struct.pack('<IIII', 0, BS,
                               fixed[0] if fixed else 0,
                               fixed[1] if fixed else 0)
            info += struct.pack('<IIQQ', 64, 64, len(records), 1)
            blk[BS - BTREE_INFO_SIZE:BS] = info[:BTREE_INFO_SIZE]
        return bytes(blk)

    def emit(entries, is_root, is_leaf, level):
        paddr = img.alloc()
        if virtual_oids is not None:
            oid = virtual_oids[0]
            virtual_oids[0] += 1
            omap_entries[oid] = paddr
            storage = OBJ_VIRTUAL
        else:
            oid = paddr
            storage = OBJ_PHYSICAL
        otype = T_BTREE if is_root else T_BTREE_NODE
        blk = node_bytes(entries, is_root, is_leaf, level)
        img.put(paddr, hdr(oid, otype, storage, subtype) + blk[OBJ_HDR:])
        return oid, paddr

    # Split the records into leaves that comfortably fit a block.
    leaves, cur, used = [], [], 0
    budget = BS - 56 - 256
    for k, v in records:
        cost = len(k) + len(v) + (4 if fixed else 8)
        if cur and used + cost > budget:
            leaves.append(cur)
            cur, used = [], 0
        cur.append((k, v))
        used += cost
    if cur:
        leaves.append(cur)

    if len(leaves) == 1:
        oid, paddr = emit(leaves[0], True, True, 0)
        return oid, paddr, omap_entries

    seps = []
    for chunk in leaves:
        oid, _ = emit(chunk, False, True, 0)
        seps.append((chunk[0][0], struct.pack('<Q', oid)))
    root_oid, root_paddr = emit(seps, True, False, 1)
    return root_oid, root_paddr, omap_entries


def omap_records(mapping):
    """(oid, xid) -> paddr records for an object map's tree, in key order."""
    out = []
    for oid in sorted(mapping):
        out.append((struct.pack('<QQ', oid, XID),
                    struct.pack('<IIQ', 0, BS, mapping[oid])))
    return out


def make_omap(img, mapping):
    """Write an object map object plus its tree; return the omap's paddr."""
    tree_paddr = None
    root_oid, root_paddr, _ = build_btree(img, omap_records(mapping),
                                          subtype=T_OMAP, fixed=(16, 16))
    tree_paddr = root_paddr
    paddr = img.alloc()
    body = struct.pack('<IIII', 0, 0, T_BTREE | OBJ_PHYSICAL, T_BTREE | OBJ_PHYSICAL)
    body += struct.pack('<QQQQQ', tree_paddr, 0, 0, 0, 0)
    img.put(paddr, hdr(paddr, T_OMAP, OBJ_PHYSICAL) + body)
    return paddr


def xfields(fields):
    """Pack inode extended fields: header, descriptor table, padded values."""
    table, data = b'', b''
    for xtype, value in fields:
        table += struct.pack('<BBH', xtype, 0, len(value))
        data += value + b'\0' * (-len(value) % 8)
    return struct.pack('<HH', len(fields), len(data)) + table + data


def inode_val(parent, private_id, mode, nchildren=0, name=b'', dstream=None,
              uncompressed=0):
    v = struct.pack('<QQQQQQQ', parent, private_id, TIME_NS, TIME_NS, TIME_NS,
                    TIME_NS, 0)
    v += struct.pack('<iIII', nchildren, 0, 0, 0)      # nchildren, class, wgc, bsd
    v += struct.pack('<IIHHI', 501, 20, mode, 0, 0)    # owner, group, mode, pads
    v += struct.pack('<Q', uncompressed)               # uncompressed_size
    assert len(v) == 96, len(v)
    fields = []
    if dstream is not None:
        size, alloced = dstream
        fields.append((INO_EXT_TYPE_DSTREAM,
                       struct.pack('<QQQQQ', size, alloced, 0, size, 0)))
    if name:
        fields.append((INO_EXT_TYPE_NAME, name + b'\0'))
    return v + (xfields(fields) if fields else b'')


def drec(parent, name, child_id, kind, hashed=True):
    nb = name.encode() + b'\0'
    if hashed:
        key = jkey(parent, TYPE_DIR_REC, struct.pack('<I', len(nb) & 0x3FF) + nb)
    else:
        key = jkey(parent, TYPE_DIR_REC, struct.pack('<H', len(nb)) + nb)
    val = struct.pack('<QQH', child_id, TIME_NS, kind)
    return key, val


def extent(stream_id, logical, length, phys):
    return (jkey(stream_id, TYPE_FILE_EXTENT, struct.pack('<Q', logical)),
            struct.pack('<QQQ', length, phys, 0))


def xattr(oid, name, flags, data):
    nb = name.encode() + b'\0'
    key = jkey(oid, TYPE_XATTR, struct.pack('<H', len(nb)) + nb)
    val = struct.pack('<HH', flags, len(data)) + data
    return key, val


def decmpfs_attr(ctype, uncompressed_size, payload):
    return struct.pack('<IIQ', 0x636D7066, ctype, uncompressed_size) + payload


def zlib_resource_fork(chunks):
    """A Macintosh resource fork holding decmpfs type-4 blocks.

    Layout: a big-endian fork header naming the data offset (0x100), then the
    resource data - a 4-byte length, then the compression table (block count
    plus offset/size pairs) whose offsets are relative to the table's base.
    """
    comp = [zlib.compress(c, 6) for c in chunks]
    table = struct.pack('<I', len(comp))
    off = 4 + 8 * len(comp)          # relative to the table base (0x104)
    body = b''
    for c in comp:
        table += struct.pack('<II', off, len(c))
        body += c
        off += len(c)
    data = table + body
    header = struct.pack('>IIII', 0x100, 0x100 + 4 + len(data), len(data), 0)
    fork = header + b'\0' * (0x100 - len(header))
    return fork + struct.pack('>I', len(data)) + data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('--files', type=int, default=0,
                    help='extra plain files, to force a multi-level B-tree')
    args = ap.parse_args()

    img = Image()
    img.alloc(24)          # reserve room for the superblock + checkpoint area
    manifest = {'files': {}, 'dirs': []}

    data_blocks = []       # (paddr, bytes) file content written after the tree

    def store(payload):
        """Write file content into fresh blocks; return the first block."""
        nblocks = max(1, (len(payload) + BS - 1) // BS)
        start = img.alloc(nblocks)
        padded = payload.ljust(nblocks * BS, b'\0')
        for i in range(nblocks):
            data_blocks.append((start + i, padded[i * BS:(i + 1) * BS]))
        return start

    records = []
    next_oid = 16

    def add_dir(parent, name):
        nonlocal next_oid
        oid = next_oid
        next_oid += 1
        records.append(drec(parent, name, oid, DT_DIR))
        records.append((jkey(oid, TYPE_INODE),
                        inode_val(parent, oid, S_IFDIR | 0o755,
                                  name=name.encode())))
        return oid

    def add_file(parent, name, content, hashed=True, sparse=False,
                 extents_override=None):
        nonlocal next_oid
        oid = next_oid
        next_oid += 1
        records.append(drec(parent, name, oid, DT_REG, hashed=hashed))
        records.append((jkey(oid, TYPE_INODE),
                        inode_val(parent, oid, S_IFREG | 0o644,
                                  name=name.encode(),
                                  dstream=(len(content), len(content)))))
        if extents_override is not None:
            for logical, length, payload in extents_override:
                phys = store(payload) if payload is not None else 0
                records.append(extent(oid, logical, length, phys))
        else:
            records.append(extent(oid, 0, (len(content) + BS - 1) // BS * BS,
                                  store(content)))
        return oid

    def add_compressed(parent, name, content, ctype):
        nonlocal next_oid
        oid = next_oid
        next_oid += 1
        records.append(drec(parent, name, oid, DT_REG))
        records.append((jkey(oid, TYPE_INODE),
                        inode_val(parent, oid, S_IFREG | 0o644,
                                  name=name.encode(),
                                  uncompressed=len(content))))
        if ctype == 3:
            attr = decmpfs_attr(3, len(content), zlib.compress(content, 6))
            records.append(xattr(oid, 'com.apple.decmpfs', XATTR_DATA_EMBEDDED, attr))
        elif ctype == 4:
            chunks = [content[i:i + 65536] for i in range(0, len(content), 65536)]
            rsrc = zlib_resource_fork(chunks)
            records.append(xattr(oid, 'com.apple.decmpfs', XATTR_DATA_EMBEDDED,
                                 decmpfs_attr(4, len(content), b'')))
            records.append(xattr(oid, 'com.apple.ResourceFork',
                                 XATTR_DATA_EMBEDDED, rsrc))
        elif ctype == 9:
            attr = decmpfs_attr(9, len(content), content)
            records.append(xattr(oid, 'com.apple.decmpfs', XATTR_DATA_EMBEDDED, attr))
        return oid

    # ---- the test volume's contents ----
    records.append((jkey(ROOT_INO, TYPE_INODE),
                    inode_val(1, ROOT_INO, S_IFDIR | 0o755, name=b'root')))

    hello = b'Hello, APFS!\n'
    add_file(ROOT_INO, 'hello.txt', hello)
    manifest['files']['hello.txt'] = hello.hex()

    # A file made of two extents that are not adjacent on disk.
    part1 = bytes(range(256)) * 16       # 4096
    part2 = bytes(reversed(range(256))) * 16
    two = part1 + part2
    add_file(ROOT_INO, 'twoextents.bin', two,
             extents_override=[(0, BS, part1), (BS, BS, part2)])
    manifest['files']['twoextents.bin'] = two.hex()

    # Sparse: data, a hole, then data again.
    head = b'A' * BS
    tail = b'B' * BS
    sparse = head + b'\0' * BS + tail
    add_file(ROOT_INO, 'sparse.bin', sparse,
             extents_override=[(0, BS, head), (2 * BS, BS, tail)])
    manifest['files']['sparse.bin'] = sparse.hex()

    # An unhashed directory-record key, which older volumes use.
    plain = b'unhashed key path\n'
    add_file(ROOT_INO, 'plainkey.txt', plain, hashed=False)
    manifest['files']['plainkey.txt'] = plain.hex()

    docs = add_dir(ROOT_INO, 'docs')
    manifest['dirs'].append('docs')
    notes = ('notes for the recovery case\n' * 40).encode()
    add_file(docs, 'notes.txt', notes)
    manifest['files']['docs/notes.txt'] = notes.hex()

    # decmpfs: zlib in the attribute, zlib in the resource fork, and stored.
    text = (b'compressible text, repeated. ' * 200)
    add_compressed(ROOT_INO, 'zlib-attr.txt', text, 3)
    manifest['files']['zlib-attr.txt'] = text.hex()

    big = bytes(1000) + (b'block of repeating content 0123456789 ' * 4000)
    big = big[:150000]
    add_compressed(ROOT_INO, 'zlib-rsrc.bin', big, 4)
    manifest['files']['zlib-rsrc.bin'] = big.hex()

    stored = b'stored, not actually compressed\n'
    add_compressed(ROOT_INO, 'raw-attr.txt', stored, 9)
    manifest['files']['raw-attr.txt'] = stored.hex()

    for i in range(args.files):
        name = f'bulk{i:04d}.txt'
        content = f'bulk file {i}\n'.encode() * (i % 7 + 1)
        add_file(ROOT_INO, name, content)
        manifest['files'][name] = content.hex()

    # ---- assemble the volume ----
    records.sort(key=lambda kv: (struct.unpack('<Q', kv[0][:8])[0] & ((1 << 60) - 1),
                                 struct.unpack('<Q', kv[0][:8])[0] >> 60,
                                 kv[0][8:]))

    fs_node_oids = [3000]
    fs_root_oid, _, fs_map = build_btree(img, records, subtype=T_FSTREE,
                                         virtual_oids=fs_node_oids)
    vol_omap_paddr = make_omap(img, fs_map)

    apsb_paddr = img.alloc()
    apsb = bytearray(BS)
    apsb[OBJ_HDR:OBJ_HDR + 8] = struct.pack('<II', 0x42535041, 0)
    struct.pack_into('<I', apsb, 116, T_BTREE)          # root_tree_type
    struct.pack_into('<Q', apsb, 128, vol_omap_paddr)   # apfs_omap_oid (physical)
    struct.pack_into('<Q', apsb, 136, fs_root_oid)      # apfs_root_tree_oid
    struct.pack_into('<Q', apsb, 184, len(manifest['files']))
    struct.pack_into('<Q', apsb, 192, len(manifest['dirs']) + 1)
    struct.pack_into('<Q', apsb, 256, TIME_NS)
    struct.pack_into('<Q', apsb, 264, 1)                # APFS_FS_UNENCRYPTED
    apsb[272:272 + 22] = b'data-extractor-pro/test'[:22]
    name = b'TestVol'
    apsb[704:704 + len(name)] = name
    struct.pack_into('<H', apsb, 964, 0x40)             # role: Data
    img.put(apsb_paddr, hdr(1000, T_FS, OBJ_VIRTUAL) + bytes(apsb[OBJ_HDR:]))

    container_omap_paddr = make_omap(img, {1000: apsb_paddr})

    for paddr, payload in data_blocks:
        img.put(paddr, payload, checksum=False)

    total_blocks = img.next_free + 8

    nx = bytearray(BS)
    struct.pack_into('<II', nx, 32, 0x4253584E, BS)
    struct.pack_into('<Q', nx, 40, total_blocks)
    struct.pack_into('<QQ', nx, 88, 5000, XID + 1)      # next_oid, next_xid
    struct.pack_into('<II', nx, 104, 8, 8)              # xp_desc_blocks, data_blocks
    struct.pack_into('<QQ', nx, 112, 1, 9)              # xp_desc_base, data_base
    struct.pack_into('<Q', nx, 160, container_omap_paddr)
    struct.pack_into('<I', nx, 180, 100)                # max_file_systems
    struct.pack_into('<Q', nx, 184, 1000)               # nx_fs_oid[0]
    sb = hdr(1, T_NX_SUPERBLOCK, OBJ_EPHEMERAL) + bytes(nx[OBJ_HDR:])
    img.put(1, sb)      # the live copy, in the checkpoint descriptor area
    img.put(0, sb)      # block 0

    img.write(args.out, total_blocks)
    with open(args.out + '.manifest.json', 'w') as f:
        json.dump(manifest, f, indent=1)
    print(f'wrote {args.out}: {total_blocks} blocks '
          f'({total_blocks * BS / 1048576:.1f} MiB), '
          f'{len(manifest["files"])} files')


if __name__ == '__main__':
    main()

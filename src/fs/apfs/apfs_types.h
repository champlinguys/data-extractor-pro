#pragma once
#include <cstdint>
#include <cstddef>

// On-disk constants and primitives for APFS (Apple File System).
//
// Everything in APFS is little-endian, so the shared rd16/rd32/rd64 helpers in
// core/byte_reader.h apply directly. The container is a flat array of blocks
// (nx_block_size, normally 4096); every metadata block starts with an
// obj_phys_t header carrying a Fletcher-64 checksum, which is what lets us tell
// a live structure from garbage when reconstructing a damaged or mis-assembled
// (wrong stripe size!) disk.
namespace de::apfs {

// ---- obj_phys_t: the 32-byte header on every metadata block ----
constexpr size_t OBJ_HDR_SIZE = 32;
// Field offsets within obj_phys_t.
constexpr size_t O_CKSUM = 0;    // u64  fletcher64 over the rest of the block
constexpr size_t O_OID = 8;      // u64
constexpr size_t O_XID = 16;     // u64  transaction that wrote this object
constexpr size_t O_TYPE = 24;    // u32  low 16 bits type, high 16 storage class
constexpr size_t O_SUBTYPE = 28; // u32

// Storage class, in the high 16 bits of o_type.
constexpr uint32_t OBJ_TYPE_MASK = 0x0000FFFF;
constexpr uint32_t OBJ_STORAGETYPE_MASK = 0xFFFF0000;
constexpr uint32_t OBJ_VIRTUAL = 0x00000000;   // resolve the oid through an omap
constexpr uint32_t OBJ_EPHEMERAL = 0x80000000; // lives in the checkpoint data area
constexpr uint32_t OBJ_PHYSICAL = 0x40000000;  // oid *is* the block address

// Object types we care about for read-only recovery.
constexpr uint32_t OBJECT_TYPE_NX_SUPERBLOCK = 0x01;
constexpr uint32_t OBJECT_TYPE_BTREE = 0x02;      // B-tree root
constexpr uint32_t OBJECT_TYPE_BTREE_NODE = 0x03; // non-root B-tree node
constexpr uint32_t OBJECT_TYPE_OMAP = 0x0B;
constexpr uint32_t OBJECT_TYPE_CHECKPOINT_MAP = 0x0C;
constexpr uint32_t OBJECT_TYPE_FS = 0x0D; // volume superblock (APSB)

constexpr uint32_t NX_MAGIC = 0x4253584E;   // 'NXSB'
constexpr uint32_t APFS_MAGIC = 0x42535041; // 'APSB'

// ---- nx_superblock_t field offsets ----
constexpr size_t NX_MAGIC_OFF = 32;
constexpr size_t NX_BLOCK_SIZE = 36;
constexpr size_t NX_BLOCK_COUNT = 40;
constexpr size_t NX_FEATURES = 48;
constexpr size_t NX_INCOMPAT_FEATURES = 64;
constexpr size_t NX_UUID = 72;
constexpr size_t NX_NEXT_XID = 96;
constexpr size_t NX_XP_DESC_BLOCKS = 104;
constexpr size_t NX_XP_DATA_BLOCKS = 108;
constexpr size_t NX_XP_DESC_BASE = 112;
constexpr size_t NX_XP_DATA_BASE = 120;
constexpr size_t NX_XP_DESC_NEXT = 128;
constexpr size_t NX_XP_DESC_INDEX = 136;
constexpr size_t NX_XP_DESC_LEN = 140;
constexpr size_t NX_SPACEMAN_OID = 152;
constexpr size_t NX_OMAP_OID = 160;
constexpr size_t NX_REAPER_OID = 168;
constexpr size_t NX_MAX_FILE_SYSTEMS = 180;
constexpr size_t NX_FS_OID = 184; // u64[100]
constexpr size_t NX_FS_OID_COUNT = 100;

// nx_incompatible_features: the container spans two devices (Fusion), so block
// addresses with the tier-2 marker bit refer to the slow disk.
constexpr uint64_t NX_INCOMPAT_FUSION = 0x0000000000000002ULL;
// A paddr with this bit set lives on the Fusion tier-2 (spinning) device.
constexpr uint64_t FUSION_TIER2_MARKER = 0x4000000000000000ULL;

// ---- apfs_superblock_t (APSB) field offsets ----
constexpr size_t APFS_MAGIC_OFF = 32;
constexpr size_t APFS_FS_INDEX = 36;
constexpr size_t APFS_FEATURES = 40;
constexpr size_t APFS_INCOMPAT_FEATURES = 56;
constexpr size_t APFS_OMAP_OID = 128;
constexpr size_t APFS_ROOT_TREE_OID = 136;
constexpr size_t APFS_EXTENTREF_TREE_OID = 144;
constexpr size_t APFS_SNAP_META_TREE_OID = 152;
constexpr size_t APFS_NUM_FILES = 184;
constexpr size_t APFS_NUM_DIRECTORIES = 192;
constexpr size_t APFS_VOL_UUID = 240;
constexpr size_t APFS_LAST_MOD_TIME = 256;
constexpr size_t APFS_FS_FLAGS = 264;
constexpr size_t APFS_FORMATTED_BY = 272; // apfs_modified_by_t: char[32] + u64 + u64
constexpr size_t APFS_VOLNAME = 704;      // char[256]
constexpr size_t APFS_ROLE = 964;         // u16

// apfs_fs_flags. When UNENCRYPTED is clear the volume is FileVault-encrypted
// and its file data (and metadata, unless ONEKEY) needs the keybag to read.
constexpr uint64_t APFS_FS_UNENCRYPTED = 0x00000001ULL;
constexpr uint64_t APFS_FS_ONEKEY = 0x00000004ULL;

// ---- btree_node_phys_t ----
constexpr size_t BTN_FLAGS = 32;       // u16
constexpr size_t BTN_LEVEL = 34;       // u16  0 = leaf
constexpr size_t BTN_NKEYS = 36;       // u32
constexpr size_t BTN_TABLE_SPACE = 40; // nloc_t {u16 off; u16 len}
constexpr size_t BTN_DATA = 56;        // start of the table/key/value area
constexpr size_t BTREE_INFO_SIZE = 40; // btree_info_t, present only in a root node

constexpr uint16_t BTNODE_ROOT = 0x0001;
constexpr uint16_t BTNODE_LEAF = 0x0002;
constexpr uint16_t BTNODE_FIXED_KV_SIZE = 0x0004;

// ---- j_key_t object types, held in the top 4 bits of obj_id_and_type ----
constexpr uint64_t OBJ_ID_MASK = 0x0FFFFFFFFFFFFFFFULL;
constexpr int OBJ_TYPE_SHIFT = 60;

constexpr uint8_t APFS_TYPE_SNAP_METADATA = 1;
constexpr uint8_t APFS_TYPE_EXTENT = 2;
constexpr uint8_t APFS_TYPE_INODE = 3;
constexpr uint8_t APFS_TYPE_XATTR = 4;
constexpr uint8_t APFS_TYPE_SIBLING_LINK = 5;
constexpr uint8_t APFS_TYPE_DSTREAM_ID = 6;
constexpr uint8_t APFS_TYPE_CRYPTO_STATE = 7;
constexpr uint8_t APFS_TYPE_FILE_EXTENT = 8;
constexpr uint8_t APFS_TYPE_DIR_REC = 9;
constexpr uint8_t APFS_TYPE_DIR_STATS = 10;
constexpr uint8_t APFS_TYPE_SNAP_NAME = 11;
constexpr uint8_t APFS_TYPE_SIBLING_MAP = 12;

// The root directory's inode number. 1 is the private-dir root, 2 is "/".
constexpr uint64_t ROOT_DIR_INO_NUM = 2;

// Inode extended-field types (x_field_t x_type).
constexpr uint8_t INO_EXT_TYPE_NAME = 4;
constexpr uint8_t INO_EXT_TYPE_DSTREAM = 8;

// j_drec_val_t flags: low 4 bits are the DT_* file type.
constexpr uint16_t DREC_TYPE_MASK = 0x000F;
constexpr uint16_t DT_DIR = 4;
constexpr uint16_t DT_REG = 8;
constexpr uint16_t DT_LNK = 10;

// mode_t bits, for classifying an inode when a dir record is missing.
constexpr uint16_t S_IFMT_ = 0xF000;
constexpr uint16_t S_IFDIR_ = 0x4000;
constexpr uint16_t S_IFREG_ = 0x8000;

// APFS timestamps are nanoseconds since the Unix epoch already, which is
// exactly what FsTimes wants - no conversion needed, unlike NTFS/HFS.

// Fletcher-64 as APFS uses it. `data` must be 4-byte aligned in length.
uint64_t fletcher64(const uint8_t* data, size_t len, uint64_t init = 0);

// Verify a metadata block against its stored o_cksum. A false result means the
// block is stale, torn, or (very commonly when assembling a RAID by hand) that
// we are reading the wrong bytes entirely - which is precisely how the RAID
// geometry prober scores candidate layouts.
bool verifyBlock(const uint8_t* block, size_t size);

// Compute the o_cksum value a block should carry (used by tests and tooling).
uint64_t computeChecksum(const uint8_t* block, size_t size);

} // namespace de::apfs

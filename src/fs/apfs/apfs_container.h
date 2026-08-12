#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "core/image_source.h"
#include "fs/apfs/apfs_types.h"

namespace de::apfs {

// Block-level reader for a container. Handles the block size and, for a Fusion
// container, routes addresses carrying the tier-2 marker bit to the second
// device - so every layer above (B-trees, extents) just asks for a paddr and
// never has to know the container spans two disks.
class BlockReader {
public:
    BlockReader(std::shared_ptr<ImageSource> main,
                std::shared_ptr<ImageSource> tier2, uint32_t blockSize)
        : main_(std::move(main)), tier2_(std::move(tier2)), blockSize_(blockSize) {}

    uint32_t blockSize() const { return blockSize_; }
    bool hasTier2() const { return tier2_ != nullptr; }

    // Read `count` consecutive blocks starting at `paddr`. A short read past
    // the end of the device is zero-filled rather than throwing, so a truncated
    // image still browses as far as its data goes.
    std::vector<uint8_t> read(uint64_t paddr, uint32_t count = 1) const;

    // Read raw bytes at a block-relative address, used by the extent reader to
    // stream large files without materialising whole blocks.
    size_t readBytes(uint64_t paddr, uint64_t byteOffInBlockRun, void* buf,
                     size_t len) const;

    uint64_t deviceSize() const { return main_->size(); }

private:
    // Split a paddr into (device, block index within that device).
    ImageSource* deviceFor(uint64_t& paddr) const;

    std::shared_ptr<ImageSource> main_;
    std::shared_ptr<ImageSource> tier2_;
    uint32_t blockSize_;
};

// One entry in a B-tree node: pointers into the node's own buffer.
struct BTreeEntry {
    const uint8_t* key = nullptr;
    size_t keyLen = 0;
    const uint8_t* val = nullptr;
    size_t valLen = 0;
};

// A parsed B-tree node. Holds its block, so entry pointers stay valid.
class BTreeNode {
public:
    static std::optional<BTreeNode> parse(std::vector<uint8_t> block);

    bool isLeaf() const { return (flags_ & BTNODE_LEAF) != 0; }
    uint16_t level() const { return level_; }
    uint32_t count() const { return nkeys_; }
    bool checksumOk() const { return checksumOk_; }

    // Entry `i`, or an empty entry if the node's tables are inconsistent.
    BTreeEntry entry(uint32_t i) const;

    // Fixed-layout nodes store only offsets, so the key/value widths come from
    // the tree's btree_info_t (which lives in the root node alone).
    void setFixedSizes(uint32_t keySize, uint32_t valSize) {
        fixedKeySize_ = keySize;
        fixedValSize_ = valSize;
    }

private:
    std::vector<uint8_t> block_;
    uint16_t flags_ = 0, level_ = 0;
    uint32_t nkeys_ = 0;
    size_t keyBase_ = 0; // absolute offset of the key area
    size_t valEnd_ = 0;  // values are addressed backwards from here
    size_t tocOff_ = 0, tocLen_ = 0;
    bool fixed_ = false;
    bool checksumOk_ = false;
    uint32_t fixedKeySize_ = 16; // omap defaults; overwritten from btree_info
    uint32_t fixedValSize_ = 16;
};

// A B-tree, walked read-only. `resolve` turns a child node's object id into a
// block address: identity for a physical tree (the container object map), and
// an object-map lookup for a virtual one (a volume's filesystem tree).
class BTree {
public:
    using Resolve = std::function<uint64_t(uint64_t oid)>; // 0 => unresolvable
    // Compare a stored key against the search target: <0 if the stored key
    // sorts before the target, 0 if equal, >0 if after.
    using Compare = std::function<int(const uint8_t* key, size_t keyLen)>;

    BTree(const BlockReader& br, uint64_t rootPaddr, Resolve resolve)
        : br_(&br), rootPaddr_(rootPaddr), resolve_(std::move(resolve)) {}

    // A position in the tree that can step forward through leaf entries in key
    // order. Holds the path from the root, since APFS nodes have no sibling
    // pointers.
    class Cursor {
    public:
        bool valid() const { return valid_; }
        const BTreeEntry& entry() const { return entry_; }
        bool next();

    private:
        friend class BTree;
        struct Level {
            std::shared_ptr<BTreeNode> node;
            uint32_t index = 0;
        };
        const BTree* tree_ = nullptr;
        std::vector<Level> path_;
        BTreeEntry entry_;
        bool valid_ = false;
        // Descend from path_.back() to the leftmost leaf entry.
        bool descend();
        void load();
    };

    // First entry whose key does not sort before the target.
    Cursor lowerBound(const Compare& cmp) const;
    // First entry in the whole tree.
    Cursor first() const;

    // True if the root block reads back as a plausible, checksum-clean node.
    bool valid() const;

private:
    std::shared_ptr<BTreeNode> nodeAt(uint64_t paddr) const;
    // Pull the fixed key/value widths out of the root node's btree_info_t.
    void loadRootInfo() const;

    const BlockReader* br_;
    uint64_t rootPaddr_;
    Resolve resolve_;
    mutable bool rootLoaded_ = false;
    mutable uint32_t fixedKeySize_ = 16;
    mutable uint32_t fixedValSize_ = 16;
};

// The container object map: (oid, xid) -> block address, used to find the
// current copy of every virtual object (volume superblocks, filesystem trees).
class Omap {
public:
    Omap(const BlockReader& br, uint64_t omapPaddr);

    bool ok() const { return ok_; }
    // Newest mapping for `oid` no newer than `maxXid`.
    std::optional<uint64_t> lookup(uint64_t oid, uint64_t maxXid) const;

private:
    const BlockReader* br_;
    uint64_t treePaddr_ = 0;
    bool ok_ = false;
};

// A volume (APSB) inside the container, as shown in the tree before mounting.
struct VolumeInfo {
    uint32_t index = 0;       // slot in nx_fs_oid
    uint64_t apsbOid = 0;     // virtual oid of the volume superblock
    uint64_t apsbPaddr = 0;   // where the current copy lives
    std::string name;         // apfs_volname
    std::string role;         // "System", "Data", "Preboot", ...
    bool encrypted = false;   // FileVault: needs the keybag to read file data
    uint64_t rootTreeOid = 0; // virtual oid of the filesystem tree
    uint64_t omapOid = 0;     // physical oid of the volume's object map
    uint64_t numFiles = 0;
    uint64_t numDirectories = 0;
    int64_t lastModTime = 0; // ns since the epoch
    std::string formattedBy;
};

// An opened APFS container: the newest valid checkpoint superblock, its object
// map, and the list of volumes it holds.
class Container {
public:
    // Open the container at the start of `main`. `tier2`, when given, is the
    // second half of a Fusion pair. Returns nullptr if this is not an APFS
    // container; `why` receives a human-readable reason.
    static std::shared_ptr<Container> open(std::shared_ptr<ImageSource> main,
                                           std::shared_ptr<ImageSource> tier2 = nullptr,
                                           std::string* why = nullptr);

    // Cheap check: is there an NXSB at block 0?
    static bool probe(ImageSource& src);

    const std::vector<VolumeInfo>& volumes() const { return volumes_; }
    const BlockReader& reader() const { return *br_; }
    const Omap& omap() const { return *omap_; }
    uint64_t xid() const { return xid_; }
    uint32_t blockSize() const { return br_->blockSize(); }
    uint64_t blockCount() const { return blockCount_; }
    bool fusion() const { return fusion_; }
    // Notes worth showing the user: recovered-from-an-older-checkpoint,
    // checksum failures, a Fusion container opened without its second disk.
    const std::vector<std::string>& notes() const { return notes_; }

private:
    std::shared_ptr<BlockReader> br_;
    std::shared_ptr<Omap> omap_;
    std::vector<VolumeInfo> volumes_;
    std::vector<std::string> notes_;
    uint64_t xid_ = 0;
    uint64_t blockCount_ = 0;
    bool fusion_ = false;
};

} // namespace de::apfs

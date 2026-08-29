#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include "fs/filesystem.h"

namespace de {

// HFS+ / HFSX (Mac OS Extended), read-only.
//
// This is the filesystem on most Mac external drives formatted before APFS -
// including the big multi-terabyte RAID volumes people keep photo archives on,
// which is what it was written for. Everything is big-endian.
//
// Unlike the classic-HFS reader next door, nothing is loaded up front: the
// catalog on a 29 TB volume is far too large to hold in memory, so the catalog
// and extents B-trees are searched lazily, one node at a time, and files are
// streamed extent by extent. Opening a volume touches a handful of blocks
// regardless of how many million files it holds.
class HfsPlusFilesystem : public Filesystem {
public:
    // Returns nullptr if `vol` is not an HFS+/HFSX volume.
    static std::unique_ptr<HfsPlusFilesystem> open(std::shared_ptr<ImageSource> vol);
    static bool probe(ImageSource& vol);

    std::string typeName() const override { return typeName_; }
    FsNode root() override;
    std::vector<FsNode> listDir(const FsNode& dir) override;
    std::vector<uint8_t> readFile(const FsNode& file) override;
    bool readFileStream(const FsNode& file, const DataSink& sink) override;
    std::vector<uint8_t> readResourceFork(const FsNode& file) override;
    bool statNode(const FsNode& in, FsNode& out) override;
    FsTimes fileTimes(const FsNode& node) override;

    std::string volumeName() const { return volName_; }

    // What the volume header claims about itself. The RAID prober leans on
    // this: a volume that says how big it is and how many files it holds can
    // be checked against the disk it was found on, which is what catches a
    // plausible-looking but wrong reassembly.
    struct Stats {
        uint64_t sizeBytes = 0;
        uint32_t blockSize = 0;
        uint64_t totalBlocks = 0;
        uint64_t fileCount = 0;
        uint64_t folderCount = 0;
        bool cleanlyUnmounted = false;
        bool alternateHeaderMatches = false; // the copy at the end of the volume
    };
    const Stats& stats() const { return stats_; }
    // Things the user should know: an unclean unmount, unreadable areas,
    // files we could not decompress.
    std::vector<std::string> notes() const;

private:
    HfsPlusFilesystem() = default;

    // One run of allocation blocks.
    struct Extent {
        uint32_t startBlock = 0;
        uint32_t blockCount = 0;
    };

    // A fork (data or resource). `extents` starts with the eight held in the
    // catalog record and grows from the extents-overflow file on demand.
    struct Fork {
        uint64_t logicalSize = 0;
        uint32_t totalBlocks = 0;
        std::vector<Extent> extents;
        uint32_t cnid = 0;
        uint8_t forkType = 0; // 0 = data, 0xFF = resource
    };

    // What we keep about a catalog entry.
    struct Record {
        uint32_t cnid = 0;
        uint32_t parentId = 0;
        std::string name;
        bool isDir = false;
        FsTimes times;
        uint16_t mode = 0;
        Fork data;
        Fork rsrc;
        uint32_t valence = 0;
        std::string typeCode;    // 4-char Mac type ('hlnk' marks a hard link)
        std::string creatorCode;
        uint32_t linkTarget = 0; // hard link: the iNode number
    };

    // A B-tree living in a fork (catalog, extents overflow, attributes).
    class BTree {
    public:
        // <0 if the stored key sorts before the target, >0 after. Our searches
        // never need equality: each one seeks the start of a group of records
        // that share a leading field, then scans forward.
        using Compare = std::function<int(const uint8_t* key, size_t keyLen)>;

        struct Rec {
            const uint8_t* key = nullptr;
            size_t keyLen = 0;
            const uint8_t* val = nullptr;
            size_t valLen = 0;
        };

        class Cursor {
        public:
            bool valid() const { return valid_; }
            const Rec& rec() const { return rec_; }
            bool next();

        private:
            friend class BTree;
            const BTree* tree_ = nullptr;
            Rec rec_;
            std::vector<uint8_t> node_;
            uint32_t nodeNo_ = 0;
            uint16_t index_ = 0;
            uint16_t count_ = 0;
            bool valid_ = false;
            void load();
        };

        bool init(HfsPlusFilesystem* fs, Fork fork, const char* what);
        Cursor lowerBound(const Compare& cmp) const;
        bool ok() const { return ok_; }

        // Every record whose key begins with the 4-byte `lead` (a parent CNID
        // in the catalog, a CNID for a thread lookup), as raw record bytes.
        //
        // This is what the three catalog searches actually want, and unlike a
        // cursor walk it can be completed from the nodes themselves when the
        // leaf chain is broken. Returns records copied out of their nodes, so
        // the caller is not holding pointers into a buffer that has moved on.
        struct OwnedRec {
            std::vector<uint8_t> key;
            std::vector<uint8_t> val;
            Rec view() const { return Rec{key.data(), key.size(), val.data(), val.size()}; }
        };
        std::vector<OwnedRec> group(uint32_t lead) const;

        // How the last group() call was satisfied, for diagnostics.
        bool sweptForLastGroup() const { return swept_; }

        // Visit every record in every readable leaf node, in node order. Used
        // to build indexes that the tree's own links cannot be trusted for.
        void forEachRecord(const std::function<void(const Rec&)>& fn) const;

    private:
        std::vector<uint8_t> node(uint32_t nodeNo) const;
        static bool record(const std::vector<uint8_t>& node, uint16_t i,
                           uint16_t nodeSize, Rec& out);
        // A readable leaf node, or empty: an index is not a leaf, and neither
        // is an overwritten node claiming some other kind.
        std::vector<uint8_t> leafNode(uint32_t nodeNo) const;
        static void collectFrom(const std::vector<uint8_t>& node, uint16_t nodeSize,
                                uint32_t lead, std::vector<OwnedRec>& out);
        void buildNodeIndex() const;

        // One entry per readable leaf node: the leading key field of its first
        // and last record. A record with leading value V can only live in a
        // node whose span covers V, so this replaces the leaf chain as the way
        // to find a group.
        struct NodeSpan { uint32_t node; uint32_t first; uint32_t last; };

        HfsPlusFilesystem* fs_ = nullptr;
        Fork fork_;
        uint32_t rootNode_ = 0;
        uint16_t nodeSize_ = 4096;
        uint32_t totalNodes_ = 0;
        uint32_t firstLeaf_ = 0;
        bool ok_ = false;
        mutable std::vector<NodeSpan> index_;
        mutable bool indexBuilt_ = false;
        mutable bool swept_ = false;
        friend class Cursor;
    };

    // -- setup --
    bool mount();

    // -- fork I/O --
    // Extend `fork`'s extent list from the extents-overflow file until it
    // covers `neededBlocks` allocation blocks.
    void ensureExtents(Fork& fork, uint64_t neededBlocks) const;
    std::vector<uint8_t> readFork(const Fork& fork, uint64_t off, size_t len) const;
    bool streamFork(const Fork& fork, uint64_t size, const DataSink& sink);

    // -- catalog --
    std::optional<Record> recordByCnid(uint32_t cnid);
    // parent CNID -> CNIDs of folders that have a thread record. Folders whose
    // own catalog record was lost to damage exist only here, and a lost folder
    // takes its entire subtree out of the listing with it.
    void buildFolderThreadIndex();
    std::multimap<uint32_t, uint32_t> folderThreads_;
    bool folderThreadsBuilt_ = false;
    std::optional<Record> childByName(uint32_t parent, const std::string& name);
    static bool parseCatalogRecord(const BTree::Rec& r, Record& out);
    // Follow an HFS+ hard link to the inode it points at.
    std::optional<Record> resolveHardLink(const Record& rec);

    // -- attributes (extended attributes; where decmpfs data lives) --
    std::optional<std::vector<uint8_t>> readAttribute(uint32_t cnid,
                                                      const std::string& name);
    bool streamCompressed(const Record& rec, const DataSink& sink);

    void note(const std::string& msg);

    std::shared_ptr<ImageSource> vol_;
    Stats stats_;
    std::string typeName_ = "HFS+";
    std::string volName_;
    uint32_t blockSize_ = 4096;
    uint64_t totalBlocks_ = 0;
    BTree catalog_;
    BTree extentsTree_;
    BTree attributes_;
    Fork extentsFork_;
    uint32_t privateDirCnid_ = 0; // the hidden HFS+ Private Data folder

    // Catalog records seen while listing, so a later read does not have to
    // find them again. Bounded: a 29 TB volume can hold far more files than we
    // want to remember.
    mutable std::mutex cacheMutex_;
    std::map<uint32_t, Record> cache_;
    mutable std::mutex noteMutex_;
    std::vector<std::string> notes_;
};

} // namespace de

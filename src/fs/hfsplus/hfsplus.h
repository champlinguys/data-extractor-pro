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

    private:
        std::vector<uint8_t> node(uint32_t nodeNo) const;
        static bool record(const std::vector<uint8_t>& node, uint16_t i,
                           uint16_t nodeSize, Rec& out);

        HfsPlusFilesystem* fs_ = nullptr;
        Fork fork_;
        uint32_t rootNode_ = 0;
        uint16_t nodeSize_ = 4096;
        uint32_t totalNodes_ = 0;
        bool ok_ = false;
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

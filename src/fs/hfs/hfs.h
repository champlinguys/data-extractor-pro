#pragma once
#include "fs/filesystem.h"
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace de {

// Classic Macintosh HFS (the pre-HFS+ filesystem used on 1980s-1990s Mac
// floppies and small disks; volume signature "BD" at sector 2). Parses the
// Master Directory Block, reassembles the Catalog and Extents-Overflow
// B-trees by following their extent records, and walks the Catalog B-tree to
// enumerate the full directory tree. Read-only.
//
// Unlike NTFS (which locates records lazily by MFT record number), the whole
// catalog is parsed once at open() time into in-memory id->entry and
// parent->children maps: classic-HFS catalogs (floppies and small volumes)
// are small enough that this is simpler and matches the proven reference
// implementation this was ported from.
class HfsFilesystem : public Filesystem {
public:
    // Returns nullptr if `vol` is not a classic HFS volume.
    static std::unique_ptr<HfsFilesystem> open(std::shared_ptr<ImageSource> vol);

    std::string typeName() const override { return "HFS"; }
    FsNode root() override;
    std::vector<FsNode> listDir(const FsNode& dir) override;
    std::vector<uint8_t> readFile(const FsNode& file) override;
    std::vector<uint8_t> readResourceFork(const FsNode& file) override;

    // Quick, cheap check used by the detector.
    static bool probe(ImageSource& vol);

private:
    HfsFilesystem() = default;

    static constexpr int SECTOR = 512;
    static constexpr uint32_t ROOT_CNID = 2;

    // A classic-HFS extent: (startAllocationBlock, blockCount).
    struct Extent { uint32_t start; uint32_t count; };

    struct CatEntry {
        uint32_t cnid = 0;
        uint32_t parentId = 0;
        std::string name;
        bool isDir = false;
        std::string type;    // 4-char Mac type code (files only)
        std::string creator; // 4-char Mac creator code (files only)
        uint32_t dataLen = 0, rsrcLen = 0;
        std::vector<Extent> dataExtents, rsrcExtents;
        int32_t createDate = 0, modDate = 0; // HFS epoch (1904) seconds
        uint32_t valence = 0; // directories: number of children
    };

    // -- volume-level state, parsed once in _parseMdb/_loadSpecialFiles ------
    std::shared_ptr<ImageSource> vol_;
    uint64_t volSize_ = 0;
    std::string volName_;
    uint32_t ablkSize_ = 0;      // drAlBlkSiz
    uint32_t alBlSt_ = 0;        // drAlBlSt, in sectors
    uint32_t sectorsPerAblk_ = 0;

    uint32_t ctSize_ = 0;
    std::vector<Extent> ctExtents_;
    uint32_t xtSize_ = 0;
    std::vector<Extent> xtExtents_;

    std::vector<uint8_t> catalogFile_;  // reassembled Catalog B-tree file
    std::vector<uint8_t> extentsFile_;  // reassembled Extents-Overflow B-tree file

    std::map<uint32_t, CatEntry> entries_;                    // cnid -> entry
    std::map<uint32_t, std::vector<uint32_t>> children_;      // parent cnid -> child cnids

    // -- setup ----------------------------------------------------------------
    bool parseMdb();
    void loadSpecialFiles();
    void parseCatalog();

    // -- raw / extent helpers --------------------------------------------------
    std::vector<uint8_t> readAt(uint64_t off, size_t len) const;
    uint64_t ablkOffset(uint32_t ablk) const;
    std::vector<uint8_t> readExtents(const std::vector<Extent>& extents, size_t length) const;
    static std::vector<Extent> parseExtentRecord(const uint8_t* p);

    // -- generic classic-HFS B-tree node walking -------------------------------
    // Yields (key, data) for every leaf record in `file`, in key order.
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        leafRecords(const std::vector<uint8_t>& file) const;

    // -- extents-overflow lookup ------------------------------------------------
    std::vector<Extent> overflowExtents(uint32_t cnid, uint8_t forkType, uint32_t startBlock) const;
    std::vector<Extent> forkExtents(uint32_t cnid, uint8_t forkType,
                                     const std::vector<Extent>& baseExtents, uint32_t logicalLen) const;

    // -- catalog record decoding -------------------------------------------------
    static std::string macRomanToUtf8(const uint8_t* p, size_t len);

    FsNode toFsNode(const CatEntry& e) const;
    const CatEntry* findEntry(uint32_t cnid) const;
};

} // namespace de

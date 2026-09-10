#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include "fs/filesystem.h"

namespace de {

// FAT12/16/32, read-only.
//
// The filesystem every drive shipped with before exFAT existed, and still what
// you find on cameras, car stereos, BIOS boot partitions, and any external disk
// that was formatted once in 2006 and never touched again. Those old volumes
// are exactly the ones that end up on this tool.
//
// Structurally it is exFAT's older sibling and the parser is shaped the same
// way: a FAT of cluster pointers (32-bit, really 28-bit, on FAT32; 16-bit on
// FAT16; packed 12-bit on FAT12), and directories made of 32-byte entries.
// Nothing is held in memory but the boot parameters and the volume label, so a
// 2 TB volume opens as fast as a 2 GB one.
//
// FAT12 and FAT16 are the same on-disk shape as FAT32 minus two things: the
// cluster pointers are narrower, and the root directory is not a cluster chain
// but a fixed-size region sitting between the FATs and the data area (no root
// cluster, no FSInfo, no backup boot sector - none of those fields exist in a
// pre-FAT32 BPB). fatBits_ selects the pointer width at mount, and root()/
// listDir()/readVolumeMetadata() branch on whether the root has a cluster
// (FAT32) or a fixed byte range (FAT12/16); everywhere else - the FAT walk via
// fatNext(), subdirectory scanning, file reads - is identical across all three.
//
// The differences from exFAT that actually matter to a reader:
//   - Names live in *two* places. Every file has a legacy 8.3 short name in its
//     directory entry, optionally preceded by a chain of VFAT long-name entries
//     holding the real UTF-16 name in reverse order.
//   - There is no entry-set checksum. The one integrity check available is the
//     byte in each long-name entry that checksums the short name it belongs to,
//     and this parser leans on it hard - it is what ties a salvaged long name to
//     the right file instead of to the debris next to it.
//   - Timestamps are local time with no recorded UTC offset, so they cannot be
//     converted exactly. See fatTimeToUnixNs.
//   - Short names are in an OEM codepage, not Unicode. CP437 is assumed.
//
// Recovery-oriented extras beyond a plain reader:
//   - Deleted entries (short name overwritten with 0xE5) are listed and marked,
//     both in place and where they linger past the end-of-directory marker.
//     Their long names are reassembled from the surrounding 0xE5 long-name
//     entries whenever the short-name checksum still vouches for them, which is
//     what recovers "Wedding Photos 2004.jpg" instead of "WEDDIN~1.JPG".
//   - Deleting a file frees its cluster chain, so for deleted entries the FAT is
//     deliberately *not* consulted - it now describes whatever was allocated
//     next - and the data is read contiguously from the first cluster instead.
//     That is the standard guess and recovers any file that was not fragmented.
//   - The backup boot sector (BPB_BkBootSec, normally sector 6) is used when the
//     primary VBR is unreadable or its geometry does not add up.
class FatFilesystem : public Filesystem {
public:
    // Returns nullptr if `vol` is not a FAT32 volume.
    static std::unique_ptr<FatFilesystem> open(std::shared_ptr<ImageSource> vol);
    static bool probe(ImageSource& vol);
    // Cheap label for a FAT volume without mounting it: 12, 16, or 32, or 0 if
    // `vol` is not a FAT volume at all. What detectFilesystemName() uses to
    // pick "FAT12"/"FAT16"/"FAT32" without paying for a full mount.
    static int probedFatBits(ImageSource& vol);

    std::string typeName() const override {
        switch (fatBits_) {
            case 12: return "FAT12";
            case 16: return "FAT16";
            default: return "FAT32";
        }
    }
    FsNode root() override;
    std::vector<FsNode> listDir(const FsNode& dir) override;
    std::vector<uint8_t> readFile(const FsNode& file) override;
    bool readFileStream(const FsNode& file, const DataSink& sink) override;
    FsTimes fileTimes(const FsNode& node) override;
    // FAT node ids are directory-entry offsets, so a cycle shows up as
    // distinct ids pointing at one cluster. Identity has to be the cluster.
    uint64_t dirIdentity(const FsNode& dir) override;

    std::string volumeName() const { return volName_; }

    // What the boot sector and FSInfo say about the volume. Mirrors
    // ExfatFilesystem::Stats so the RAID prober and the volume-info panes can
    // treat the two the same way.
    struct Stats {
        uint64_t sizeBytes = 0;
        uint32_t bytesPerSector = 512;
        uint32_t clusterSize = 0;
        uint64_t clusterCount = 0;
        uint64_t usedClusters = 0;   // derived from FSInfo; advisory only
        uint8_t  fatCount = 1;
        uint8_t  fatBits = 32;       // 12, 16, or 32
        bool volumeDirty = false;    // clean-shutdown bit cleared in FAT[1]; FAT12 has none
        bool mediaFailure = false;   // hard-error bit cleared in FAT[1]; FAT12 has none
        bool usedBackupBootRegion = false;
    };
    const Stats& stats() const { return stats_; }

    // Things the user should know: an unclean unmount, a damaged primary VBR,
    // directory entries we had to reject, timestamps we could not localise.
    std::vector<std::string> notes() const;

private:
    FatFilesystem() = default;

    // One directory entry, flattened into what the rest of the tool needs.
    // For a file with long-name entries this is the short entry plus the
    // reassembled name; there is no other state to carry.
    struct Record {
        uint64_t entryOffset = 0;  // volume byte offset of the 8.3 entry
        std::string name;
        bool isDir = false;
        bool isDeleted = false;
        uint64_t size = 0;
        uint32_t firstCluster = 0;
        // Read the clusters consecutively instead of following the FAT. Set for
        // deleted records, whose chain has been freed and may now belong to
        // another file.
        bool contiguous = false;
        FsTimes times;
    };

    bool mount(bool fromBackup);
    // Volume label and free-space count, from the root directory and FSInfo.
    void readVolumeMetadata(uint32_t fsInfoSector);

    // -- geometry --
    uint64_t clusterToOffset(uint32_t cluster) const;
    bool validCluster(uint32_t cluster) const;

    // -- FAT --
    // Read `n` bytes (1-4) at `byteOffset` within the FAT through the block
    // cache, or nullopt if that range is unreadable or out of bounds. A FAT12
    // entry can straddle a cache block boundary (the block size is a power of
    // two, an entry is 1.5 bytes); that one case falls back to reading the
    // volume directly instead of complicating the cache.
    std::optional<uint32_t> fatReadRaw(uint64_t byteOffset, size_t n) const;
    // Next cluster in the chain, or 0 if the chain ends / the cluster is free /
    // the entry is unusable. Normalises FAT12/16's narrower special values
    // (bad cluster, end-of-chain) to the FAT32 sentinels chainExtents already
    // checks for, so everything downstream of this is width-agnostic.
    uint32_t fatNext(uint32_t cluster) const;
    // Walk `firstCluster` into coalesced byte extents covering `bytes`, using
    // the FAT unless `contiguous` says to read straight through.
    struct Extent { uint64_t off; uint64_t len; };
    std::vector<Extent> chainExtents(uint32_t firstCluster, bool contiguous,
                                     uint64_t bytes) const;

    // -- directory entries --
    // Re-read the 8.3 entry an FsNode id points at. The long name is not
    // recovered here: it lives in the entries *before* this one and is only
    // needed while listing, which scanDirectory does in one forward pass.
    std::optional<Record> recordAt(uint64_t entryOffset) const;
    // Walk a directory's clusters, including anything salvageable past the
    // end-of-directory marker. `contiguous` selects the deleted-directory walk,
    // which has no chain to follow and so stops on the first cluster that does
    // not look like directory entries. `labelOut`, when non-null, receives the
    // volume label entry's name (root directory only).
    std::vector<Record> scanDirectory(uint32_t firstCluster, bool contiguous,
                                      std::string* labelOut);
    // FAT12/16 root: not a cluster chain, just a fixed byte range between the
    // FATs and the data area. Reads it in one shot and runs it through the
    // same per-entry logic as scanDirectory via scanEntries.
    std::vector<Record> scanFixedRoot(std::string* labelOut);
    // The per-entry body scanDirectory and scanFixedRoot both need: walk one
    // buffer's worth of 32-byte directory entries, accumulating long-name
    // fragments and appending finished Records to `out`. `lfn`, `pastEnd`, and
    // `rejected` are the caller's running state, carried across calls so a
    // long-name run can straddle a cluster boundary.
    void scanEntries(const uint8_t* buf, size_t len, uint64_t chunkBase,
                     std::vector<std::array<uint8_t, 32>>& lfn, bool& pastEnd,
                     size_t& rejected, std::string* labelOut,
                     std::vector<Record>& out);

    bool streamRecord(const Record& rec, const DataSink& sink);
    void note(const std::string& msg) const;

    std::shared_ptr<ImageSource> vol_;
    Stats stats_;
    std::string volName_;

    int fatBits_ = 32;                 // 12, 16, or 32
    uint32_t bytesPerSector_ = 512;
    uint32_t clusterSize_ = 0;
    uint64_t fatByteOffset_ = 0;       // the active FAT
    uint64_t fatByteLength_ = 0;
    uint64_t dataByteOffset_ = 0;      // cluster 2 lives here
    uint32_t clusterCount_ = 0;
    uint32_t rootCluster_ = 0;         // FAT32 only
    uint64_t rootDirByteOffset_ = 0;   // FAT12/16 only: the fixed root region
    uint64_t rootDirBytes_ = 0;        // FAT12/16 only
    uint64_t volumeBytes_ = 0;

    // The active FAT, read in blocks: a multi-gigabyte file is thousands of
    // chain hops, and one pread per hop is what makes a naive reader crawl.
    mutable std::mutex fatMutex_;
    mutable std::vector<uint8_t> fatBlock_;
    mutable uint64_t fatBlockStart_ = 0;
    mutable bool fatBlockValid_ = false;

    mutable std::mutex noteMutex_;
    mutable std::vector<std::string> notes_;
};

} // namespace de

#pragma once
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include "fs/filesystem.h"

namespace de {

// exFAT (Microsoft Extended FAT), read-only.
//
// This is what almost every large removable drive ships with: external USB
// disks over 32 GB, SDXC cards, and anything that has to be readable on both
// Windows and macOS. It is a much simpler filesystem than the others here -
// there is no B-tree and no journal, just a FAT and directories made of 32-byte
// entry sets - which is exactly why deleted files survive on it so well.
//
// Nothing is held in memory except the boot parameters and the volume label:
// directories are walked a cluster at a time and files are streamed run by run,
// so a 1 TB volume opens as fast as a 1 GB one.
//
// Recovery-oriented extras beyond a plain reader:
//   - Deleted entry sets (the in-use bit cleared) are listed and marked, both
//     where they still sit among live entries and where they linger past the
//     end-of-directory marker; scavenged ones are accepted only if the entry
//     set checksum still validates, which is what keeps garbage out.
//   - The backup boot region at sector 12 is used when the primary VBR is
//     unreadable or damaged - common on the failing drives this tool exists for.
//   - A cluster chain that runs off into an invalid FAT entry falls back to
//     "assume contiguous", so a file with a partly-destroyed chain still
//     exports what it can instead of nothing.
class ExfatFilesystem : public Filesystem {
public:
    // Returns nullptr if `vol` is not an exFAT volume.
    static std::unique_ptr<ExfatFilesystem> open(std::shared_ptr<ImageSource> vol);
    static bool probe(ImageSource& vol);

    std::string typeName() const override { return "exFAT"; }
    FsNode root() override;
    std::vector<FsNode> listDir(const FsNode& dir) override;
    std::vector<uint8_t> readFile(const FsNode& file) override;
    bool readFileStream(const FsNode& file, const DataSink& sink) override;
    FsTimes fileTimes(const FsNode& node) override;

    std::string volumeName() const { return volName_; }

    // What the boot sector and allocation bitmap say about the volume. Mirrors
    // HfsPlusFilesystem::Stats so the RAID prober and the volume-info panes can
    // treat the two the same way.
    struct Stats {
        uint64_t sizeBytes = 0;
        uint32_t bytesPerSector = 512;
        uint32_t clusterSize = 0;
        uint64_t clusterCount = 0;
        uint64_t usedClusters = 0;   // popcount of the allocation bitmap
        uint8_t  fatCount = 1;
        bool volumeDirty = false;    // set when the volume was not unmounted
        bool mediaFailure = false;   // the driver hit unreadable sectors
        bool usedBackupBootRegion = false;
    };
    const Stats& stats() const { return stats_; }

    // Things the user should know: an unclean unmount, a damaged primary VBR,
    // directory entries we had to reject.
    std::vector<std::string> notes() const;

private:
    ExfatFilesystem() = default;

    // A directory entry set, flattened into what the rest of the tool needs.
    struct Record {
        uint64_t entryOffset = 0;  // volume byte offset of the primary entry
        std::string name;
        bool isDir = false;
        bool isDeleted = false;
        uint64_t size = 0;           // DataLength
        uint64_t validSize = 0;      // ValidDataLength
        uint32_t firstCluster = 0;
        bool noFatChain = false;     // contiguous; the FAT holds nothing for it
        FsTimes times;
    };

    bool mount(bool fromBackup);
    // Pull the volume label, and the allocation bitmap's location, out of the
    // root directory's special entry sets.
    void readRootMetadata();

    // -- geometry --
    uint64_t clusterToOffset(uint32_t cluster) const;
    bool validCluster(uint32_t cluster) const;

    // -- FAT --
    // Next cluster in the chain, or 0 if the chain ends / the entry is invalid.
    uint32_t fatNext(uint32_t cluster) const;
    // Walk `firstCluster` into coalesced byte extents covering `bytes`, using
    // the FAT unless `noFatChain` says the run is contiguous.
    struct Extent { uint64_t off; uint64_t len; };
    std::vector<Extent> chainExtents(uint32_t firstCluster, bool noFatChain,
                                     uint64_t bytes) const;

    // -- directory entries --
    // How to get from one cluster of a directory to the next. A directory with
    // the NoFatChain flag set is contiguous and its FAT entries are undefined -
    // possibly stale values left by whatever occupied those clusters before -
    // so following the FAT there would walk off into unrelated data.
    enum class Chain { UseFat, Contiguous };

    // Read `entries` 32-byte slots starting at volume offset `off`, crossing
    // cluster boundaries the way `chain` says to.
    std::vector<uint8_t> readEntries(uint64_t off, uint32_t entries,
                                     Chain chain = Chain::UseFat) const;
    // Parse one entry set. `raw` must hold the primary entry plus its
    // secondaries. Returns nullopt if the set is malformed.
    std::optional<Record> parseEntrySet(const std::vector<uint8_t>& raw,
                                        uint64_t entryOffset) const;
    // Re-read the entry set an FsNode id points at.
    std::optional<Record> recordAt(uint64_t entryOffset) const;
    // Enumerate a directory's clusters, including anything salvageable past
    // the end-of-directory marker. `sizeBytes` is the directory's DataLength;
    // pass 0 when it is unknown (the root has no directory entry of its own),
    // in which case the FAT chain is what says where the directory ends.
    std::vector<Record> scanDirectory(uint32_t firstCluster, bool noFatChain,
                                      uint64_t sizeBytes, bool wantSpecials,
                                      std::vector<std::vector<uint8_t>>* specials);

    bool streamRecord(const Record& rec, const DataSink& sink);
    void note(const std::string& msg) const;

    std::shared_ptr<ImageSource> vol_;
    Stats stats_;
    std::string volName_;

    uint32_t bytesPerSector_ = 512;
    uint32_t clusterSize_ = 0;
    uint64_t fatByteOffset_ = 0;       // the active FAT
    uint64_t fatByteLength_ = 0;
    uint64_t heapByteOffset_ = 0;      // cluster 2 lives here
    uint32_t clusterCount_ = 0;
    uint32_t rootCluster_ = 0;
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

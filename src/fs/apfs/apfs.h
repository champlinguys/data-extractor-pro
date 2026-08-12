#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include "fs/apfs/apfs_container.h"
#include "fs/filesystem.h"

namespace de {

// APFS, read-only.
//
// An APFS *container* holds several *volumes* (on a Mac: "Macintosh HD",
// "Macintosh HD - Data", Preboot, Recovery, VM) that share one pool of blocks,
// so unlike NTFS or HFS there is no single root to hand back. We present a
// synthetic root whose children are the volumes; below that, each volume's own
// directory tree. The GUI's checkbox export and the CLI's recursive extract
// then work unchanged, which is the point: you can tick one folder inside one
// volume and pull just that out.
//
// Node ids pack the volume in the top byte so a single 64-bit id still
// round-trips through the existing tree/export code:
//     id 0                     = the container itself
//     (volume+1) << 56 | oid   = object `oid` inside that volume
class ApfsFilesystem : public Filesystem {
public:
    // Mount the container at the start of `vol`. `tier2` is the second device
    // of a Fusion pair, if there is one. Returns nullptr if this is not APFS.
    static std::unique_ptr<ApfsFilesystem> open(std::shared_ptr<ImageSource> vol,
                                                std::shared_ptr<ImageSource> tier2 = nullptr);
    static bool probe(ImageSource& vol);

    std::string typeName() const override;
    FsNode root() override;
    std::vector<FsNode> listDir(const FsNode& dir) override;
    std::vector<uint8_t> readFile(const FsNode& file) override;
    bool readFileStream(const FsNode& file, const DataSink& sink) override;
    std::vector<uint8_t> readResourceFork(const FsNode& file) override;
    FsTimes fileTimes(const FsNode& node) override;

    // Volumes in the container, for the UI and for `de-cli`'s listing.
    const std::vector<apfs::VolumeInfo>& volumes() const { return container_->volumes(); }
    // Anything the user should know: stale checkpoints, a missing Fusion disk,
    // encrypted volumes, files we could not decompress.
    std::vector<std::string> notes() const;

private:
    // Everything needed to walk one volume's filesystem tree.
    struct Volume {
        apfs::VolumeInfo info;
        std::shared_ptr<apfs::Omap> omap;
        std::shared_ptr<apfs::BTree> tree;
        bool ok = false;
    };

    struct Dstream {
        uint64_t size = 0;
        uint64_t allocedSize = 0;
    };

    struct Inode {
        uint64_t oid = 0;
        uint64_t parentId = 0;
        uint64_t privateId = 0; // the id file extents are keyed by
        FsTimes times;
        uint16_t mode = 0;
        uint64_t internalFlags = 0;
        uint64_t uncompressedSize = 0; // set when the file is decmpfs-compressed
        std::optional<Dstream> dstream;
        std::string name;
    };

    struct Extent {
        uint64_t logical = 0;
        uint64_t length = 0;
        uint64_t physBlock = 0; // 0 = sparse hole
    };

    Volume* volumeFor(uint64_t nodeId);
    static uint32_t volIndexOf(uint64_t nodeId) { return static_cast<uint32_t>(nodeId >> 56); }
    static uint64_t oidOf(uint64_t nodeId) { return nodeId & 0x00FFFFFFFFFFFFFFULL; }
    static uint64_t makeId(uint32_t volIndex, uint64_t oid) {
        return (static_cast<uint64_t>(volIndex + 1) << 56) | oid;
    }

    std::optional<Inode> findInode(Volume& v, uint64_t oid);
    std::vector<Extent> extentsFor(Volume& v, uint64_t streamId);
    std::optional<std::vector<uint8_t>> readXattr(Volume& v, uint64_t oid,
                                                  const std::string& name);
    // Stream a data stream (file fork or attribute fork) to the sink.
    bool streamExtents(Volume& v, uint64_t streamId, uint64_t size,
                       const DataSink& sink);
    // Size of a compressed file, from its decmpfs header.
    uint64_t compressedSize(Volume& v, uint64_t oid);
    void note(const std::string& msg);

    std::shared_ptr<apfs::Container> container_;
    std::vector<Volume> volumes_;
    mutable std::mutex noteMutex_;
    std::vector<std::string> notes_;
};

} // namespace de

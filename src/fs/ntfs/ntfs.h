#pragma once
#include "fs/filesystem.h"
#include <memory>
#include <vector>

namespace de {

// NTFS reader. Parses the boot sector, reads MFT records (applying fixups),
// decodes attributes and non-resident data runs, and walks directory B-trees
// ($INDEX_ROOT + $INDEX_ALLOCATION) to enumerate children.
//
// Scope of this first milestone: read-only browse + export of the default data
// stream. Named/alternate data streams, compressed/sparse/encrypted streams,
// and deleted-record scavenging are follow-ups (hooks are noted in the .cpp).
class NtfsFilesystem : public Filesystem {
public:
    // Returns nullptr if `vol` is not an NTFS volume.
    static std::unique_ptr<NtfsFilesystem> open(std::shared_ptr<ImageSource> vol);

    std::string typeName() const override { return "NTFS"; }
    FsNode root() override;
    std::vector<FsNode> listDir(const FsNode& dir) override;
    std::vector<uint8_t> readFile(const FsNode& file) override;
    bool readFileStream(const FsNode& file, const DataSink& sink) override;

    // Quick, cheap check used by the detector.
    static bool probe(ImageSource& vol);

private:
    NtfsFilesystem() = default;

    struct Extent { uint64_t startByte; uint64_t lengthByte; bool sparse; };

    // Read and fixup MFT record `recno` into a buffer. Empty on failure.
    std::vector<uint8_t> readMftRecord(uint64_t recno);

    // Full value of an attribute (resident inline, or read from its runs).
    std::vector<uint8_t> attrValue(const uint8_t* attr);

    // All attributes for a base record, following any $ATTRIBUTE_LIST to pull
    // in attributes stored in extension MFT records (each returned as a copy).
    std::vector<std::vector<uint8_t>> collectAttributes(
        const std::vector<uint8_t>& baseRec, uint64_t baseRecNo);

    // Decode a non-resident attribute's run list into byte extents.
    std::vector<Extent> decodeRuns(const uint8_t* runlist, size_t maxLen,
                                   uint64_t allocSize);

    std::shared_ptr<ImageSource> vol_;
    uint32_t bytesPerSector_ = 512;
    uint32_t clusterSize_ = 4096;
    uint32_t mftRecordSize_ = 1024;
    uint64_t mftByteOffset_ = 0;   // byte offset of the MFT itself
    // Byte extents of the MFT's own $DATA, so records beyond the first cluster
    // are reachable even when the MFT is fragmented.
    std::vector<Extent> mftExtents_;
};

} // namespace de

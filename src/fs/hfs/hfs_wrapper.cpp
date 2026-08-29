#include "fs/hfs/hfs_wrapper.h"
#include "core/byte_reader.h"

namespace de::hfswrapper {

namespace {

constexpr uint64_t MDB_OFFSET = 1024;      // where an HFS+ volume header would be
constexpr uint16_t SIG_HFS = 0x4244;       // 'BD'  classic HFS
constexpr uint16_t SIG_HFSPLUS = 0x482B;   // 'H+'  the embedded volume

// Master Directory Block field offsets. drAlBlSt is counted in 512-byte units
// from the volume start, *not* in allocation blocks - the one field in here it
// is easy to get wrong, and getting it wrong lands a few kilobytes off the
// embedded header rather than obviously nowhere.
constexpr size_t DR_SIG_WORD = 0x00;
constexpr size_t DR_AL_BLK_SIZ = 0x14;
constexpr size_t DR_AL_BL_ST = 0x1C;
constexpr size_t DR_EMBED_SIG_WORD = 0x7C;
constexpr size_t DR_EMBED_EXTENT = 0x7E;
constexpr size_t MDB_BYTES = 0x82;         // through the end of drEmbedExtent

} // namespace

std::optional<Embedded> find(ImageSource& vol) {
    uint8_t mdb[512] = {};
    if (vol.readAt(MDB_OFFSET, mdb, sizeof mdb) < MDB_BYTES) return std::nullopt;
    if (rdBE16(mdb + DR_SIG_WORD) != SIG_HFS) return std::nullopt;
    if (rdBE16(mdb + DR_EMBED_SIG_WORD) != SIG_HFSPLUS) return std::nullopt;

    uint32_t blockSize = rdBE32(mdb + DR_AL_BLK_SIZ);
    uint64_t firstBlock = rdBE16(mdb + DR_AL_BL_ST);
    uint64_t startBlock = rdBE16(mdb + DR_EMBED_EXTENT);
    uint64_t blockCount = rdBE16(mdb + DR_EMBED_EXTENT + 2);

    // An HFS allocation block is a non-zero multiple of 512, and an embedded
    // volume spanning no blocks is a corrupt pointer rather than a volume.
    if (blockSize == 0 || blockSize % 512 || blockCount == 0) return std::nullopt;

    Embedded e;
    e.offset = firstBlock * 512 + startBlock * blockSize;
    e.length = blockCount * blockSize;
    if (e.offset >= vol.size()) return std::nullopt;
    // A wrapper on a truncated or partially recovered image can describe more
    // than is present; clamp rather than hand out a source that reads past the
    // end of what we have.
    if (e.offset + e.length > vol.size()) e.length = vol.size() - e.offset;
    return e;
}

std::shared_ptr<ImageSource> open(const std::shared_ptr<ImageSource>& vol) {
    if (!vol) return nullptr;
    auto e = find(*vol);
    if (!e) return nullptr;
    return std::make_shared<SubImageSource>(vol, e->offset, e->length,
                                            "embedded HFS+ volume");
}

} // namespace de::hfswrapper

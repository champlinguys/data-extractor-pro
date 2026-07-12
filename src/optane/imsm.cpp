#include "optane/imsm.h"
#include "core/byte_reader.h"
#include <cstring>

namespace de::optane {

namespace {
constexpr char IMSM_SIG[] = "Intel Raid ISM Cfg Sig.";
constexpr size_t IMSM_SIG_LEN = sizeof(IMSM_SIG) - 1;
// The IMSM super sits 0x1E00 into the Intel Cache region, just after the
// NV Cache Cfg header (see FORMAT_NOTES.md).
constexpr uint64_t IMSM_OFFSET_IN_REGION = 0x1E00;

// Find the byte offset of the IMSM signature. If `hintRegion` points at the
// cache region, check there first; otherwise scan the device in large windows.
std::optional<uint64_t> findImsm(ImageSource& img, uint64_t hintRegion) {
    if (hintRegion != UINT64_MAX) {
        auto probe = img.read(hintRegion + IMSM_OFFSET_IN_REGION, IMSM_SIG_LEN);
        if (std::memcmp(probe.data(), IMSM_SIG, IMSM_SIG_LEN) == 0)
            return hintRegion + IMSM_OFFSET_IN_REGION;
    }
    // Fallback: sequential scan (slow on a full 27 GB device - prefer the hint).
    const size_t win = 16 * 1024 * 1024;
    const size_t overlap = IMSM_SIG_LEN;
    std::vector<uint8_t> buf;
    for (uint64_t base = 0; base < img.size(); base += win - overlap) {
        buf = img.read(base, win);
        for (size_t i = 0; i + IMSM_SIG_LEN <= buf.size(); ++i)
            if (std::memcmp(&buf[i], IMSM_SIG, IMSM_SIG_LEN) == 0)
                return base + i;
    }
    return std::nullopt;
}
} // namespace

std::optional<ImsmMetadata> parseImsm(ImageSource& optane, uint64_t hintCacheOffset) {
    auto sigOff = findImsm(optane, hintCacheOffset);
    if (!sigOff) return std::nullopt;

    auto sb = optane.read(*sigOff, 4096); // the super plus disk/dev arrays
    de::Span s{sb.data(), sb.size()};

    ImsmMetadata m;
    m.cacheRegionOffset = *sigOff - IMSM_OFFSET_IN_REGION;
    m.familyNum     = s.u32(0x28);
    m.generationNum = s.u32(0x2C);
    m.numDisks      = s.u8(0x38);
    m.numRaidDevs   = s.u8(0x39);

    // Disk array at 0xD8, 48 bytes each.
    size_t off = 0xD8;
    for (uint8_t i = 0; i < m.numDisks && off + 48 <= sb.size(); ++i, off += 48) {
        ImsmDisk d;
        d.serial.assign(reinterpret_cast<const char*>(s.at(off, 16)), 16);
        d.serial.erase(d.serial.find_last_not_of(" \0") + 1);
        uint64_t lo = s.u32(off + 0x10), hi = s.u32(off + 0x20);
        d.totalBlocks = lo | (hi << 32);
        d.status = s.u32(off + 0x18);
        m.disks.push_back(std::move(d));
    }

    // RAID device (imsm_dev): volume name (16) + size_low/high.
    for (uint8_t i = 0; i < m.numRaidDevs && off + 24 <= sb.size(); ++i) {
        ImsmVolume v;
        v.name.assign(reinterpret_cast<const char*>(s.at(off, 16)), 16);
        v.name.erase(v.name.find_last_not_of(" \0") + 1);
        uint64_t lo = s.u32(off + 0x10), hi = s.u32(off + 0x14);
        v.sizeBlocks = lo | (hi << 32);
        m.volumes.push_back(std::move(v));
        // The full imsm_dev is larger (migration/map records follow); for the
        // geometry we only need the header. Advance conservatively.
        off += 0x1C;
    }
    return m;
}

} // namespace de::optane

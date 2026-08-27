#include "optane/imsm.h"
#include "core/byte_reader.h"
#include <cstring>

namespace de::optane {

namespace {
constexpr char IMSM_SIG[] = "Intel Raid ISM Cfg Sig.";
constexpr size_t IMSM_SIG_LEN = sizeof(IMSM_SIG) - 1;
// The NV-cache config header that opens the Intel Cache region. The IMSM super
// sits 0x1E00 further in, and both are repeated on an 8 KiB stride
// (see FORMAT_NOTES.md).
constexpr char NVC_SIG[] = "Intel IMSM NV Cache Cfg. Sig.";
constexpr size_t NVC_SIG_LEN = sizeof(NVC_SIG) - 1;
constexpr uint64_t IMSM_OFFSET_IN_REGION = 0x1E00;
constexpr uint64_t REGION_ALIGN = 8192;

// mdadm's __gen_imsm_checksum: the sum of every u32 in the first mpb_size
// bytes, less the stored checksum word.
uint32_t imsmChecksum(const uint8_t* p, uint32_t mpbSize) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i + 4 <= mpbSize; i += 4) sum += rd32(p + i);
    return sum - rd32(p + 0x20);
}

// Is this really an IMSM super, or just the literal string?
//
// The Intel RST driver binary embeds "Intel Raid ISM Cfg Sig. " in its own
// format-string table, and that binary gets cached onto the Optane like any
// other file - so a plain signature scan finds the driver's string table long
// before the real metadata and parses its message text as disks and volumes.
// The checksum is what separates the two.
bool validSuper(const uint8_t* p, size_t avail) {
    if (avail < 0xD8 + 48) return false;
    if (std::memcmp(p, IMSM_SIG, IMSM_SIG_LEN) != 0) return false;
    uint32_t mpbSize = rd32(p + 0x24);
    if (mpbSize < 0xD8 || mpbSize % 4 || mpbSize > avail) return false;
    if (p[0x38] > 16 || p[0x39] > 4) return false;   // num_disks, num_raid_devs
    return imsmChecksum(p, mpbSize) == rd32(p + 0x20);
}

// Find the byte offset of a verified IMSM super. If `hintRegion` points at the
// cache region, check there first; otherwise scan the device.
std::optional<uint64_t> findImsm(ImageSource& img, uint64_t hintRegion) {
    const size_t kSuperWindow = 8192;
    auto superAt = [&](uint64_t off) {
        auto b = img.read(off, kSuperWindow);
        return b.size() >= 0xD8 + 48 && validSuper(b.data(), b.size());
    };

    if (hintRegion != UINT64_MAX && superAt(hintRegion + IMSM_OFFSET_IN_REGION))
        return hintRegion + IMSM_OFFSET_IN_REGION;

    // Scan. The region is 8 KiB-aligned and opens with the NV-cache config
    // header, so probe that alignment rather than every byte: it is both far
    // faster and immune to the driver-string false positive above.
    const size_t win = 16 * 1024 * 1024;
    std::vector<uint8_t> buf;
    for (uint64_t base = 0; base < img.size(); base += win) {
        buf = img.read(base, win);
        if (buf.empty()) break;
        for (size_t i = 0; i + IMSM_OFFSET_IN_REGION + 0xD8 + 48 <= buf.size();
             i += REGION_ALIGN) {
            if (std::memcmp(&buf[i], NVC_SIG, NVC_SIG_LEN) != 0) continue;
            uint64_t super = base + i + IMSM_OFFSET_IN_REGION;
            if (superAt(super)) return super;
        }
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

#include "partition/partition.h"
#include "core/byte_reader.h"
#include <array>

namespace de {

namespace {

// Map a few common MBR partition type bytes to friendly names.
std::string mbrTypeName(uint8_t t) {
    switch (t) {
        case 0x07: return "NTFS / exFAT";
        case 0x0B: case 0x0C: return "FAT32";
        case 0x83: return "Linux filesystem";
        case 0xAF: return "HFS / HFS+";
        case 0xEE: return "GPT protective";
        case 0x82: return "Linux swap";
        default:   return "Unknown (0x" + std::string(1, "0123456789ABCDEF"[t >> 4])
                          + std::string(1, "0123456789ABCDEF"[t & 0xF]) + ")";
    }
}

// A handful of well-known GPT partition type GUIDs (stored mixed-endian on disk).
std::string gptTypeName(const uint8_t* guid) {
    // Compare the first 4 bytes (little-endian Data1) plus a couple more; that
    // is enough to disambiguate the common types without a full GUID table.
    auto d1 = rd32(guid);
    if (d1 == 0xEBD0A0A2) return "Basic data (NTFS/exFAT/FAT)";
    if (d1 == 0x0FC63DAF) return "Linux filesystem";
    if (d1 == 0xC12A7328) return "EFI System";
    if (d1 == 0x48465300) return "Apple HFS+";
    if (d1 == 0x7C3457EF) return "Apple APFS";
    if (d1 == 0xE6D6D379) return "Linux LVM";
    // All-zero GUID marks an unused table entry.
    bool zero = true;
    for (int i = 0; i < 16; ++i) if (guid[i]) { zero = false; break; }
    return zero ? "" : "Unknown GUID";
}

std::vector<Partition> scanGpt(const std::shared_ptr<ImageSource>& img,
                               uint32_t sectorSize) {
    std::vector<Partition> out;
    auto hdr = img->read(sectorSize, sectorSize); // GPT header at LBA 1
    de::Span h{hdr.data(), hdr.size()};
    if (std::memcmp(hdr.data(), "EFI PART", 8) != 0)
        return out;

    uint64_t entryLba   = h.u64(72);
    uint32_t numEntries = h.u32(80);
    uint32_t entrySize  = h.u32(84);
    if (entrySize < 128 || numEntries == 0 || numEntries > 4096)
        return out;

    uint64_t tableOff = entryLba * sectorSize;
    auto table = img->read(tableOff, static_cast<size_t>(numEntries) * entrySize);
    int idx = 1;
    for (uint32_t i = 0; i < numEntries; ++i) {
        const uint8_t* e = table.data() + static_cast<size_t>(i) * entrySize;
        std::string type = gptTypeName(e);
        if (type.empty()) continue; // unused slot
        uint64_t firstLba = rd64(e + 32);
        uint64_t lastLba  = rd64(e + 40);
        if (lastLba < firstLba) continue;
        Partition p;
        p.scheme = "GPT";
        p.firstByte = firstLba * sectorSize;
        p.lengthBytes = (lastLba - firstLba + 1) * sectorSize;
        p.typeName = type;
        p.index = idx++;
        out.push_back(std::move(p));
    }
    return out;
}

} // namespace

std::vector<Partition> scanPartitions(const std::shared_ptr<ImageSource>& img) {
    std::vector<Partition> out;
    const uint32_t sectorSize = 512; // 512e is near-universal for imaged media

    auto mbr = img->read(0, 512);
    bool hasSig = (mbr[510] == 0x55 && mbr[511] == 0xAA);

    // A bare filesystem volume (image of a single partition, no partition
    // table) has an FS boot record at sector 0, which also carries the 0x55AA
    // signature. Detect the common ones by their OEM/signature so we don't
    // mis-parse the VBR's boot code as an MBR partition table. This is exactly
    // the shape of a raw single-volume image (no partition table).
    bool bareVolume =
        std::memcmp(mbr.data() + 3, "NTFS    ", 8) == 0 ||  // NTFS
        std::memcmp(mbr.data() + 3, "-FVE-FS-", 8) == 0 ||  // BitLocker
        std::memcmp(mbr.data() + 3, "MSDOS", 5) == 0    ||  // FAT
        std::memcmp(mbr.data() + 0x52, "FAT32", 5) == 0;

    if (hasSig && !bareVolume) {
        // Detect a GPT via a protective 0xEE entry anywhere in the MBR table.
        bool protective = false;
        for (int i = 0; i < 4; ++i)
            if (mbr[446 + i * 16 + 4] == 0xEE) protective = true;

        if (protective) {
            out = scanGpt(img, sectorSize);
            if (!out.empty()) return out;
        }

        // Classic MBR primary partitions.
        int idx = 1;
        for (int i = 0; i < 4; ++i) {
            const uint8_t* e = mbr.data() + 446 + i * 16;
            uint8_t type = e[4];
            uint32_t startLba = rd32(e + 8);
            uint32_t sectors  = rd32(e + 12);
            if (type == 0 || sectors == 0) continue;
            Partition p;
            p.scheme = "MBR";
            p.firstByte = static_cast<uint64_t>(startLba) * sectorSize;
            p.lengthBytes = static_cast<uint64_t>(sectors) * sectorSize;
            p.typeName = mbrTypeName(type);
            p.index = idx++;
            out.push_back(std::move(p));
        }
        if (!out.empty()) return out;
    }

    // No usable table: treat the whole image as one volume.
    Partition whole;
    whole.scheme = "none";
    whole.firstByte = 0;
    whole.lengthBytes = img->size();
    whole.typeName = "Whole image (no partition table)";
    whole.index = 1;
    out.push_back(std::move(whole));
    return out;
}

} // namespace de

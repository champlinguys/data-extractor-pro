#include "partition/partition.h"
#include "core/byte_reader.h"
#include <array>
#include <cstring>
#include <optional>

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

// The parts of a GPT header we need to locate and bound the entry array.
struct GptHeader {
    uint64_t entryLba = 2;
    uint32_t numEntries = 128;
    uint32_t entrySize = 128;
    uint64_t firstUsable = 34;
    uint64_t lastUsable = 0;
};

// Read and sanity-check the GPT header at `lba`. Rejects anything whose entry
// array geometry is implausible, so a half-overwritten header can't send us
// reading gigabytes of garbage.
std::optional<GptHeader> readGptHeader(const std::shared_ptr<ImageSource>& img,
                                       uint64_t lba, uint32_t sectorSize) {
    auto hdr = img->read(lba * sectorSize, sectorSize);
    if (std::memcmp(hdr.data(), "EFI PART", 8) != 0) return std::nullopt;
    de::Span h{hdr.data(), hdr.size()};
    GptHeader g;
    g.firstUsable = h.u64(40);
    g.lastUsable  = h.u64(48);
    g.entryLba    = h.u64(72);
    g.numEntries  = h.u32(80);
    g.entrySize   = h.u32(84);
    if (g.entrySize < 128 || g.entrySize > 4096) return std::nullopt;
    if (g.numEntries == 0 || g.numEntries > 4096) return std::nullopt;
    if (g.lastUsable < g.firstUsable) return std::nullopt;
    if (g.entryLba == 0 || g.entryLba * sectorSize >= img->size()) return std::nullopt;
    return g;
}

// Parse one entry array. Entries outside [firstUsable, lastUsable] are dropped:
// on a disk whose backup table has been partly overwritten (RST/Optane metadata
// lives in those very sectors) the array still parses, but the clobbered slots
// decode as absurd ranges and would otherwise show up as phantom partitions.
std::vector<Partition> readGptEntries(const std::shared_ptr<ImageSource>& img,
                                      uint64_t entryLba, const GptHeader& g,
                                      uint32_t sectorSize, const char* scheme) {
    std::vector<Partition> out;
    auto table = img->read(entryLba * sectorSize,
                           static_cast<size_t>(g.numEntries) * g.entrySize);
    int idx = 1;
    for (uint32_t i = 0; i < g.numEntries; ++i) {
        const uint8_t* e = table.data() + static_cast<size_t>(i) * g.entrySize;
        std::string type = gptTypeName(e);
        if (type.empty()) continue; // unused slot
        uint64_t firstLba = rd64(e + 32);
        uint64_t lastLba  = rd64(e + 40);
        if (lastLba < firstLba) continue;
        if (firstLba < g.firstUsable || lastLba > g.lastUsable) continue;
        Partition p;
        p.scheme = scheme;
        p.firstByte = firstLba * sectorSize;
        p.lengthBytes = (lastLba - firstLba + 1) * sectorSize;
        p.typeName = type;
        p.index = idx++;
        out.push_back(std::move(p));
    }
    return out;
}

// Scan a GPT, tolerating a destroyed primary header.
//
// Windows/RST disks turn up with the header at LBA 1 zeroed while the entry
// array at LBA 2 is intact and current - and, on an Optane-cached disk, with
// the backup table at the end of the media partly overwritten by the Intel RST
// metadata. So: take geometry from whichever header survives (primary, else
// backup), then try both entry-array locations and keep whichever yields more
// usable entries, preferring the primary array on a tie because it is the copy
// the running system updates first.
std::vector<Partition> scanGpt(const std::shared_ptr<ImageSource>& img,
                               uint32_t sectorSize) {
    const uint64_t lastLba = img->size() / sectorSize - 1;
    auto primary = readGptHeader(img, 1, sectorSize);
    auto backup  = readGptHeader(img, lastLba, sectorSize);

    GptHeader g;
    if (primary)      g = *primary;
    else if (backup)  g = *backup;
    else {
        // Both headers gone. The entry array at LBA 2 may still be there, so
        // fall back to the standard geometry every Windows/UEFI disk uses.
        g.entryLba = 2;
        g.numEntries = 128;
        g.entrySize = 128;
        g.firstUsable = 34;
        g.lastUsable = lastLba >= 34 ? lastLba - 33 : 0;
    }
    const char* scheme = primary ? "GPT" : "GPT (recovered)";

    // Candidate entry-array locations, best-first.
    std::vector<uint64_t> candidates{2};
    if (g.entryLba != 2) candidates.push_back(g.entryLba);
    if (backup && backup->entryLba != 2 && backup->entryLba != g.entryLba)
        candidates.push_back(backup->entryLba);

    std::vector<Partition> best;
    for (uint64_t lba : candidates) {
        auto got = readGptEntries(img, lba, g, sectorSize, scheme);
        if (got.size() > best.size()) best = std::move(got);
    }
    return best;
}

// Does a filesystem boot record live at this byte offset?
// Checked by OEM/signature rather than by trusting the partition type byte,
// because the type byte is what we are trying to corroborate.
bool looksLikeVolumeStart(const std::shared_ptr<ImageSource>& img, uint64_t off) {
    if (off + 512 > img->size()) return false;
    auto b = img->read(off, 512);
    if (std::memcmp(b.data() + 3, "NTFS    ", 8) == 0) return true;
    if (std::memcmp(b.data() + 3, "-FVE-FS-", 8) == 0) return true;   // BitLocker
    if (std::memcmp(b.data() + 3, "EXFAT   ", 8) == 0) return true;
    if (std::memcmp(b.data() + 3, "MSDOS", 5) == 0) return true;
    if (std::memcmp(b.data() + 0x52, "FAT32", 5) == 0) return true;
    if (std::memcmp(b.data() + 0x36, "FAT", 3) == 0) return true;
    return false;
}

// Work out the logical sector size the partition table was written in.
//
// 512 is not safe to assume. Native-4K (4Kn) drives store LBAs in the MBR in
// 4096-byte units, so reading them as 512 lands every offset 8x too low: a
// partition at LBA 2048 sits at byte 8,388,608, not 1,048,576. The scan then
// looks 7 MB short of the boot sector, finds nothing, and reports "no
// filesystem" on a perfectly good image.
//
// Seen for real on a 3 TB Seagate ST3000DM001 (4Kn, case chris3tb): at 512 its
// sole NTFS partition computes as 349.3 GiB starting at 1 MiB; at 4096 it
// computes as 3.00 TB starting at 8 MiB and matches the image exactly. Note
// that lsblk makes the same mistake and also reports 349.3G, so agreeing with
// the OS is not evidence of being right.
//
// Two independent signals, both required, so a coincidence in one cannot carry
// the decision:
//   1. a real filesystem boot record sits at startLBA * candidate
//   2. the partition fits inside the image
// Ties go to 512, which keeps existing 512e behaviour byte-for-byte.
uint32_t detectSectorSize(const std::shared_ptr<ImageSource>& img,
                          const std::vector<uint8_t>& mbr) {
    static const uint32_t kCandidates[] = {512, 4096};
    for (uint32_t cand : kCandidates) {
        for (int i = 0; i < 4; ++i) {
            const uint8_t* e = mbr.data() + 446 + i * 16;
            uint8_t type = e[4];
            uint32_t startLba = rd32(e + 8);
            uint32_t sectors  = rd32(e + 12);
            if (type == 0 || type == 0xEE || sectors == 0 || startLba == 0) continue;

            uint64_t first = static_cast<uint64_t>(startLba) * cand;
            uint64_t len   = static_cast<uint64_t>(sectors) * cand;
            if (first + len > img->size()) continue;           // signal 2
            if (!looksLikeVolumeStart(img, first)) continue;   // signal 1
            return cand;
        }
    }
    return 512;   // nothing corroborated; keep the historical default
}

} // namespace

std::vector<Partition> scanPartitions(const std::shared_ptr<ImageSource>& img) {
    std::vector<Partition> out;

    auto mbr = img->read(0, 512);
    // Derived from the table itself, never assumed. See detectSectorSize().
    const uint32_t sectorSize = detectSectorSize(img, mbr);
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
            // 0xEE is the protective entry for a GPT we have already failed to
            // read; reporting it as a partition covering the whole disk is
            // worse than useless, so leave it out and let the whole-image
            // fallback below speak instead.
            if (type == 0 || type == 0xEE || sectors == 0) continue;
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

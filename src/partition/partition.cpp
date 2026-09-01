#include "partition/partition.h"
#include "core/byte_reader.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <utility>

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
    if (d1 == 0x53746F72) return "Apple Core Storage";
    if (d1 == 0x426F6F74) return "Apple Boot (Recovery)";
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

// ------------------------------------------------------- Apple Partition Map
//
// The scheme every Mac used before the Intel transition, and the one every
// external drive sold for a Mac in that era carries. Block 0 is a Driver
// Descriptor Record signed 'ER' which states the device block size; blocks
// 1..n are the map entries themselves, each signed 'PM' and each repeating how
// many entries the map has.
//
// An APM disk carries no 0x55AA at the end of block 0, so a scanner that knows
// only MBR and GPT reports "no partition table" on a perfectly healthy Mac
// drive and falls back to treating the whole disk as one volume - which then
// fails to mount, because the filesystem starts 393,216 bytes in.
//
// The map also lists far more entries than a user would call partitions: the
// map is itself an entry, as are the legacy driver stubs and every unallocated
// hole. A 2005 LaCie shows seven entries for one volume of data, so the
// bookkeeping kinds are skipped and only real volumes are reported.
constexpr uint16_t APM_DDR_SIGNATURE = 0x4552;    // 'ER', block 0
constexpr uint16_t APM_ENTRY_SIGNATURE = 0x504D;  // 'PM', blocks 1..n
constexpr uint32_t APM_MAX_ENTRIES = 256;         // sanity cap on pmMapBlkCnt

// A fixed-width, NUL-padded APM name/type field.
std::string apmString(const uint8_t* p, size_t max) {
    size_t n = 0;
    while (n < max && p[n]) ++n;
    std::string out(reinterpret_cast<const char*>(p), n);
    // These fields are ASCII by spec; keep anything unprintable from reaching
    // a terminal or a Qt label.
    for (char& c : out)
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) == 0x7F)
            c = '_';
    return out;
}

// Entries that describe bookkeeping rather than a volume.
bool apmIsBookkeeping(const std::string& type) {
    return type == "Apple_partition_map" || type == "Apple_Free" ||
           type == "Apple_Void";
}

std::vector<Partition> scanApm(const std::shared_ptr<ImageSource>& img,
                               const std::vector<uint8_t>& ddr) {
    std::vector<Partition> out;
    // Offsets are in units of the block size the DDR declares - 512 on every
    // hard disk, 2048 on optical media - not in 512-byte sectors.
    uint32_t blockSize = rdBE16(ddr.data() + 2);
    if (blockSize < 512 || blockSize % 512) blockSize = 512;

    auto first = img->read(blockSize, 512);
    if (first.size() < 512 || rdBE16(first.data()) != APM_ENTRY_SIGNATURE) return out;
    uint32_t count = rdBE32(first.data() + 4);
    if (count > APM_MAX_ENTRIES) count = APM_MAX_ENTRIES;

    int idx = 1;
    for (uint32_t i = 0; i < count; ++i) {
        auto entry = i == 0 ? first : img->read(static_cast<uint64_t>(i + 1) * blockSize, 512);
        if (entry.size() < 128 || rdBE16(entry.data()) != APM_ENTRY_SIGNATURE) break;

        uint64_t startBlock = rdBE32(entry.data() + 8);
        uint64_t blocks = rdBE32(entry.data() + 12);
        std::string name = apmString(entry.data() + 16, 32);
        std::string type = apmString(entry.data() + 48, 32);
        if (blocks == 0 || apmIsBookkeeping(type)) continue;

        Partition p;
        p.scheme = "APM";
        p.firstByte = startBlock * blockSize;
        p.lengthBytes = blocks * blockSize;
        p.typeName = name.empty() ? type : type + " \"" + name + "\"";
        p.index = idx++;
        if (p.firstByte >= img->size()) continue;
        out.push_back(std::move(p));
    }
    return out;
}

// ------------------------------------------------------- lost-volume recovery
//
// Deleting a partition, or letting an installer rewrite the table, does not
// touch the volume it pointed at: the boot record, the metadata and the file
// data all stay exactly where they were. So when the table describes less than
// the disk holds, the unallocated gaps are worth searching directly.
//
// The case this was written for (case brian): a 512 GB UEFI laptop SSD whose
// GPT listed only the 190 MiB EFI partition and a 990 MiB recovery partition,
// with 475 GiB of "free space" between them. That gap held an intact
// BitLocker-encrypted C: starting 128 MiB into the gap. The table was the only
// thing that had been lost.
//
// A candidate is accepted only if it identifies itself *and* its own recorded
// size is consistent with where it was found, which is what keeps a random
// 0x55AA in file data from being reported as a partition.

// A volume found by scanning, described by its own on-disk fields.
struct FoundVolume {
    std::string typeName;
    uint64_t lengthBytes = 0;
};

// Is `v` a power of two within [lo, hi]?
bool pow2InRange(uint64_t v, uint64_t lo, uint64_t hi) {
    return v >= lo && v <= hi && (v & (v - 1)) == 0;
}

// Read the size a BitLocker volume records for itself.
//
// The boot record points at up to three copies of the FVE metadata, each of
// which restates the encrypted volume size. That figure lives inside the
// volume, so unlike a partition table it cannot be stale - the same reasoning
// reconcileVolumeSize() already applies once a volume is mounted.
uint64_t bitlockerSelfSize(const std::shared_ptr<ImageSource>& img,
                           uint64_t off, const uint8_t* boot) {
    for (int i = 0; i < 3; ++i) {
        uint64_t mdOff = rd64(boot + 0xB0 + 8 * i);
        if (mdOff == 0 || mdOff > img->size() - off) continue;
        auto md = img->read(off + mdOff, 512);
        if (md.size() < 512 || std::memcmp(md.data(), "-FVE-FS-", 8) != 0) continue;
        uint64_t sz = rd64(md.data() + 0x10);
        if (sz) return sz;
    }
    return 0;
}

// Identify a volume boot record at `off` and work out how long it says it is.
// Returns nullopt unless the record is self-consistent.
std::optional<FoundVolume> identifyVolume(const std::shared_ptr<ImageSource>& img,
                                          uint64_t off) {
    if (off + 512 > img->size()) return std::nullopt;
    auto b = img->read(off, 512);
    if (b.size() < 512) return std::nullopt;
    // Every one of these records ends in the boot signature. Checking it first
    // rejects all but 1 in 65536 offsets before any further work.
    if (b[510] != 0x55 || b[511] != 0xAA) return std::nullopt;

    const uint8_t* p = b.data();
    uint64_t bps = rd16(p + 0x0B);              // bytes per sector
    const uint64_t avail = img->size() - off;

    auto accept = [&](const char* name, uint64_t len) -> std::optional<FoundVolume> {
        if (len == 0 || len > avail) return std::nullopt;
        return FoundVolume{name, len};
    };

    if (std::memcmp(p + 3, "-FVE-FS-", 8) == 0) {
        // BitLocker. Its own "hidden sectors" field is the volume's start LBA,
        // so it should equal where we found it - a self-check strong enough to
        // stand on its own.
        uint64_t hidden = rd32(p + 0x1C);
        if (bps && hidden && hidden * bps != off) return std::nullopt;
        uint64_t len = bitlockerSelfSize(img, off, p);
        return accept("BitLocker encrypted volume", len);
    }
    if (std::memcmp(p + 3, "NTFS    ", 8) == 0) {
        if (!pow2InRange(bps, 512, 4096)) return std::nullopt;
        if (!pow2InRange(rd8(p + 0x0D), 1, 128)) return std::nullopt;  // sectors/cluster
        // NTFS records one sector fewer than the partition holds: the last
        // sector is the backup boot record and is left out of the count.
        uint64_t len = (rd64(p + 0x28) + 1) * bps;
        return accept("NTFS", len);
    }
    if (std::memcmp(p + 3, "EXFAT   ", 8) == 0) {
        uint64_t shift = rd8(p + 0x6C);
        if (shift < 9 || shift > 12) return std::nullopt;
        return accept("exFAT", rd64(p + 0x48) << shift);
    }
    if (std::memcmp(p + 0x52, "FAT32", 5) == 0) {
        if (!pow2InRange(bps, 512, 4096)) return std::nullopt;
        return accept("FAT32", rd64(p + 0x20) * bps);   // total sectors (32-bit field)
    }
    if (std::memcmp(p + 0x36, "FAT", 3) == 0) {
        if (!pow2InRange(bps, 512, 4096)) return std::nullopt;
        uint64_t secs = rd16(p + 0x13);
        if (!secs) secs = rd32(p + 0x20);
        return accept("FAT", secs * bps);
    }
    return std::nullopt;
}

// A run of unallocated bytes.
struct Gap { uint64_t begin, end; };

// The regions of the image no reported partition covers.
std::vector<Gap> unallocatedGaps(const std::vector<Partition>& parts, uint64_t imgSize) {
    std::vector<std::pair<uint64_t, uint64_t>> used;
    for (const auto& p : parts)
        if (p.lengthBytes) used.emplace_back(p.firstByte, p.firstByte + p.lengthBytes);
    std::sort(used.begin(), used.end());

    std::vector<Gap> gaps;
    // The first megabyte holds the partition table itself; a volume never
    // starts there, and skipping it keeps the protective MBR out of the scan.
    uint64_t cursor = 1u << 20;
    for (auto& [b, e] : used) {
        if (b > cursor) gaps.push_back({cursor, b});
        cursor = std::max(cursor, e);
    }
    if (cursor < imgSize) gaps.push_back({cursor, imgSize});
    return gaps;
}

// Search the gaps for volumes the table forgot.
//
// Cost is dominated by seeking, so the probe pattern matters more than the
// number of bytes touched. Two passes, cheapest first:
//
//   1. Every sector of the first 32 MiB of a gap, read in big sequential
//      blocks. Catches a volume that starts immediately after the previous one
//      and any odd, unaligned legacy geometry, for the price of one streamed
//      read.
//   2. Every 1 MiB boundary. Modern partitioners align to 1 MiB without
//      exception, so this is where a lost volume actually starts. In Fast mode
//      the pass stops 4 GiB into the gap; Deep runs it to the end.
//
// A confirmed volume is recorded and the cursor jumps past its full length,
// so the scan never reports structures found inside a volume it already knows.
std::vector<Partition> scanForOrphans(const std::shared_ptr<ImageSource>& img,
                                      const std::vector<Partition>& known,
                                      OrphanScan mode) {
    std::vector<Partition> found;
    if (mode == OrphanScan::Off) return found;

    constexpr uint64_t SECTOR   = 512;
    constexpr uint64_t MiB      = 1u << 20;
    constexpr uint64_t DENSE    = 32 * MiB;    // pass 1 window
    constexpr uint64_t FAST_CAP = 4096 * MiB;  // pass 2 window in Fast mode
    constexpr size_t   CHUNK    = 4u << 20;

    auto record = [&](uint64_t off, const FoundVolume& v) {
        Partition p;
        p.scheme = "found";
        p.firstByte = off;
        p.lengthBytes = v.lengthBytes;
        p.typeName = v.typeName;
        found.push_back(std::move(p));
    };

    for (const auto& g : unallocatedGaps(known, img->size())) {
        if (g.end - g.begin < MiB) continue;

        // Pass 1: dense, streamed.
        uint64_t covered = g.begin;   // end of the last volume confirmed here
        uint64_t denseEnd = std::min(g.end, g.begin + DENSE);
        std::vector<uint8_t> buf;
        for (uint64_t off = g.begin; off < denseEnd; ) {
            size_t want = static_cast<size_t>(std::min<uint64_t>(CHUNK, denseEnd - off));
            buf.assign(want, 0);
            size_t got = img->readAt(off, buf.data(), want);
            if (got < SECTOR) break;
            bool jumped = false;
            for (size_t s = 0; s + SECTOR <= got; s += SECTOR) {
                // Cheap gate: only pay for identifyVolume() where the boot
                // signature is already present.
                if (buf[s + 510] != 0x55 || buf[s + 511] != 0xAA) continue;
                uint64_t at = off + s;
                if (auto v = identifyVolume(img, at)) {
                    record(at, *v);
                    off = covered = at + v->lengthBytes;
                    jumped = true;
                    break;
                }
            }
            if (!jumped) off += got;
        }

        // Pass 2: 1 MiB stride.
        uint64_t start = (covered + MiB - 1) / MiB * MiB;
        uint64_t stop = mode == OrphanScan::Deep ? g.end
                                                 : std::min(g.end, g.begin + FAST_CAP);
        for (uint64_t off = start; off + SECTOR <= stop; ) {
            if (auto v = identifyVolume(img, off)) {
                record(off, *v);
                covered = off + v->lengthBytes;
                off = (covered + MiB - 1) / MiB * MiB;
            } else {
                off += MiB;
            }
        }
    }
    return found;
}

} // namespace

std::vector<Partition> scanPartitions(const std::shared_ptr<ImageSource>& img,
                                      OrphanScan orphans) {
    std::vector<Partition> out;

    auto mbr = img->read(0, 512);

    // The Apple Partition Map is checked first: its block 0 has no 0x55AA, so
    // it has to be recognised before the MBR path below rejects it.
    // Appends any volume the table does not account for, then renumbers so the
    // indices the caller prints stay contiguous.
    auto withOrphans = [&](std::vector<Partition> table) {
        for (auto& p : scanForOrphans(img, table, orphans))
            table.push_back(std::move(p));
        int n = 1;
        for (auto& p : table) p.index = n++;
        return table;
    };

    if (mbr.size() >= 512 && rdBE16(mbr.data()) == APM_DDR_SIGNATURE) {
        out = scanApm(img, mbr);
        if (!out.empty()) return withOrphans(std::move(out));
    }

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
            if (!out.empty()) return withOrphans(std::move(out));
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
        if (!out.empty()) return withOrphans(std::move(out));
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

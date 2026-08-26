#include "fs/fat/fat.h"
#include "core/byte_reader.h"
#include <algorithm>
#include <array>
#include <cstring>

namespace de {

namespace {

constexpr size_t ENTRY_SIZE = 32;

// Directory entry attributes.
constexpr uint8_t ATTR_READ_ONLY = 0x01;
constexpr uint8_t ATTR_HIDDEN    = 0x02;
constexpr uint8_t ATTR_SYSTEM    = 0x04;
constexpr uint8_t ATTR_VOLUME_ID = 0x08;
constexpr uint8_t ATTR_DIRECTORY = 0x10;
// A long-name entry is flagged with all four of the low attribute bits at once,
// a combination no real file can have. That is exactly how VFAT hid these
// entries from DOS versions that predated it.
constexpr uint8_t ATTR_LONG_NAME = ATTR_READ_ONLY | ATTR_HIDDEN |
                                   ATTR_SYSTEM | ATTR_VOLUME_ID;
// Bits 6 and 7 are reserved and always zero. A slot with either set is not a
// directory entry, which makes this the cheapest garbage filter available.
constexpr uint8_t ATTR_RESERVED  = 0xC0;

constexpr uint8_t DIR_FREE    = 0xE5;  // entry deleted
constexpr uint8_t DIR_END     = 0x00;  // this entry and every one after is free
constexpr uint8_t DIR_KANJI_E5 = 0x05; // a real leading 0xE5, escaped

constexpr uint8_t LFN_LAST = 0x40;     // set on the highest-ordinal entry
constexpr uint32_t MAX_LFN_ENTRIES = 20;   // 20 * 13 chars = 260 >= 255 + NUL
constexpr size_t LFN_CHARS_PER_ENTRY = 13;

// FAT32 entries are 28 bits; the top nibble is reserved and must be masked off
// before comparing against any of these.
constexpr uint32_t FAT32_MASK = 0x0FFFFFFF;
constexpr uint32_t FAT_BAD    = 0x0FFFFFF7;
constexpr uint32_t FAT_EOF_MIN = 0x0FFFFFF8;  // >= this means end of chain

// Read the FAT in chunks this big rather than four bytes at a time.
constexpr size_t FAT_BLOCK = 64 * 1024;

// A FAT32 volume is one with at least this many clusters; below it the same
// BPB describes a FAT16 or FAT12 volume, whose FAT entries are a different
// width and whose root directory is not a cluster chain at all.
constexpr uint32_t FAT32_MIN_CLUSTERS = 65525;

// How far to keep walking a deleted directory. Its chain is gone, so the walk
// is a guess (see scanDirectory) and needs a hard stop. 64 clusters is 2 MB of
// directory at the usual 32 KB cluster - thousands of entries.
constexpr uint64_t MAX_DELETED_DIR_CLUSTERS = 64;

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm). Used
// instead of timegm() so the conversion is pure and does not depend on the
// host's timezone database.
int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// A FAT timestamp is a packed DOS date and time in *local* time, with no record
// anywhere of which local time that was. exFAT later added a UTC offset byte to
// each stamp precisely because of this gap; FAT32 has nothing equivalent, so an
// exact conversion is not possible from the volume alone.
//
// We therefore read the stamp as if it were UTC. That is the same choice the
// Linux and Windows drivers make by default, so exported files carry the dates
// the user is used to seeing, and it is off by at most the original machine's
// UTC offset. mount() notes this so the discrepancy is never a surprise.
//
// `tenth` is the create-time refinement, 0-199 in units of 10 ms, and applies
// only to the creation stamp.
int64_t fatTimeToUnixNs(uint16_t date, uint16_t time, uint8_t tenth = 0) {
    if (date == 0) return 0;   // "not recorded"; access dates are often zero
    unsigned day   = date & 0x1F;
    unsigned month = (date >> 5) & 0x0F;
    unsigned year  = ((date >> 9) & 0x7F) + 1980;
    unsigned sec   = (time & 0x1F) * 2;
    unsigned mins  = (time >> 5) & 0x3F;
    unsigned hour  = (time >> 11) & 0x1F;
    if (month < 1 || month > 12 || day < 1 || day > 31) return 0;
    if (hour > 23 || mins > 59 || sec > 59) return 0;

    int64_t days = daysFromCivil(static_cast<int64_t>(year), month, day);
    int64_t secs = days * 86400 + hour * 3600 + mins * 60 + sec;
    int64_t ns = secs * 1000000000ll;
    if (tenth <= 199) ns += static_cast<int64_t>(tenth) * 10000000ll;
    return ns;
}

// Code page 437, the OEM character set short names are written in. Only the
// high half needs a table; 0x00-0x7F is ASCII. Getting this right is what turns
// a 2006-era "RÉSUMÉ.DOC" into the name the owner will recognise instead of
// mojibake - these drives predate any expectation of Unicode in a short name.
const uint16_t kCp437High[128] = {
    0x00C7,0x00FC,0x00E9,0x00E2,0x00E4,0x00E0,0x00E5,0x00E7,
    0x00EA,0x00EB,0x00E8,0x00EF,0x00EE,0x00EC,0x00C4,0x00C5,
    0x00C9,0x00E6,0x00C6,0x00F4,0x00F6,0x00F2,0x00FB,0x00F9,
    0x00FF,0x00D6,0x00DC,0x00A2,0x00A3,0x00A5,0x20A7,0x0192,
    0x00E1,0x00ED,0x00F3,0x00FA,0x00F1,0x00D1,0x00AA,0x00BA,
    0x00BF,0x2310,0x00AC,0x00BD,0x00BC,0x00A1,0x00AB,0x00BB,
    0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,
    0x2555,0x2563,0x2551,0x2557,0x255D,0x255C,0x255B,0x2510,
    0x2514,0x2534,0x252C,0x251C,0x2500,0x253C,0x255E,0x255F,
    0x255A,0x2554,0x2569,0x2566,0x2560,0x2550,0x256C,0x2567,
    0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256B,
    0x256A,0x2518,0x250C,0x2588,0x2584,0x258C,0x2590,0x2580,
    0x03B1,0x00DF,0x0393,0x03C0,0x03A3,0x03C3,0x00B5,0x03C4,
    0x03A6,0x0398,0x03A9,0x03B4,0x221E,0x03C6,0x03B5,0x2229,
    0x2261,0x00B1,0x2265,0x2264,0x2320,0x2321,0x00F7,0x2248,
    0x00B0,0x2219,0x00B7,0x221A,0x207F,0x00B2,0x25A0,0x00A0,
};

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// UTF-16LE -> UTF-8, handling surrogate pairs. Long names are padded with
// 0xFFFF and terminated with 0x0000, both of which the caller trims first.
std::string utf16leToUtf8(const std::vector<uint16_t>& units) {
    std::string out;
    out.reserve(units.size());
    for (size_t i = 0; i < units.size(); ++i) {
        uint32_t cp = units[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units.size()) {
            uint32_t lo = units[i + 1];
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        appendUtf8(out, cp);
    }
    return out;
}

// The checksum stored in every long-name entry, computed over the 11 raw bytes
// of the short name it belongs to.
uint8_t shortNameChecksum(const uint8_t* name11) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; ++i)
        sum = static_cast<uint8_t>(((sum & 1) ? 0x80 : 0) + (sum >> 1) + name11[i]);
    return sum;
}

// Recover the first byte of a deleted short name from its long-name checksum.
//
// Deleting a file overwrites only that first byte, with 0xE5 - so the checksum
// the long-name entries still carry was computed over a name we no longer have.
// But every step of shortNameChecksum is a rotate or an add, both bijections on
// eight bits, so the map from first byte to final checksum is one-to-one:
// exactly one value of the 256 reproduces the stored checksum, and that value
// is the character that was there before the delete.
//
// This is what turns a recovered "_ESUME.DOC" back into "RESUME.DOC".
uint8_t recoverDeletedFirstByte(uint8_t storedChecksum, const uint8_t* name11) {
    uint8_t probe[11];
    std::memcpy(probe, name11, 11);
    for (unsigned c = 0; c < 256; ++c) {
        probe[0] = static_cast<uint8_t>(c);
        if (shortNameChecksum(probe) == storedChecksum)
            return static_cast<uint8_t>(c);
    }
    return DIR_FREE;   // unreachable: the map is a bijection
}

// Is this byte legal in a short name? Control characters and the characters DOS
// reserved never appear in one, so their presence means the slot is not a
// directory entry at all - stale data in a reused cluster, most often.
bool shortNameByteIsLegal(uint8_t c) {
    if (c < 0x20) return false;
    return std::strchr("\"*+,./:;<=>?[\\]|", static_cast<char>(c)) == nullptr;
}

// Decode one run of short-name bytes from CP437, trimming the trailing spaces
// the field is padded with. Returns false if the run is entirely padding.
bool emitShortRun(const uint8_t* raw, int from, int to, bool lower,
                  std::string& out) {
    int end = to;
    while (end > from && raw[end - 1] == ' ') --end;
    if (end == from) return false;
    for (int i = from; i < end; ++i) {
        uint8_t c = raw[i];
        if (c < 0x80) {
            if (lower && c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c + 32);
            out.push_back(static_cast<char>(c));
        } else {
            appendUtf8(out, kCp437High[c - 0x80]);
        }
    }
    return true;
}

// Decode the 8.3 name, honouring the lowercase hints Windows NT stored in the
// otherwise-unused byte at offset 12. `firstByte` is passed separately because
// on a deleted entry the stored one has been overwritten with 0xE5 and the
// caller supplies either the recovered character or a placeholder.
// Returns false if the bytes are not a legal short name.
bool decodeShortName(const uint8_t* e, bool deleted, uint8_t firstByte,
                     std::string& out) {
    uint8_t raw[11];
    std::memcpy(raw, e, 11);
    raw[0] = firstByte;
    // 0x05 escapes a genuine leading 0xE5, which would otherwise read as
    // "deleted". Only meaningful on a live entry: on a deleted one the byte has
    // been overwritten and firstByte is the recovered or placeholder value.
    if (!deleted && raw[0] == DIR_KANJI_E5) raw[0] = 0xE5;

    for (int i = 0; i < 11; ++i)
        if (!shortNameByteIsLegal(raw[i])) return false;

    out.clear();
    // An all-blank base is padding, not a name.
    if (!emitShortRun(raw, 0, 8, (e[12] & 0x08) != 0, out)) return false;
    std::string ext;
    if (emitShortRun(raw, 8, 11, (e[12] & 0x10) != 0, ext)) {
        out.push_back('.');
        out += ext;
    }
    return !out.empty();
}

// The volume label is eleven raw bytes with no 8.3 split, so it is decoded as
// one run rather than as a name with an extension - "MY BOOK 123" must not come
// back as "MY BOOK.123".
bool decodeLabel(const uint8_t* e, std::string& out) {
    uint8_t raw[11];
    std::memcpy(raw, e, 11);
    for (int i = 0; i < 11; ++i)
        if (raw[i] < 0x20) return false;
    out.clear();
    return emitShortRun(raw, 0, 11, false, out);
}

// The "." and ".." links every subdirectory begins with. They are not files,
// and their names are not legal short names, so they are recognised and skipped
// before any other check - counting them as corrupt would hang a spurious
// "skipped 2 corrupt entries" warning on every single folder in the volume.
bool isDotEntry(const uint8_t* e) {
    if (!(e[11] & ATTR_DIRECTORY)) return false;
    return std::memcmp(e, ".          ", 11) == 0 ||
           std::memcmp(e, "..         ", 11) == 0;
}

// Names that would escape the export directory if we ever wrote them out
// verbatim. A damaged entry can hold anything, so this is a hard filter, not a
// nicety.
bool nameIsSafe(const std::string& s) {
    if (s.empty() || s == "." || s == "..") return false;
    return s.find('/') == std::string::npos &&
           s.find('\0') == std::string::npos;
}

// The BIOS parameter block, validated. Anything that fails these checks is not
// a FAT32 volume - a damaged sector, a FAT16 volume, or a boot sector from some
// other filesystem entirely.
struct Bpb {
    uint32_t bytesPerSector = 0;
    uint32_t sectorsPerCluster = 0;
    uint32_t reservedSectors = 0;
    uint32_t numFats = 0;
    uint32_t fatSizeSectors = 0;
    uint64_t totalSectors = 0;
    uint32_t rootCluster = 0;
    uint32_t fsInfoSector = 0;
    uint32_t backupBootSector = 0;
    uint32_t activeFat = 0;
    uint32_t clusterCount = 0;
    uint64_t dataStartSector = 0;
};

bool isPowerOfTwo(uint32_t v) { return v && (v & (v - 1)) == 0; }

std::optional<Bpb> parseBpb(const uint8_t* v) {
    if (v[510] != 0x55 || v[511] != 0xAA) return std::nullopt;
    // A FAT boot sector starts with a jump instruction. Checking it rejects a
    // sector of file data that happens to end in 0x55AA.
    if (!(v[0] == 0xEB && v[2] == 0x90) && v[0] != 0xE9) return std::nullopt;

    Bpb b;
    b.bytesPerSector    = rd16(v + 0x0B);
    b.sectorsPerCluster = v[0x0D];
    b.reservedSectors   = rd16(v + 0x0E);
    b.numFats           = v[0x10];
    uint16_t rootEntries = rd16(v + 0x11);
    uint16_t totSec16   = rd16(v + 0x13);
    uint8_t  media      = v[0x15];
    uint16_t fatSize16  = rd16(v + 0x16);
    uint32_t totSec32   = rd32(v + 0x20);
    b.fatSizeSectors    = rd32(v + 0x24);
    uint16_t extFlags   = rd16(v + 0x28);
    uint16_t fsVersion  = rd16(v + 0x2A);
    b.rootCluster       = rd32(v + 0x2C);
    b.fsInfoSector      = rd16(v + 0x30);
    b.backupBootSector  = rd16(v + 0x32);

    if (b.bytesPerSector < 512 || b.bytesPerSector > 4096 ||
        !isPowerOfTwo(b.bytesPerSector)) return std::nullopt;
    if (!isPowerOfTwo(b.sectorsPerCluster) || b.sectorsPerCluster > 128)
        return std::nullopt;
    if (b.reservedSectors == 0) return std::nullopt;
    if (b.numFats < 1 || b.numFats > 2) return std::nullopt;
    if (media != 0xF0 && media < 0xF8) return std::nullopt;
    // The three fields FAT32 redefines: all must be zero, which is what tells a
    // FAT32 BPB apart from the FAT12/FAT16 one it is an extension of.
    if (rootEntries != 0 || totSec16 != 0 || fatSize16 != 0) return std::nullopt;
    if (fsVersion != 0) return std::nullopt;     // no other version exists
    if (b.fatSizeSectors == 0 || totSec32 == 0) return std::nullopt;

    b.totalSectors = totSec32;
    b.dataStartSector = static_cast<uint64_t>(b.reservedSectors) +
                        static_cast<uint64_t>(b.numFats) * b.fatSizeSectors;
    if (b.dataStartSector >= b.totalSectors) return std::nullopt;
    uint64_t dataSectors = b.totalSectors - b.dataStartSector;
    uint64_t clusters = dataSectors / b.sectorsPerCluster;
    // Below this the volume is FAT16 or FAT12 by definition, whatever the BPB
    // looks like: the cluster count alone is what picks the FAT width.
    if (clusters < FAT32_MIN_CLUSTERS || clusters > FAT32_MASK - 1)
        return std::nullopt;
    b.clusterCount = static_cast<uint32_t>(clusters);

    if (b.rootCluster < 2 || b.rootCluster >= b.clusterCount + 2)
        return std::nullopt;
    // The FAT has to be big enough to describe every cluster, plus its two
    // reserved entries. A stale backup boot sector from a smaller former volume
    // is caught here rather than by reads running off the end of the FAT.
    uint64_t fatBytes = static_cast<uint64_t>(b.fatSizeSectors) * b.bytesPerSector;
    if (fatBytes < (static_cast<uint64_t>(b.clusterCount) + 2) * 4)
        return std::nullopt;

    // Bit 7 of ExtFlags means the FATs are not mirrored, and the low nibble
    // then says which one is live. With mirroring on, both are identical.
    b.activeFat = 0;
    if ((extFlags & 0x0080) && b.numFats == 2) b.activeFat = extFlags & 0x000F;
    if (b.activeFat >= b.numFats) b.activeFat = 0;
    return b;
}

} // namespace

// ---------------------------------------------------------------- geometry --

uint64_t FatFilesystem::clusterToOffset(uint32_t cluster) const {
    return dataByteOffset_ +
           static_cast<uint64_t>(cluster - 2) * clusterSize_;
}

bool FatFilesystem::validCluster(uint32_t cluster) const {
    return cluster >= 2 && cluster < clusterCount_ + 2;
}

// -------------------------------------------------------------------- mount --

bool FatFilesystem::probe(ImageSource& vol) {
    uint8_t vbr[512] = {};
    if (vol.readAt(0, vbr, sizeof vbr) == sizeof vbr && parseBpb(vbr))
        return true;
    // The primary may be unreadable; the backup normally sits at sector 6, but
    // that is only knowable from the primary, so try the standard location.
    if (vol.readAt(6ull * 512, vbr, sizeof vbr) == sizeof vbr && parseBpb(vbr))
        return true;
    return false;
}

std::unique_ptr<FatFilesystem> FatFilesystem::open(std::shared_ptr<ImageSource> vol) {
    if (!vol) return nullptr;
    auto fs = std::unique_ptr<FatFilesystem>(new FatFilesystem());
    fs->vol_ = std::move(vol);
    // Prefer the primary VBR; fall back to the backup copy when the primary is
    // unreadable or its geometry does not add up. On a drive with a weak start -
    // the usual reason an image lands on this tool - that fallback is the
    // difference between a mount and an "unknown volume".
    if (fs->mount(false)) return fs;
    if (fs->mount(true)) {
        fs->stats_.usedBackupBootRegion = true;
        fs->note("Primary boot sector unusable; mounted from the backup boot "
                 "sector at sector 6.");
        return fs;
    }
    return nullptr;
}

bool FatFilesystem::mount(bool fromBackup) {
    // BPB_BkBootSec lives in the primary, which is the sector we are replacing,
    // so the backup can only be looked for where the spec puts it.
    uint64_t vbrOff = fromBackup ? 6ull * 512 : 0;
    uint8_t v[512] = {};
    if (vol_->readAt(vbrOff, v, sizeof v) < sizeof v) return false;
    auto bpb = parseBpb(v);
    if (!bpb) return false;

    bytesPerSector_ = bpb->bytesPerSector;
    clusterSize_ = bpb->bytesPerSector * bpb->sectorsPerCluster;
    clusterCount_ = bpb->clusterCount;
    rootCluster_ = bpb->rootCluster;
    volumeBytes_ = bpb->totalSectors * bpb->bytesPerSector;
    dataByteOffset_ = bpb->dataStartSector * bpb->bytesPerSector;

    fatByteOffset_ = (static_cast<uint64_t>(bpb->reservedSectors) +
                      static_cast<uint64_t>(bpb->activeFat) * bpb->fatSizeSectors) *
                     bpb->bytesPerSector;
    fatByteLength_ = static_cast<uint64_t>(bpb->fatSizeSectors) * bpb->bytesPerSector;

    // The data region has to fit inside the volume. A backup boot sector from a
    // differently-sized former volume fails here rather than sending every read
    // off the end of the image.
    uint64_t dataEnd = dataByteOffset_ +
                       static_cast<uint64_t>(clusterCount_) * clusterSize_;
    if (dataEnd > volumeBytes_) return false;
    // ...and inside the image we were actually given, which is the check that
    // catches a truncated or still-imaging file.
    if (vol_->size() && dataByteOffset_ >= vol_->size()) return false;

    stats_.sizeBytes = volumeBytes_;
    stats_.bytesPerSector = bytesPerSector_;
    stats_.clusterSize = clusterSize_;
    stats_.clusterCount = clusterCount_;
    stats_.fatCount = static_cast<uint8_t>(bpb->numFats);

    // FAT[1] carries two status bits in its top nibble, both active-low: bit 27
    // is "was cleanly unmounted" and bit 26 is "no hard error was seen". They
    // are the only dirty-volume signal FAT32 has.
    uint8_t fat1[8] = {};
    if (vol_->readAt(fatByteOffset_, fat1, sizeof fat1) == sizeof fat1) {
        uint32_t e1 = rd32(fat1 + 4);
        // Only meaningful if FAT[0] holds the media descriptor it should; on a
        // damaged FAT these bits would otherwise read as alarming nonsense.
        if ((rd32(fat1) & FAT32_MASK) >= 0x0FFFFF00) {
            stats_.volumeDirty  = (e1 & 0x08000000) == 0;
            stats_.mediaFailure = (e1 & 0x04000000) == 0;
        }
    }
    if (stats_.volumeDirty)
        note("Volume flagged dirty: it was not unmounted cleanly, so some "
             "recent changes may not be reflected in the directories.");
    if (stats_.mediaFailure)
        note("Volume flagged with a media failure: the last driver to write it "
             "hit sectors it could not read.");

    note("FAT32 timestamps are stored in local time with no record of the time "
         "zone, so they are read as UTC. Dates may be off by the original "
         "machine's UTC offset.");

    readVolumeMetadata(bpb->fsInfoSector);
    return true;
}

void FatFilesystem::readVolumeMetadata(uint32_t fsInfoSector) {
    // The volume label lives in the root directory as an entry with the
    // volume-id attribute. It is also in the BPB at offset 0x47, but that copy
    // goes stale the moment the volume is renamed, so the directory wins.
    scanDirectory(rootCluster_, false, &volName_);

    // FAT32 has no allocation bitmap; FSInfo caches the free cluster count so a
    // driver does not have to sum the whole FAT at mount. It is a hint, not a
    // record - drivers may leave it stale - so it is only used when its two
    // signatures are intact and the count is in range.
    if (fsInfoSector == 0 || fsInfoSector == 0xFFFF) return;
    std::vector<uint8_t> fi(bytesPerSector_, 0);
    uint64_t off = static_cast<uint64_t>(fsInfoSector) * bytesPerSector_;
    if (vol_->readAt(off, fi.data(), fi.size()) < fi.size()) return;
    if (rd32(fi.data()) != 0x41615252) return;           // "RRaA"
    if (rd32(fi.data() + 484) != 0x61417272) return;     // "rrAa"
    uint32_t freeCount = rd32(fi.data() + 488);
    if (freeCount == 0xFFFFFFFF || freeCount > clusterCount_) return;  // unknown
    stats_.usedClusters = clusterCount_ - freeCount;
}

// ------------------------------------------------------------------- FAT ----

uint32_t FatFilesystem::fatNext(uint32_t cluster) const {
    if (!validCluster(cluster)) return 0;
    uint64_t off = fatByteOffset_ + static_cast<uint64_t>(cluster) * 4;
    if (off + 4 > fatByteOffset_ + fatByteLength_) return 0;

    std::lock_guard<std::mutex> lock(fatMutex_);
    uint64_t blockStart = off & ~static_cast<uint64_t>(FAT_BLOCK - 1);
    if (!fatBlockValid_ || blockStart != fatBlockStart_) {
        size_t want = static_cast<size_t>(
            std::min<uint64_t>(FAT_BLOCK,
                               fatByteOffset_ + fatByteLength_ - blockStart));
        fatBlock_.assign(want, 0);
        size_t got = vol_->readAt(blockStart, fatBlock_.data(), want);
        // A short read means unreadable FAT sectors; the zeros left behind read
        // back as "free", which chainExtents recovers from by falling through to
        // its contiguous assumption.
        if (got < want) fatBlock_.resize(want);
        fatBlockStart_ = blockStart;
        fatBlockValid_ = true;
    }
    size_t idx = static_cast<size_t>(off - blockStart);
    if (idx + 4 > fatBlock_.size()) return 0;
    return rd32(fatBlock_.data() + idx) & FAT32_MASK;
}

std::vector<FatFilesystem::Extent> FatFilesystem::chainExtents(
    uint32_t firstCluster, bool contiguous, uint64_t bytes) const {
    std::vector<Extent> out;
    if (bytes == 0 || !validCluster(firstCluster)) return out;

    uint64_t needed = (bytes + clusterSize_ - 1) / clusterSize_;
    uint64_t remaining = bytes;
    uint32_t cluster = firstCluster;
    uint64_t visited = 0;
    bool assumedContiguous = false;

    while (remaining > 0 && visited < needed && validCluster(cluster)) {
        uint64_t off = clusterToOffset(cluster);
        uint64_t len = std::min<uint64_t>(clusterSize_, remaining);
        // Coalesce physically adjacent clusters: a defragmented multi-gigabyte
        // file collapses to a single extent and one big sequential read.
        if (!out.empty() && out.back().off + out.back().len == off &&
            out.back().len % clusterSize_ == 0) {
            out.back().len += len;
        } else {
            out.push_back({off, len});
        }
        remaining -= len;
        ++visited;
        if (remaining == 0) break;

        uint32_t next;
        if (contiguous) {
            next = cluster + 1;
        } else {
            next = fatNext(cluster);
            // 0 is a free cluster, and the rest are end-of-chain or bad. Either
            // the chain is damaged or the entry outlived it; carrying on
            // contiguously is the standard recovery guess and recovers the whole
            // file whenever it was not fragmented, which is the common case.
            if (next == 0 || next == FAT_BAD || next >= FAT_EOF_MIN ||
                !validCluster(next)) {
                next = cluster + 1;
                assumedContiguous = true;
            }
        }
        cluster = next;
    }

    if (assumedContiguous)
        note("At least one file's cluster chain ended early; the rest was read "
             "as if contiguous. Verify such files before relying on them.");
    return out;
}

// ------------------------------------------------------- directory entries --

std::optional<FatFilesystem::Record> FatFilesystem::recordAt(uint64_t entryOffset) const {
    uint8_t e[ENTRY_SIZE] = {};
    if (entryOffset < dataByteOffset_) return std::nullopt;
    if (vol_->readAt(entryOffset, e, sizeof e) < sizeof e) return std::nullopt;

    uint8_t first = e[0];
    if (first == DIR_END) return std::nullopt;
    uint8_t attr = e[11];
    if (attr == ATTR_LONG_NAME) return std::nullopt;   // a name fragment, not a file
    if (attr & ATTR_RESERVED) return std::nullopt;
    if (attr & ATTR_VOLUME_ID) return std::nullopt;

    Record rec;
    rec.entryOffset = entryOffset;
    rec.isDeleted = (first == DIR_FREE);
    rec.contiguous = rec.isDeleted;
    rec.isDir = (attr & ATTR_DIRECTORY) != 0;
    rec.size = rec.isDir ? 0 : rd32(e + 28);
    rec.firstCluster = (static_cast<uint32_t>(rd16(e + 20)) << 16) | rd16(e + 26);
    rec.times.crtime = fatTimeToUnixNs(rd16(e + 16), rd16(e + 14), e[13]);
    rec.times.mtime  = fatTimeToUnixNs(rd16(e + 24), rd16(e + 22));
    rec.times.atime  = fatTimeToUnixNs(rd16(e + 18), 0);

    // The name is not reconstructed here - it lives in the entries *before*
    // this one. Callers that need it go through scanDirectory.
    if (!decodeShortName(e, rec.isDeleted, rec.isDeleted ? '_' : first, rec.name))
        return std::nullopt;
    if (rec.size > volumeBytes_) return std::nullopt;
    if (rec.size > 0 && !validCluster(rec.firstCluster)) return std::nullopt;
    return rec;
}

std::vector<FatFilesystem::Record> FatFilesystem::scanDirectory(
    uint32_t firstCluster, bool contiguous, std::string* labelOut) {
    std::vector<Record> out;
    if (!validCluster(firstCluster)) return out;

    uint32_t cluster = firstCluster;
    uint64_t clustersRead = 0;
    // A FAT directory carries no length: the chain says where it ends. The cap
    // stops a cross-linked or circular chain from spinning forever, and for a
    // deleted directory - which has no chain left at all - it is the only limit
    // there is besides the plausibility check below.
    uint64_t maxClusters = contiguous ? MAX_DELETED_DIR_CLUSTERS : clusterCount_;
    bool pastEnd = false;      // we have seen the end-of-directory marker
    size_t rejected = 0;

    // Long-name entries accumulate here until the short entry they belong to
    // turns up. They are stored highest-ordinal first, immediately before it,
    // and may straddle a cluster boundary - so this deliberately survives the
    // loop iteration.
    std::vector<std::array<uint8_t, ENTRY_SIZE>> lfn;

    std::vector<uint8_t> buf(clusterSize_);
    while (validCluster(cluster) && clustersRead < maxClusters) {
        size_t got = vol_->readAt(clusterToOffset(cluster), buf.data(), buf.size());
        if (got == 0) {
            note("A directory cluster could not be read; some entries in this "
                 "folder are missing.");
            break;
        }
        uint64_t clusterBase = clusterToOffset(cluster);

        for (size_t i = 0; i + ENTRY_SIZE <= got; i += ENTRY_SIZE) {
            const uint8_t* e = buf.data() + i;
            uint8_t first = e[0];
            uint8_t attr = e[11];

            if (first == DIR_END) {
                // Everything from here on is free space. It is worth reading
                // anyway - that is where a deleted file most often survives -
                // but nothing past this point is a live entry.
                pastEnd = true;
                lfn.clear();
                continue;
            }
            if (attr & ATTR_RESERVED) { lfn.clear(); ++rejected; continue; }
            if (isDotEntry(e)) { lfn.clear(); continue; }

            if (attr == ATTR_LONG_NAME) {
                if (lfn.size() >= MAX_LFN_ENTRIES) lfn.clear();
                std::array<uint8_t, ENTRY_SIZE> a{};
                std::memcpy(a.data(), e, ENTRY_SIZE);
                lfn.push_back(a);
                continue;
            }

            // A volume-label entry: the root's, which names the volume, or a
            // stray one in a subdirectory, which names nothing.
            if (attr & ATTR_VOLUME_ID) {
                if (labelOut && labelOut->empty() && first != DIR_FREE && !pastEnd) {
                    std::string label;
                    if (decodeLabel(e, label)) *labelOut = label;
                }
                lfn.clear();
                continue;
            }

            bool deleted = (first == DIR_FREE) || pastEnd;

            // Tie the accumulated long-name entries to this short entry. Every
            // one of them must carry the same checksum, and that checksum must
            // match the short name - which is what stops a long name from being
            // grafted onto the unrelated entry that happens to follow it.
            std::string longName;
            if (!lfn.empty()) {
                uint8_t cs = lfn[0][13];
                bool consistent = true;
                for (const auto& l : lfn)
                    if (l[13] != cs) { consistent = false; break; }
                if (consistent) {
                    uint8_t nameFirst = first;
                    if (first == DIR_FREE) {
                        // The original first byte is gone, but the checksum is
                        // invertible and hands it straight back.
                        nameFirst = recoverDeletedFirstByte(cs, e);
                    }
                    uint8_t probe[11];
                    std::memcpy(probe, e, 11);
                    probe[0] = nameFirst;
                    if (shortNameChecksum(probe) == cs) {
                        std::vector<uint16_t> units;
                        units.reserve(lfn.size() * LFN_CHARS_PER_ENTRY);
                        // Stored in reverse order: walk back to read forwards.
                        for (auto it = lfn.rbegin(); it != lfn.rend(); ++it) {
                            const uint8_t* l = it->data();
                            for (size_t k = 0; k < 5; ++k)  units.push_back(rd16(l + 1 + k * 2));
                            for (size_t k = 0; k < 6; ++k)  units.push_back(rd16(l + 14 + k * 2));
                            for (size_t k = 0; k < 2; ++k)  units.push_back(rd16(l + 28 + k * 2));
                        }
                        // Padded with 0xFFFF and terminated with 0x0000.
                        auto end = std::find_if(units.begin(), units.end(),
                            [](uint16_t u) { return u == 0x0000 || u == 0xFFFF; });
                        units.erase(end, units.end());
                        longName = utf16leToUtf8(units);
                    }
                }
            }
            lfn.clear();

            Record rec;
            rec.entryOffset = clusterBase + i;
            rec.isDeleted = deleted;
            // A deleted entry's chain has been freed and the FAT now describes
            // whatever was allocated over it, so following it would read another
            // file's data. Reading straight through is the standard guess.
            rec.contiguous = deleted;
            rec.isDir = (attr & ATTR_DIRECTORY) != 0;
            rec.size = rec.isDir ? 0 : rd32(e + 28);
            rec.firstCluster = (static_cast<uint32_t>(rd16(e + 20)) << 16) | rd16(e + 26);
            rec.times.crtime = fatTimeToUnixNs(rd16(e + 16), rd16(e + 14), e[13]);
            rec.times.mtime  = fatTimeToUnixNs(rd16(e + 24), rd16(e + 22));
            rec.times.atime  = fatTimeToUnixNs(rd16(e + 18), 0);

            std::string shortName;
            uint8_t nameFirst = first;
            if (first == DIR_FREE) nameFirst = '_';   // unrecoverable without a long name
            bool shortOk = decodeShortName(e, first == DIR_FREE, nameFirst, shortName);

            if (!longName.empty() && nameIsSafe(longName)) {
                rec.name = longName;
            } else if (shortOk && nameIsSafe(shortName)) {
                rec.name = shortName;
            } else {
                // Neither name survived: the slot is not really a directory
                // entry, or it is too damaged to name safely.
                ++rejected;
                continue;
            }

            // A stale slot can hold anything. These two are what keep debris out
            // of the listing without discarding genuinely recoverable files.
            if (rec.size > volumeBytes_) { ++rejected; continue; }
            if (rec.size > 0 && !validCluster(rec.firstCluster)) { ++rejected; continue; }
            if (rec.isDir && !validCluster(rec.firstCluster)) { ++rejected; continue; }

            out.push_back(std::move(rec));
        }

        ++clustersRead;
        uint32_t next;
        if (contiguous) {
            // No chain to follow. Stop as soon as the next cluster does not
            // read as directory entries, which is the only signal available
            // that the deleted directory ended here.
            next = cluster + 1;
            if (!validCluster(next)) break;
            uint8_t probe[ENTRY_SIZE * 4] = {};
            if (vol_->readAt(clusterToOffset(next), probe, sizeof probe) < sizeof probe)
                break;
            bool plausible = false;
            for (size_t k = 0; k < sizeof probe; k += ENTRY_SIZE) {
                if (probe[k] == DIR_END) continue;              // free slot
                if (probe[k + 11] & ATTR_RESERVED) { plausible = false; break; }
                plausible = true;
            }
            if (!plausible) break;
        } else {
            next = fatNext(cluster);
            if (next == 0 || next == FAT_BAD || next >= FAT_EOF_MIN ||
                !validCluster(next)) break;
        }
        if (next == cluster) break;
        cluster = next;
    }

    if (rejected)
        note("Skipped " + std::to_string(rejected) +
             " unreadable or corrupt directory entries.");
    return out;
}

// ----------------------------------------------------------- Filesystem API --

FsNode FatFilesystem::root() {
    FsNode n;
    n.id = 0;               // the root has no directory entry to point at
    n.name = volName_.empty() ? "FAT32 volume" : volName_;
    n.isDir = true;
    return n;
}

std::vector<FsNode> FatFilesystem::listDir(const FsNode& dir) {
    uint32_t cluster = rootCluster_;
    bool contiguous = false;
    // Everything below a deleted folder is deleted too, whatever the child
    // entries themselves still say. Deleting a folder only marks the folder's
    // own entry - the entries *inside* it are left exactly as they were, so they
    // look live. They are still worth listing, and often still readable, but the
    // folder's clusters are free space now and the user has to be told so rather
    // than shown thousands of files as if they were intact.
    bool inheritDeleted = dir.isDeleted;
    if (dir.id != 0) {
        auto rec = recordAt(dir.id);
        if (!rec || !rec->isDir) return {};
        if (!validCluster(rec->firstCluster)) return {};
        cluster = rec->firstCluster;
        // Callers that rebuild an FsNode from an id alone (the CLI does) have
        // no isDeleted to pass in, so take it from the entry itself.
        inheritDeleted = inheritDeleted || rec->isDeleted;
        contiguous = inheritDeleted;
    }

    auto records = scanDirectory(cluster, contiguous, nullptr);
    std::vector<FsNode> out;
    out.reserve(records.size());
    for (const auto& r : records) {
        FsNode n;
        n.id = r.entryOffset;
        n.name = r.name;
        n.isDir = r.isDir;
        n.isDeleted = r.isDeleted || inheritDeleted;
        n.size = r.isDir ? 0 : r.size;
        n.times = r.times;
        out.push_back(n);
    }
    return out;
}

bool FatFilesystem::readFileStream(const FsNode& file, const DataSink& sink) {
    auto rec = recordAt(file.id);
    if (!rec) return sink(nullptr, 0);
    // A file reached through a deleted parent has a freed chain too, even though
    // its own entry still looks live.
    if (file.isDeleted) rec->contiguous = true;
    return streamRecord(*rec, sink);
}

bool FatFilesystem::streamRecord(const Record& rec, const DataSink& sink) {
    if (rec.isDir || rec.size == 0) return sink(nullptr, 0);

    uint64_t written = 0;
    for (const auto& ex : chainExtents(rec.firstCluster, rec.contiguous, rec.size)) {
        uint64_t off = ex.off;
        uint64_t left = ex.len;
        std::vector<uint8_t> buf(static_cast<size_t>(std::min<uint64_t>(left, 1u << 20)));
        while (left > 0) {
            size_t want = static_cast<size_t>(std::min<uint64_t>(left, buf.size()));
            size_t got = vol_->readAt(off, buf.data(), want);
            if (got == 0) {
                // Unreadable sectors: pad with zeros rather than truncating, so
                // the exported file keeps the right length and everything after
                // the bad patch stays at its correct offset.
                note("Unreadable sectors in \"" + rec.name +
                     "\"; the gap was zero-filled.");
                std::fill(buf.begin(), buf.begin() + want, 0);
                got = want;
            }
            if (!sink(buf.data(), got)) return false;
            written += got;
            off += got;
            left -= got;
        }
    }
    // The chain ran out before the size was covered - a truncated image, or a
    // deleted file whose contiguous run walked off the end of the volume. Pad so
    // the exported file still has the length its directory entry claims.
    if (written < rec.size) {
        std::vector<uint8_t> zeros(static_cast<size_t>(
            std::min<uint64_t>(rec.size - written, 1u << 20)), 0);
        while (written < rec.size) {
            size_t n = static_cast<size_t>(
                std::min<uint64_t>(rec.size - written, zeros.size()));
            if (!sink(zeros.data(), n)) return false;
            written += n;
        }
    }
    return true;
}

std::vector<uint8_t> FatFilesystem::readFile(const FsNode& file) {
    std::vector<uint8_t> out;
    readFileStream(file, [&](const uint8_t* d, size_t n) {
        if (d && n) out.insert(out.end(), d, d + n);
        else if (n) out.resize(out.size() + n, 0);
        return true;
    });
    return out;
}

uint64_t FatFilesystem::dirIdentity(const FsNode& dir) {
    if (!dir.isDir) return 0;
    // The root directory has no entry of its own; its cluster is the one the
    // boot sector names.
    if (dir.id == 0) return rootCluster_;
    auto rec = recordAt(dir.id);
    if (!rec || !rec->isDir) return 0;
    // An empty directory can legitimately have no cluster allocated. 0 is the
    // "unknown" contract from the base class, and is right here too: a
    // directory with no clusters has no children to recurse into anyway.
    return rec->firstCluster;
}

FsTimes FatFilesystem::fileTimes(const FsNode& node) {
    if (node.id == 0) return node.times;
    if (auto rec = recordAt(node.id)) return rec->times;
    return node.times;
}

// ------------------------------------------------------------------- notes --

void FatFilesystem::note(const std::string& msg) const {
    std::lock_guard<std::mutex> lock(noteMutex_);
    if (std::find(notes_.begin(), notes_.end(), msg) == notes_.end())
        notes_.push_back(msg);
}

std::vector<std::string> FatFilesystem::notes() const {
    std::lock_guard<std::mutex> lock(noteMutex_);
    return notes_;
}

} // namespace de

#include "fs/exfat/exfat.h"
#include "core/byte_reader.h"
#include <algorithm>
#include <cstring>

namespace de {

namespace {

constexpr uint32_t SECTOR_BACKUP_VBR = 12;   // backup boot region

// Entry types. The top bit is "in use": clearing it is all that deleting a
// file does to the directory, which is why exFAT undelete works so well.
constexpr uint8_t ET_IN_USE       = 0x80;
constexpr uint8_t ET_END          = 0x00;
constexpr uint8_t ET_BITMAP       = 0x81;
constexpr uint8_t ET_UPCASE       = 0x82;
constexpr uint8_t ET_VOLUME_LABEL = 0x83;
constexpr uint8_t ET_FILE         = 0x85;
constexpr uint8_t ET_STREAM       = 0xC0;
constexpr uint8_t ET_FILE_NAME    = 0xC1;

constexpr uint16_t ATTR_DIRECTORY = 0x0010;

constexpr size_t ENTRY_SIZE = 32;
constexpr uint32_t MAX_SECONDARY = 18;       // 1 stream + up to 17 name entries
constexpr size_t MAX_NAME_CHARS = 255;

// FAT sentinels.
constexpr uint32_t FAT_BAD = 0xFFFFFFF7;
constexpr uint32_t FAT_EOF = 0xFFFFFFFF;

// Read the FAT in chunks this big rather than four bytes at a time.
constexpr size_t FAT_BLOCK = 64 * 1024;

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

// An exFAT timestamp is a packed local-time DOS date plus, for create and
// modify, a 10-millisecond refinement and a UTC offset. The offset byte is
// valid only when its top bit is set; older formatters leave it clear, in
// which case there is nothing better to do than take the stamp as UTC.
int64_t exfatTimeToUnixNs(uint32_t ts, uint8_t tenMs, uint8_t utcOffset) {
    if (ts == 0) return 0;
    unsigned sec   = (ts & 0x1F) * 2;
    unsigned mins  = (ts >> 5) & 0x3F;
    unsigned hour  = (ts >> 11) & 0x1F;
    unsigned day   = (ts >> 16) & 0x1F;
    unsigned month = (ts >> 21) & 0x0F;
    unsigned year  = ((ts >> 25) & 0x7F) + 1980;
    if (month < 1 || month > 12 || day < 1 || day > 31) return 0;
    if (hour > 23 || mins > 59 || sec > 59) return 0;

    int64_t days = daysFromCivil(static_cast<int64_t>(year), month, day);
    int64_t secs = days * 86400 + hour * 3600 + mins * 60 + sec;

    if (utcOffset & 0x80) {
        // Low 7 bits: a two's-complement count of 15-minute steps.
        int8_t steps = static_cast<int8_t>(utcOffset << 1) / 2;
        secs -= static_cast<int64_t>(steps) * 15 * 60;
    }
    // tenMs only refines create/modify, and only up to 199 (2 seconds).
    int64_t ns = secs * 1000000000ll;
    if (tenMs <= 199) ns += static_cast<int64_t>(tenMs) * 10000000ll;
    return ns;
}

// UTF-16LE -> UTF-8, handling surrogate pairs. exFAT names are UTF-16 with an
// explicit length, so there is no NUL to look for.
std::string utf16leToUtf8(const uint8_t* p, size_t units) {
    std::string out;
    out.reserve(units);
    for (size_t i = 0; i < units; ++i) {
        uint32_t cp = rd16(p + i * 2);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units) {
            uint32_t lo = rd16(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
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
    return out;
}

// The entry-set checksum, over every byte of the set except the checksum field
// itself (bytes 2-3 of the primary entry).
//
// The in-use bit is forced back on for every entry type byte first: a deleted
// set has that bit cleared in place, so checksumming the bytes as they lie
// would never match, while checksumming them as they were before the delete
// tells us whether the set is intact. That distinction is what separates a
// recoverable deleted file from a slot full of stale garbage.
uint16_t entrySetChecksum(const std::vector<uint8_t>& raw, size_t entries) {
    uint16_t sum = 0;
    size_t n = entries * ENTRY_SIZE;
    for (size_t i = 0; i < n && i < raw.size(); ++i) {
        if (i == 2 || i == 3) continue;
        uint8_t b = raw[i];
        if (i % ENTRY_SIZE == 0) b |= ET_IN_USE;
        sum = static_cast<uint16_t>(((sum << 15) | (sum >> 1)) + b);
    }
    return sum;
}

// Names that would escape the export directory if we ever wrote them out
// verbatim. A damaged entry can hold anything, so this is a hard filter, not a
// nicety.
bool nameIsSafe(const std::string& s) {
    if (s.empty() || s == "." || s == "..") return false;
    return s.find('/') == std::string::npos &&
           s.find('\0') == std::string::npos;
}

} // namespace

// ---------------------------------------------------------------- geometry --

uint64_t ExfatFilesystem::clusterToOffset(uint32_t cluster) const {
    return heapByteOffset_ +
           static_cast<uint64_t>(cluster - 2) * clusterSize_;
}

bool ExfatFilesystem::validCluster(uint32_t cluster) const {
    return cluster >= 2 && cluster < clusterCount_ + 2;
}

// -------------------------------------------------------------------- mount --

bool ExfatFilesystem::probe(ImageSource& vol) {
    uint8_t vbr[512] = {};
    for (uint32_t sec : {0u, SECTOR_BACKUP_VBR}) {
        if (vol.readAt(static_cast<uint64_t>(sec) * 512, vbr, sizeof vbr) < sizeof vbr)
            continue;
        if (std::memcmp(vbr + 3, "EXFAT   ", 8) != 0) continue;
        // MustBeZero: what tells a real exFAT VBR apart from a FAT32 one that
        // happens to carry the string in its OEM field.
        bool zero = true;
        for (size_t i = 11; i < 64; ++i)
            if (vbr[i]) { zero = false; break; }
        if (!zero) continue;
        if (vbr[510] != 0x55 || vbr[511] != 0xAA) continue;
        return true;
    }
    return false;
}

std::unique_ptr<ExfatFilesystem> ExfatFilesystem::open(std::shared_ptr<ImageSource> vol) {
    if (!vol) return nullptr;
    auto fs = std::unique_ptr<ExfatFilesystem>(new ExfatFilesystem());
    fs->vol_ = std::move(vol);
    // Prefer the primary VBR; fall back to the backup copy at sector 12 when
    // the primary is unreadable or its geometry does not add up. On a drive
    // with a weak start - the usual reason an image lands on this tool - that
    // fallback is the difference between a mount and an "unknown volume".
    if (fs->mount(false)) return fs;
    if (fs->mount(true)) {
        fs->stats_.usedBackupBootRegion = true;
        fs->note("Primary boot sector unusable; mounted from the backup boot "
                 "region at sector 12.");
        return fs;
    }
    return nullptr;
}

bool ExfatFilesystem::mount(bool fromBackup) {
    uint64_t vbrOff = fromBackup ? static_cast<uint64_t>(SECTOR_BACKUP_VBR) * 512 : 0;
    uint8_t v[512] = {};
    if (vol_->readAt(vbrOff, v, sizeof v) < sizeof v) return false;
    if (std::memcmp(v + 3, "EXFAT   ", 8) != 0) return false;
    if (v[510] != 0x55 || v[511] != 0xAA) return false;

    uint64_t volumeLengthSectors = rd64(v + 0x48);
    uint32_t fatOffsetSectors    = rd32(v + 0x50);
    uint32_t fatLengthSectors    = rd32(v + 0x54);
    uint32_t heapOffsetSectors   = rd32(v + 0x58);
    uint32_t clusterCount        = rd32(v + 0x5C);
    uint32_t rootCluster         = rd32(v + 0x60);
    uint16_t volumeFlags         = rd16(v + 0x6A);
    uint8_t  bytesPerSectorShift = v[0x6C];
    uint8_t  sectorsPerClusterShift = v[0x6D];
    uint8_t  numberOfFats        = v[0x6E];

    // Ranges are the ones the spec permits; anything outside means we are
    // looking at a damaged or misidentified sector, not an exFAT volume.
    if (bytesPerSectorShift < 9 || bytesPerSectorShift > 12) return false;
    if (sectorsPerClusterShift > 25 - bytesPerSectorShift) return false;
    if (numberOfFats != 1 && numberOfFats != 2) return false;
    if (clusterCount == 0 || clusterCount > 0xFFFFFFF5) return false;
    if (rootCluster < 2 || rootCluster >= clusterCount + 2) return false;
    if (fatLengthSectors == 0 || fatOffsetSectors == 0) return false;

    bytesPerSector_ = 1u << bytesPerSectorShift;
    uint32_t sectorsPerCluster = 1u << sectorsPerClusterShift;
    clusterSize_ = bytesPerSector_ * sectorsPerCluster;
    clusterCount_ = clusterCount;
    rootCluster_ = rootCluster;
    volumeBytes_ = volumeLengthSectors * bytesPerSector_;
    heapByteOffset_ = static_cast<uint64_t>(heapOffsetSectors) * bytesPerSector_;

    // With two FATs (TexFAT), bit 0 of the volume flags says which one is live.
    uint32_t activeFat = (numberOfFats == 2 && (volumeFlags & 0x0001)) ? 1 : 0;
    fatByteOffset_ = (static_cast<uint64_t>(fatOffsetSectors) +
                      static_cast<uint64_t>(activeFat) * fatLengthSectors) *
                     bytesPerSector_;
    fatByteLength_ = static_cast<uint64_t>(fatLengthSectors) * bytesPerSector_;

    // The heap has to fit in the volume, and the FAT has to be big enough to
    // describe the heap. A backup VBR from a differently-sized former volume
    // fails here rather than sending every read off the end of the image.
    uint64_t heapEnd = heapByteOffset_ +
                       static_cast<uint64_t>(clusterCount_) * clusterSize_;
    if (heapEnd > volumeBytes_) return false;
    if (fatByteLength_ < (static_cast<uint64_t>(clusterCount_) + 2) * 4) return false;

    stats_.sizeBytes = volumeBytes_;
    stats_.bytesPerSector = bytesPerSector_;
    stats_.clusterSize = clusterSize_;
    stats_.clusterCount = clusterCount_;
    stats_.fatCount = numberOfFats;
    stats_.volumeDirty = (volumeFlags & 0x0002) != 0;
    stats_.mediaFailure = (volumeFlags & 0x0004) != 0;

    if (stats_.volumeDirty)
        note("Volume flagged dirty: it was not unmounted cleanly, so some "
             "recent changes may not be reflected in the directories.");
    if (stats_.mediaFailure)
        note("Volume flagged with a media failure: the last driver to write it "
             "hit sectors it could not read.");

    readRootMetadata();
    return true;
}

void ExfatFilesystem::readRootMetadata() {
    std::vector<std::vector<uint8_t>> specials;
    // The root directory has no entry set of its own, so there is no length to
    // go by - but it is always FAT-chained, so the chain says where it ends.
    scanDirectory(rootCluster_, false, 0, true, &specials);

    for (const auto& e : specials) {
        if (e.size() < ENTRY_SIZE) continue;
        switch (e[0]) {
        case ET_VOLUME_LABEL: {
            size_t chars = std::min<size_t>(e[1], 11);
            volName_ = utf16leToUtf8(e.data() + 2, chars);
            break;
        }
        case ET_BITMAP: {
            // Bit 0 of the flags selects the second FAT's bitmap; with one FAT
            // there is only ever the first.
            if (e[1] & 0x01) break;
            uint32_t first = rd32(e.data() + 0x14);
            uint64_t len = rd64(e.data() + 0x18);
            if (!validCluster(first) || len == 0) break;
            // Count the allocated clusters so the UI can show how full the
            // volume is - and, more usefully here, how much of it is free
            // space that a deleted file could still be sitting in.
            uint64_t cap = (static_cast<uint64_t>(clusterCount_) + 7) / 8;
            len = std::min(len, cap);
            uint64_t used = 0;
            for (const auto& ex : chainExtents(first, false, len)) {
                std::vector<uint8_t> buf(static_cast<size_t>(ex.len));
                size_t got = vol_->readAt(ex.off, buf.data(), buf.size());
                for (size_t i = 0; i < got; ++i)
                    used += static_cast<unsigned>(__builtin_popcount(buf[i]));
            }
            stats_.usedClusters = std::min<uint64_t>(used, clusterCount_);
            break;
        }
        default:
            break; // up-case table: only needed for name comparison, not reads
        }
    }
}

// ----------------------------------------------------------------- FAT ------

uint32_t ExfatFilesystem::fatNext(uint32_t cluster) const {
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
        // A short read means unreadable FAT sectors; the zeros left behind
        // read back as "end of chain", which chainExtents recovers from by
        // falling through to its contiguous assumption.
        if (got < want) fatBlock_.resize(want);
        fatBlockStart_ = blockStart;
        fatBlockValid_ = true;
    }
    size_t idx = static_cast<size_t>(off - blockStart);
    if (idx + 4 > fatBlock_.size()) return 0;
    return rd32(fatBlock_.data() + idx);
}

std::vector<ExfatFilesystem::Extent> ExfatFilesystem::chainExtents(
    uint32_t firstCluster, bool noFatChain, uint64_t bytes) const {
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
        if (noFatChain) {
            next = cluster + 1;
        } else {
            next = fatNext(cluster);
            if (next == FAT_EOF || next == FAT_BAD || !validCluster(next)) {
                // Either the file was deleted (which frees its chain) or the
                // FAT is damaged. Carrying on contiguously is the standard
                // recovery guess and recovers the whole file whenever it was
                // not fragmented, which is the common case.
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

std::vector<uint8_t> ExfatFilesystem::readEntries(uint64_t off, uint32_t entries,
                                                  Chain chain) const {
    std::vector<uint8_t> out;
    if (entries == 0) return out;
    out.reserve(entries * ENTRY_SIZE);

    uint64_t want = static_cast<uint64_t>(entries) * ENTRY_SIZE;
    uint64_t cur = off;
    while (want > 0) {
        if (cur < heapByteOffset_) break;
        uint64_t rel = cur - heapByteOffset_;
        uint32_t cluster = static_cast<uint32_t>(rel / clusterSize_) + 2;
        if (!validCluster(cluster)) break;
        uint64_t inCluster = rel % clusterSize_;
        uint64_t take = std::min<uint64_t>(want, clusterSize_ - inCluster);

        size_t before = out.size();
        out.resize(before + static_cast<size_t>(take));
        size_t got = vol_->readAt(cur, out.data() + before, static_cast<size_t>(take));
        if (got < take) { out.resize(before + got); break; }
        want -= take;
        if (want == 0) break;

        // Crossed into the next cluster: follow the chain, and fall back to
        // the adjacent cluster when the FAT does not give a usable answer.
        uint32_t next = cluster + 1;
        if (chain == Chain::UseFat) {
            uint32_t f = fatNext(cluster);
            if (f != FAT_EOF && f != FAT_BAD && validCluster(f)) next = f;
        }
        if (!validCluster(next)) break;
        cur = clusterToOffset(next);
    }
    return out;
}

std::optional<ExfatFilesystem::Record> ExfatFilesystem::parseEntrySet(
    const std::vector<uint8_t>& raw, uint64_t entryOffset) const {
    if (raw.size() < ENTRY_SIZE * 2) return std::nullopt;
    uint8_t type = raw[0];
    if ((type | ET_IN_USE) != ET_FILE) return std::nullopt;

    Record rec;
    rec.entryOffset = entryOffset;
    rec.isDeleted = (type & ET_IN_USE) == 0;

    uint8_t secondaryCount = raw[1];
    if (secondaryCount < 1 || secondaryCount > MAX_SECONDARY) return std::nullopt;
    size_t setEntries = static_cast<size_t>(secondaryCount) + 1;
    if (raw.size() < setEntries * ENTRY_SIZE) return std::nullopt;

    uint16_t attrs = rd16(raw.data() + 0x04);
    rec.isDir = (attrs & ATTR_DIRECTORY) != 0;
    rec.times.crtime = exfatTimeToUnixNs(rd32(raw.data() + 0x08), raw[0x14], raw[0x16]);
    rec.times.mtime  = exfatTimeToUnixNs(rd32(raw.data() + 0x0C), raw[0x15], raw[0x17]);
    // Access time has no 10 ms field - it is only ever whole seconds.
    rec.times.atime  = exfatTimeToUnixNs(rd32(raw.data() + 0x10), 0, raw[0x18]);

    // Secondary entries: exactly one stream extension, then the name.
    const uint8_t* stream = nullptr;
    std::string name;
    size_t nameUnitsSeen = 0;
    for (size_t i = 1; i < setEntries; ++i) {
        const uint8_t* e = raw.data() + i * ENTRY_SIZE;
        uint8_t t = static_cast<uint8_t>(e[0] | ET_IN_USE);
        if (t == ET_STREAM) {
            if (stream) return std::nullopt; // two stream entries: malformed
            stream = e;
        } else if (t == ET_FILE_NAME) {
            if (!stream) return std::nullopt; // name before stream: malformed
            name += utf16leToUtf8(e + 2, 15);
            nameUnitsSeen += 15;
        }
        // Other secondary types (vendor extensions) carry nothing we need.
    }
    if (!stream) return std::nullopt;

    uint8_t flags = stream[0x01];
    uint8_t nameLength = stream[0x03];
    rec.validSize    = rd64(stream + 0x08);
    rec.firstCluster = rd32(stream + 0x14);
    rec.size         = rd64(stream + 0x18);
    rec.noFatChain   = (flags & 0x02) != 0;

    if (nameLength == 0 || nameLength > MAX_NAME_CHARS) return std::nullopt;
    if (nameUnitsSeen < nameLength) return std::nullopt;
    // The name entries are padded out to a multiple of 15 units; NameLength is
    // what says where the real name stops. Re-decode exactly that many units
    // so a surrogate pair straddling the cut is handled once, correctly.
    {
        std::vector<uint8_t> units;
        units.reserve(static_cast<size_t>(nameLength) * 2);
        size_t remaining = nameLength;
        for (size_t i = 1; i < setEntries && remaining; ++i) {
            const uint8_t* e = raw.data() + i * ENTRY_SIZE;
            if (static_cast<uint8_t>(e[0] | ET_IN_USE) != ET_FILE_NAME) continue;
            size_t take = std::min<size_t>(15, remaining);
            units.insert(units.end(), e + 2, e + 2 + take * 2);
            remaining -= take;
        }
        name = utf16leToUtf8(units.data(), units.size() / 2);
    }
    if (!nameIsSafe(name)) return std::nullopt;
    rec.name = name;

    // Size sanity: a directory entry claiming more bytes than the volume holds
    // is a corrupt or stale slot, not a very big file.
    if (rec.size > volumeBytes_) return std::nullopt;
    if (rec.size > 0 && !validCluster(rec.firstCluster)) return std::nullopt;
    return rec;
}

std::optional<ExfatFilesystem::Record> ExfatFilesystem::recordAt(uint64_t entryOffset) const {
    auto head = readEntries(entryOffset, 1);
    if (head.size() < ENTRY_SIZE) return std::nullopt;
    uint8_t secondaryCount = head[1];
    if (secondaryCount < 1 || secondaryCount > MAX_SECONDARY) return std::nullopt;
    uint32_t entries = secondaryCount + 1u;

    // An id on its own does not say whether the directory holding it is
    // FAT-chained or contiguous, and it matters only when the set straddles a
    // cluster boundary. Read it both ways if need be and let the entry set
    // checksum pick the one that actually reassembled the set.
    auto attempt = [&](Chain chain) -> std::optional<Record> {
        auto raw = readEntries(entryOffset, entries, chain);
        if (raw.size() < static_cast<size_t>(entries) * ENTRY_SIZE) return std::nullopt;
        auto rec = parseEntrySet(raw, entryOffset);
        if (!rec) return std::nullopt;
        if (entrySetChecksum(raw, entries) != rd16(raw.data() + 2)) return std::nullopt;
        return rec;
    };

    if (auto rec = attempt(Chain::UseFat)) return rec;
    if (auto rec = attempt(Chain::Contiguous)) return rec;
    // Neither checksum matched: the set is damaged. Hand back whatever parses,
    // because a file with a scrambled name entry is still worth exporting.
    return parseEntrySet(readEntries(entryOffset, entries), entryOffset);
}

std::vector<ExfatFilesystem::Record> ExfatFilesystem::scanDirectory(
    uint32_t firstCluster, bool noFatChain, uint64_t sizeBytes, bool wantSpecials,
    std::vector<std::vector<uint8_t>>* specials) {
    std::vector<Record> out;
    if (!validCluster(firstCluster)) return out;

    Chain chain = noFatChain ? Chain::Contiguous : Chain::UseFat;
    uint32_t cluster = firstCluster;
    uint64_t clustersRead = 0;
    // How far to go. A contiguous directory has no end-of-chain marker at all,
    // so its DataLength is the only thing that says where it stops - without
    // this the walk runs to the end of the volume. The fallback cap also stops
    // a FAT loop (a cross-linked or circular chain) from spinning forever.
    uint64_t maxClusters = clusterCount_;
    if (sizeBytes > 0)
        maxClusters = (sizeBytes + clusterSize_ - 1) / clusterSize_;
    else if (noFatChain)
        maxClusters = 1;  // contiguous and no length: all we can trust is one
    bool pastEnd = false;   // we have seen the end-of-directory marker
    size_t rejected = 0;

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
            uint8_t type = buf[i];
            if (type == ET_END) { pastEnd = true; continue; }

            uint8_t base = static_cast<uint8_t>(type | ET_IN_USE);
            bool inUse = (type & ET_IN_USE) != 0;

            if (base != ET_FILE) {
                if (wantSpecials && specials && inUse &&
                    (base == ET_VOLUME_LABEL || base == ET_BITMAP || base == ET_UPCASE))
                    specials->emplace_back(buf.begin() + i,
                                           buf.begin() + i + ENTRY_SIZE);
                continue;
            }

            uint8_t secondaryCount = buf[i + 1];
            if (secondaryCount < 1 || secondaryCount > MAX_SECONDARY) {
                ++rejected;
                continue;
            }
            size_t setEntries = static_cast<size_t>(secondaryCount) + 1;
            uint64_t setOffset = clusterBase + i;

            std::vector<uint8_t> raw;
            if (i + setEntries * ENTRY_SIZE <= got) {
                raw.assign(buf.begin() + i, buf.begin() + i + setEntries * ENTRY_SIZE);
            } else {
                // The set runs past this cluster; readEntries follows the chain.
                raw = readEntries(setOffset, static_cast<uint32_t>(setEntries), chain);
            }

            auto rec = parseEntrySet(raw, setOffset);
            if (!rec) { ++rejected; continue; }

            // Entries found after the end-of-directory marker are debris left
            // by a compaction. They are worth surfacing - that is where a
            // deleted file often survives - but only when the set checksum
            // still validates, which garbage will not.
            if (pastEnd) {
                uint16_t stored = rd16(raw.data() + 2);
                if (entrySetChecksum(raw, setEntries) != stored) { ++rejected; continue; }
                rec->isDeleted = true;
            }
            out.push_back(*rec);
            // Skip the secondaries we just consumed.
            i += (setEntries - 1) * ENTRY_SIZE;
        }

        ++clustersRead;
        uint32_t next = noFatChain ? cluster + 1 : fatNext(cluster);
        if (next == FAT_EOF || next == FAT_BAD || !validCluster(next)) break;
        if (next == cluster) break;
        cluster = next;
        if (clustersRead >= maxClusters) break;
    }

    if (rejected)
        note("Skipped " + std::to_string(rejected) +
             " unreadable or corrupt directory entries.");
    return out;
}

// ------------------------------------------------------------ Filesystem API --

FsNode ExfatFilesystem::root() {
    FsNode n;
    n.id = 0;               // the root has no directory entry to point at
    n.name = volName_.empty() ? "exFAT volume" : volName_;
    n.isDir = true;
    return n;
}

std::vector<FsNode> ExfatFilesystem::listDir(const FsNode& dir) {
    uint32_t cluster = rootCluster_;
    bool noFatChain = false;
    uint64_t sizeBytes = 0;
    // Everything below a deleted folder is deleted too, whatever the child
    // entries themselves still say. Deleting a folder only clears the in-use
    // bit on the folder's own entry set - the entries *inside* it are left
    // exactly as they were, so they look live. They are still worth listing,
    // and often still readable, but the folder's clusters are free space now
    // and the user has to be told so rather than shown thousands of files as
    // if they were intact.
    bool inheritDeleted = dir.isDeleted;
    if (dir.id != 0) {
        auto rec = recordAt(dir.id);
        if (!rec || !rec->isDir) return {};
        if (!validCluster(rec->firstCluster)) return {};
        cluster = rec->firstCluster;
        noFatChain = rec->noFatChain;
        sizeBytes = rec->size;
        // Callers that rebuild an FsNode from an id alone (the CLI does) have
        // no isDeleted to pass in, so take it from the entry set itself.
        inheritDeleted = inheritDeleted || rec->isDeleted;
    }

    auto records = scanDirectory(cluster, noFatChain, sizeBytes, dir.id == 0, nullptr);
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

bool ExfatFilesystem::readFileStream(const FsNode& file, const DataSink& sink) {
    auto rec = recordAt(file.id);
    if (!rec) return sink(nullptr, 0);
    return streamRecord(*rec, sink);
}

bool ExfatFilesystem::streamRecord(const Record& rec, const DataSink& sink) {
    if (rec.isDir || rec.size == 0) return sink(nullptr, 0);

    // Bytes past ValidDataLength were never written, so the filesystem defines
    // them as zero. Some formatters (mostly cameras) never maintain the field
    // and leave it at zero on a non-empty file; trusting it there would export
    // nothing but zeros, so in that case the data length wins.
    uint64_t valid = rec.size;
    if (rec.validSize > 0 && rec.validSize < rec.size) valid = rec.validSize;

    uint64_t written = 0;
    for (const auto& ex : chainExtents(rec.firstCluster, rec.noFatChain, valid)) {
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
    // Zero-fill the tail past ValidDataLength.
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

std::vector<uint8_t> ExfatFilesystem::readFile(const FsNode& file) {
    std::vector<uint8_t> out;
    readFileStream(file, [&](const uint8_t* d, size_t n) {
        if (d && n) out.insert(out.end(), d, d + n);
        else if (n) out.resize(out.size() + n, 0);
        return true;
    });
    return out;
}

FsTimes ExfatFilesystem::fileTimes(const FsNode& node) {
    if (node.id == 0) return node.times;
    if (auto rec = recordAt(node.id)) return rec->times;
    return node.times;
}

// ------------------------------------------------------------------- notes --

void ExfatFilesystem::note(const std::string& msg) const {
    std::lock_guard<std::mutex> lock(noteMutex_);
    if (std::find(notes_.begin(), notes_.end(), msg) == notes_.end())
        notes_.push_back(msg);
}

std::vector<std::string> ExfatFilesystem::notes() const {
    std::lock_guard<std::mutex> lock(noteMutex_);
    return notes_;
}

} // namespace de

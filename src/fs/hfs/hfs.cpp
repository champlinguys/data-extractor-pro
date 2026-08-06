#include "fs/hfs/hfs.h"
#include "core/byte_reader.h"
#include <algorithm>
#include <cstring>

namespace de {

namespace {

// HFS epoch is 1904-01-01, Unix epoch is 1970-01-01; the difference is
// 66 years including 17 leap days = 2082844800 seconds.
constexpr int64_t HFS_TO_UNIX_EPOCH_DELTA = 2082844800;

int64_t hfsDateToUnix(uint32_t v) {
    if (v == 0) return 0;
    return static_cast<int64_t>(v) - HFS_TO_UNIX_EPOCH_DELTA;
}

// Same conversion, in the nanoseconds-since-Unix-epoch unit FsTimes uses.
// Classic HFS dates are whole seconds in the Mac's *local* time; there is no
// stored offset to undo, so they are exported as-is.
int64_t hfsDateToUnixNs(uint32_t v) {
    if (v == 0) return 0;
    return hfsDateToUnix(v) * 1000000000ll;
}

// MacRoman -> Unicode codepoint table for bytes 0x80-0xFF (0x00-0x7F is ASCII).
constexpr char32_t kMacRomanHigh[128] = {
    0x00C4,0x00C5,0x00C7,0x00C9,0x00D1,0x00D6,0x00DC,0x00E1,
    0x00E0,0x00E2,0x00E4,0x00E3,0x00E5,0x00E7,0x00E9,0x00E8,
    0x00EA,0x00EB,0x00ED,0x00EC,0x00EE,0x00EF,0x00F1,0x00F3,
    0x00F2,0x00F4,0x00F6,0x00F5,0x00FA,0x00F9,0x00FB,0x00FC,
    0x2020,0x00B0,0x00A2,0x00A3,0x00A7,0x2022,0x00B6,0x00DF,
    0x00AE,0x00A9,0x2122,0x00B4,0x00A8,0x2260,0x00C6,0x00D8,
    0x221E,0x00B1,0x2264,0x2265,0x00A5,0x00B5,0x2202,0x2211,
    0x220F,0x03C0,0x222B,0x00AA,0x00BA,0x03A9,0x00E6,0x00F8,
    0x00BF,0x00A1,0x00AC,0x221A,0x0192,0x2248,0x2206,0x00AB,
    0x00BB,0x2026,0x00A0,0x00C0,0x00C3,0x00D5,0x0152,0x0153,
    0x2013,0x2014,0x201C,0x201D,0x2018,0x2019,0x00F7,0x25CA,
    0x00FF,0x0178,0x2044,0x20AC,0x2039,0x203A,0xFB01,0xFB02,
    0x2021,0x00B7,0x201A,0x201E,0x2030,0x00C2,0x00CA,0x00C1,
    0x00CB,0x00C8,0x00CD,0x00CE,0x00CF,0x00CC,0x00D3,0x00D4,
    0xF8FF,0x00D2,0x00DA,0x00DB,0x00D9,0x0131,0x02C6,0x02DC,
    0x00AF,0x02D8,0x02D9,0x02DA,0x00B8,0x02DD,0x02DB,0x02C7,
};

void appendUtf8(std::string& out, char32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
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

// Safe big-endian reads into a possibly-truncated/corrupt record: return 0
// instead of throwing when the field falls past the end of `d`.
uint32_t safeBE32(const std::vector<uint8_t>& d, size_t off) {
    if (off + 4 > d.size()) return 0;
    return rdBE32(d.data() + off);
}
uint16_t safeBE16(const std::vector<uint8_t>& d, size_t off) {
    if (off + 2 > d.size()) return 0;
    return rdBE16(d.data() + off);
}
// Mac type/creator codes are 4 raw bytes (often non-ASCII); render as a
// best-effort Latin-1-ish string, empty if the record is too short to hold one.
std::string safeFourCC(const std::vector<uint8_t>& d, size_t off) {
    if (off + 4 > d.size()) return {};
    return std::string(reinterpret_cast<const char*>(d.data() + off), 4);
}

constexpr uint8_t CDR_DIR = 1;
constexpr uint8_t CDR_FILE = 2;
// CDR_DIR_THREAD = 3, CDR_FILE_THREAD = 4 are not needed for listing/export.

} // namespace

std::string HfsFilesystem::macRomanToUtf8(const uint8_t* p, size_t len) {
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = p[i];
        if (b < 0x80) appendUtf8(out, b);
        else appendUtf8(out, kMacRomanHigh[b - 0x80]);
    }
    return out;
}

bool HfsFilesystem::probe(ImageSource& vol) {
    uint8_t sig[2];
    return vol.readAt(2 * SECTOR, sig, 2) == 2 && sig[0] == 'B' && sig[1] == 'D';
}

std::unique_ptr<HfsFilesystem> HfsFilesystem::open(std::shared_ptr<ImageSource> vol) {
    if (!vol || !probe(*vol)) return nullptr;
    auto fs = std::unique_ptr<HfsFilesystem>(new HfsFilesystem());
    fs->vol_ = std::move(vol);
    fs->volSize_ = fs->vol_->size();
    if (!fs->parseMdb()) return nullptr;
    fs->loadSpecialFiles();
    fs->parseCatalog();
    return fs;
}

std::vector<uint8_t> HfsFilesystem::readAt(uint64_t off, size_t len) const {
    return vol_->read(off, len);
}

std::vector<HfsFilesystem::Extent> HfsFilesystem::parseExtentRecord(const uint8_t* p) {
    std::vector<Extent> ex;
    for (int i = 0; i < 3; ++i) {
        uint32_t start = rdBE16(p + i * 4);
        uint32_t count = rdBE16(p + i * 4 + 2);
        if (count) ex.push_back({start, count});
    }
    return ex;
}

bool HfsFilesystem::parseMdb() {
    auto b = readAt(2 * SECTOR, SECTOR);
    if (b.size() < 0x9E || b[0] != 'B' || b[1] != 'D') return false;

    ablkSize_ = rdBE32(&b[0x14]);       // drAlBlkSiz
    uint16_t nAlBlks = rdBE16(&b[0x12]); // drNmAlBlks
    alBlSt_ = rdBE16(&b[0x1C]);          // drAlBlSt (sectors)
    if (ablkSize_ == 0 || ablkSize_ % SECTOR != 0) return false;
    sectorsPerAblk_ = ablkSize_ / SECTOR;
    (void)nAlBlks;

    uint8_t vnlen = std::min<uint8_t>(b[0x24], 27);
    volName_ = macRomanToUtf8(&b[0x25], vnlen);

    xtSize_ = rdBE32(&b[0x82]);
    xtExtents_ = parseExtentRecord(&b[0x86]);
    ctSize_ = rdBE32(&b[0x92]);
    ctExtents_ = parseExtentRecord(&b[0x96]);
    return true;
}

uint64_t HfsFilesystem::ablkOffset(uint32_t ablk) const {
    return (static_cast<uint64_t>(alBlSt_) + static_cast<uint64_t>(ablk) * sectorsPerAblk_) * SECTOR;
}

std::vector<uint8_t> HfsFilesystem::readExtents(const std::vector<Extent>& extents, size_t length) const {
    std::vector<uint8_t> out;
    out.reserve(length);
    for (const auto& e : extents) {
        if (e.count == 0) continue;
        auto chunk = readAt(ablkOffset(e.start), static_cast<size_t>(e.count) * ablkSize_);
        out.insert(out.end(), chunk.begin(), chunk.end());
        if (out.size() >= length) break;
    }
    if (out.size() > length) out.resize(length);
    return out;
}

void HfsFilesystem::loadSpecialFiles() {
    extentsFile_ = xtSize_ ? readExtents(xtExtents_, xtSize_) : std::vector<uint8_t>();
    catalogFile_ = readExtents(ctExtents_, ctSize_);
}

// -- generic classic-HFS B-tree node walking --------------------------------

namespace {

// Parse a leaf record's raw bytes into (key, data), per Inside Macintosh:
// the key occupies its length byte plus keyLen more bytes (kept WITH the
// leading length byte so field offsets line up with the on-disk layout);
// the data record follows, word-aligned.
bool splitKeyData(const std::vector<uint8_t>& rec, std::vector<uint8_t>& key,
                   std::vector<uint8_t>& data) {
    if (rec.empty()) return false;
    uint8_t keylen = rec[0];
    if (keylen == 0 || static_cast<size_t>(1 + keylen) > rec.size()) return false;
    key.assign(rec.begin(), rec.begin() + 1 + keylen);
    size_t dataOff = 1 + keylen;
    if (dataOff % 2 == 1) ++dataOff;
    if (dataOff > rec.size()) dataOff = rec.size();
    data.assign(rec.begin() + dataOff, rec.end());
    return true;
}

} // namespace

std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
HfsFilesystem::leafRecords(const std::vector<uint8_t>& file) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> out;
    if (file.size() < SECTOR) return out;

    // Node 0 is the header node; BTHeaderRec starts right after the 14-byte
    // node descriptor.
    uint16_t nodeSize = rdBE16(&file[14 + 18]);
    if (nodeSize == 0) nodeSize = SECTOR;
    uint32_t firstLeaf = rdBE32(&file[14 + 10]);
    uint32_t nNodes = rdBE32(&file[14 + 22]);

    auto node = [&](uint32_t n) -> std::vector<uint8_t> {
        size_t off = static_cast<size_t>(n) * nodeSize;
        if (off + nodeSize > file.size()) return {};
        return std::vector<uint8_t>(file.begin() + off, file.begin() + off + nodeSize);
    };

    // Return (ndType, record byte-slices) for one node, parsing the reversed
    // offset table stored at the end of the node.
    auto nodeRecords = [&](const std::vector<uint8_t>& n)
            -> std::pair<int, std::vector<std::vector<uint8_t>>> {
        std::vector<std::vector<uint8_t>> recs;
        if (n.size() < 14) return {0, recs};
        int ndType = static_cast<int8_t>(n[8]);
        uint16_t nrecs = rdBE16(&n[10]);
        size_t ns = n.size();
        for (uint16_t i = 0; i < nrecs; ++i) {
            size_t need = 2 * static_cast<size_t>(i + 1);
            if (need > ns) break;
            uint16_t start = rdBE16(&n[ns - need]);
            size_t endNeed = 2 * static_cast<size_t>(i + 2);
            size_t endPos = ns - endNeed;
            uint16_t end = (endNeed <= ns) ? rdBE16(&n[endPos]) : start;
            if (end < start || end > ns) end = start;
            recs.emplace_back(n.begin() + start, n.begin() + end);
        }
        return {ndType, recs};
    };

    auto collectLeaf = [&](const std::vector<uint8_t>& n) {
        auto [ndType, recs] = nodeRecords(n);
        if (ndType != -1) return; // only leaf nodes (ndType 0xFF / -1) hold records we want
        for (auto& r : recs) {
            std::vector<uint8_t> key, data;
            if (splitKeyData(r, key, data)) out.emplace_back(std::move(key), std::move(data));
        }
    };

    if (firstLeaf == 0 || firstLeaf >= nNodes) {
        // First-leaf pointer is bogus (damaged header): fall back to scanning
        // every node in the file for leaf-typed ones.
        uint32_t scanCount = nNodes ? nNodes : static_cast<uint32_t>(file.size() / nodeSize);
        for (uint32_t n = 0; n < scanCount; ++n) {
            auto nd = node(n);
            if (nd.size() < 14) continue;
            collectLeaf(nd);
        }
        return out;
    }

    std::vector<bool> seen(nNodes, false);
    uint32_t n = firstLeaf;
    while (n && n < nNodes && !seen[n]) {
        seen[n] = true;
        auto nd = node(n);
        if (nd.size() < 14) break;
        collectLeaf(nd);
        n = rdBE32(&nd[0]); // fLink
    }
    return out;
}

// -- extents-overflow lookup -------------------------------------------------

std::vector<HfsFilesystem::Extent> HfsFilesystem::overflowExtents(
        uint32_t cnid, uint8_t forkType, uint32_t startBlock) const {
    std::vector<Extent> result;
    if (extentsFile_.empty()) return result;

    // Extents-overflow key: keylen(1), reserved(1), xkrFkType(1), xkrFNum(4)@2,
    // xkrFABN(2)@6.
    std::vector<std::pair<uint32_t, std::vector<Extent>>> matches;
    for (auto& [key, data] : leafRecords(extentsFile_)) {
        if (key.size() < 7) continue;
        uint8_t xkrFkType = key[1];
        uint32_t xkrFNum = rdBE32(&key[2]);
        uint32_t xkrFABN = rdBE16(&key[6]);
        if (xkrFNum == cnid && xkrFkType == forkType && xkrFABN >= startBlock) {
            uint8_t padded[12] = {0};
            std::memcpy(padded, data.data(), std::min<size_t>(data.size(), 12));
            matches.emplace_back(xkrFABN, parseExtentRecord(padded));
        }
    }
    std::sort(matches.begin(), matches.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    for (auto& [abn, ex] : matches) result.insert(result.end(), ex.begin(), ex.end());
    return result;
}

std::vector<HfsFilesystem::Extent> HfsFilesystem::forkExtents(
        uint32_t cnid, uint8_t forkType, const std::vector<Extent>& baseExtents,
        uint32_t logicalLen) const {
    std::vector<Extent> extents = baseExtents;
    uint64_t covered = 0;
    for (auto& e : extents) covered += static_cast<uint64_t>(e.count) * ablkSize_;
    if (covered < logicalLen) {
        uint32_t startBlock = 0;
        for (auto& e : extents) startBlock += e.count;
        auto more = overflowExtents(cnid, forkType, startBlock);
        extents.insert(extents.end(), more.begin(), more.end());
    }
    return extents;
}

// -- catalog ------------------------------------------------------------------

void HfsFilesystem::parseCatalog() {
    for (auto& [key, data] : leafRecords(catalogFile_)) {
        if (key.size() < 7 || data.empty()) continue;
        uint32_t parId = rdBE32(&key[2]);
        uint8_t nlen = key[6];
        size_t avail = key.size() - 7;
        std::string name = macRomanToUtf8(&key[7], std::min<size_t>(nlen, avail));
        uint8_t cdrType = data[0];

        CatEntry e;
        e.parentId = parId;
        e.name = name;

        if (cdrType == CDR_DIR) {
            e.isDir = true;
            e.valence = safeBE16(data, 4);
            e.cnid = safeBE32(data, 6);
            e.createDate = static_cast<int32_t>(safeBE32(data, 10));
            e.modDate = static_cast<int32_t>(safeBE32(data, 14));
        } else if (cdrType == CDR_FILE) {
            e.isDir = false;
            e.type = safeFourCC(data, 4);
            e.creator = safeFourCC(data, 8);
            e.cnid = safeBE32(data, 20);
            e.dataLen = safeBE32(data, 26);
            e.rsrcLen = safeBE32(data, 36);
            e.createDate = static_cast<int32_t>(safeBE32(data, 44));
            e.modDate = static_cast<int32_t>(safeBE32(data, 48));
            if (data.size() >= 86) e.dataExtents = parseExtentRecord(&data[74]);
            if (data.size() >= 98) e.rsrcExtents = parseExtentRecord(&data[86]);
        } else {
            continue; // thread records (3, 4): not needed for listing/export
        }

        if (e.cnid == 0) continue;
        children_[parId].push_back(e.cnid);
        entries_[e.cnid] = std::move(e);
    }
}

const HfsFilesystem::CatEntry* HfsFilesystem::findEntry(uint32_t cnid) const {
    auto it = entries_.find(cnid);
    return it == entries_.end() ? nullptr : &it->second;
}

FsNode HfsFilesystem::toFsNode(const CatEntry& e) const {
    FsNode n;
    n.id = e.cnid;
    n.name = e.name;
    n.isDir = e.isDir;
    n.size = e.isDir ? 0 : e.dataLen;
    // Classic HFS records no access time, so atime stays 0 and the exporter
    // falls back to the modification time.
    n.times.mtime  = hfsDateToUnixNs(static_cast<uint32_t>(e.modDate));
    n.times.crtime = hfsDateToUnixNs(static_cast<uint32_t>(e.createDate));
    return n;
}

FsNode HfsFilesystem::root() {
    FsNode n;
    n.id = ROOT_CNID;
    n.name = volName_.empty() ? "/" : volName_;
    n.isDir = true;
    return n;
}

std::vector<FsNode> HfsFilesystem::listDir(const FsNode& dir) {
    std::vector<FsNode> out;
    auto it = children_.find(static_cast<uint32_t>(dir.id));
    if (it == children_.end()) return out;
    out.reserve(it->second.size());
    for (uint32_t cnid : it->second) {
        if (const CatEntry* e = findEntry(cnid)) out.push_back(toFsNode(*e));
    }
    return out;
}

std::vector<uint8_t> HfsFilesystem::readFile(const FsNode& file) {
    const CatEntry* e = findEntry(static_cast<uint32_t>(file.id));
    if (!e || e->isDir || e->dataLen == 0) return {};
    auto extents = forkExtents(e->cnid, 0x00, e->dataExtents, e->dataLen);
    return readExtents(extents, e->dataLen);
}

std::vector<uint8_t> HfsFilesystem::readResourceFork(const FsNode& file) {
    const CatEntry* e = findEntry(static_cast<uint32_t>(file.id));
    if (!e || e->isDir || e->rsrcLen == 0) return {};
    auto extents = forkExtents(e->cnid, 0xFF, e->rsrcExtents, e->rsrcLen);
    return readExtents(extents, e->rsrcLen);
}

} // namespace de

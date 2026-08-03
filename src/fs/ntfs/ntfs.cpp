#include "fs/ntfs/ntfs.h"
#include "core/byte_reader.h"
#include <cstring>
#include <algorithm>
#include <set>

namespace de {

namespace {

constexpr uint32_t ATTR_STANDARD_INFO = 0x10;
constexpr uint32_t ATTR_ATTRIBUTE_LIST = 0x20;
constexpr uint32_t ATTR_FILE_NAME     = 0x30;
constexpr uint32_t ATTR_DATA          = 0x80;
constexpr uint32_t ATTR_INDEX_ROOT    = 0x90;
constexpr uint32_t ATTR_INDEX_ALLOC   = 0xA0;
constexpr uint32_t ATTR_END           = 0xFFFFFFFF;

constexpr uint16_t MFT_FLAG_IN_USE    = 0x0001;
constexpr uint16_t MFT_FLAG_DIRECTORY = 0x0002;

constexpr uint64_t ROOT_RECNO = 5;

// Decode NTFS's signed power-of-two size field (used for sectors-per-cluster,
// MFT record size, and index record size). Positive => a count of the smaller
// unit; negative => 2^|value| bytes directly.
uint32_t decodeSizeField(int8_t v, uint32_t unitBytes) {
    if (v >= 0) return static_cast<uint32_t>(v) * unitBytes;
    return 1u << static_cast<unsigned>(-v);
}

// Apply the NTFS "fixup"/update-sequence array in place. A multi-sector
// structure (FILE / INDX record) is divided into equal chunks whose last two
// bytes have been swapped out for a sequence number; restore the originals.
// Returns false if the record is inconsistent (a torn write or a bad record).
//
// The chunk stride is derived from the record, NOT from the volume's bytes per
// sector. usaCnt is 1 + one entry per protected chunk, so the stride is
// simply rec.size() / (usaCnt - 1). This is the only reliable source.
//
// Why it matters: on a 4Kn volume the BPB reports 4096 bytes per sector, but
// the MFT records are still protected in 512-byte chunks - a 4096-byte FILE
// record carries usaCnt = 9, i.e. eight 512-byte chunks. Passing 4096 as the
// stride made the second iteration address byte 8190 of a 4096-byte record,
// hit the bounds check and return false, so EVERY MFT record failed to load
// and the volume enumerated as completely empty. Seen on the 3 TB ST3000DM001
// (case chris3tb): partitions and the FS type were detected fine, and the
// filesystem still listed nothing at all.
//
// `sectorSize` is retained only as a fallback for the degenerate usaCnt == 1
// case (a structure with no protected chunks).
bool applyFixup(std::vector<uint8_t>& rec, uint32_t sectorSize) {
    if (rec.size() < 8) return false;
    uint16_t usaOff = rd16(&rec[4]);
    uint16_t usaCnt = rd16(&rec[6]);
    if (usaCnt == 0) return false;
    if (usaOff + static_cast<size_t>(usaCnt) * 2 > rec.size()) return false;
    if (usaCnt == 1) return true;   // nothing protected; nothing to restore

    const size_t stride = rec.size() / (usaCnt - 1);
    // A stride must be a sane power-of-two sector multiple and leave room for
    // the two bytes it protects; anything else means a malformed header.
    if (stride < 2 || stride > rec.size() || (stride & (stride - 1)) != 0)
        return false;
    (void)sectorSize;

    uint16_t usn = rd16(&rec[usaOff]);
    for (uint16_t i = 1; i < usaCnt; ++i) {
        size_t chunkEnd = static_cast<size_t>(i) * stride - 2;
        if (chunkEnd + 2 > rec.size()) return false;
        // The last two bytes of the chunk must currently hold the USN.
        if (rd16(&rec[chunkEnd]) != usn) return false;
        std::memcpy(&rec[chunkEnd], &rec[usaOff + i * 2], 2);
    }
    return true;
}

// Minimal UTF-16LE -> UTF-8 for filenames (handles the BMP plus surrogate
// pairs). Good enough for display and export path names.
std::string utf16leToUtf8(const uint8_t* p, size_t chars) {
    std::string out;
    out.reserve(chars);
    for (size_t i = 0; i < chars; ++i) {
        uint32_t cp = rd16(p + i * 2);
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < chars) {
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

// Walk the attribute chain of a FILE record, invoking `fn` on each attribute
// header. `fn` returns true to stop iteration.
template <typename Fn>
void forEachAttribute(const std::vector<uint8_t>& rec, Fn&& fn) {
    if (rec.size() < 0x18) return;
    size_t off = rd16(&rec[0x14]); // first attribute offset
    while (off + 8 <= rec.size()) {
        uint32_t type = rd32(&rec[off]);
        if (type == ATTR_END) break;
        uint32_t len = rd32(&rec[off + 4]);
        if (len < 8 || off + len > rec.size()) break;
        if (fn(&rec[off], len)) break;
        off += len;
    }
}

} // namespace

// ---------------------------------------------------------------------------

bool NtfsFilesystem::probe(ImageSource& vol) {
    uint8_t boot[512];
    if (vol.readAt(0, boot, sizeof boot) < sizeof boot) return false;
    return std::memcmp(boot + 3, "NTFS    ", 8) == 0
        && boot[510] == 0x55 && boot[511] == 0xAA;
}

std::unique_ptr<NtfsFilesystem> NtfsFilesystem::open(std::shared_ptr<ImageSource> vol) {
    if (!probe(*vol)) return nullptr;
    auto fs = std::unique_ptr<NtfsFilesystem>(new NtfsFilesystem());
    fs->vol_ = std::move(vol);

    auto boot = fs->vol_->read(0, 512);
    fs->bytesPerSector_ = rd16(&boot[0x0B]);
    if (fs->bytesPerSector_ == 0) return nullptr;
    uint32_t secPerClus = decodeSizeField(static_cast<int8_t>(boot[0x0D]), 1);
    if (secPerClus == 0) return nullptr;
    fs->clusterSize_ = fs->bytesPerSector_ * secPerClus;
    uint64_t mftLcn = rd64(&boot[0x30]);
    fs->mftByteOffset_ = mftLcn * fs->clusterSize_;
    fs->mftRecordSize_ = decodeSizeField(static_cast<int8_t>(boot[0x40]),
                                         fs->clusterSize_);
    if (fs->mftRecordSize_ < 42) return nullptr;

    // Bootstrap: before we know where the (possibly fragmented) MFT lives, read
    // record 0 ($MFT) directly from its boot-sector location and decode its own
    // $DATA run list. That run list is the map to every other MFT record.
    fs->mftExtents_.push_back(
        {fs->mftByteOffset_, fs->vol_->size() - fs->mftByteOffset_, false});
    auto rec0 = fs->readMftRecord(0);
    if (!rec0.empty()) {
        forEachAttribute(rec0, [&](const uint8_t* a, uint32_t) {
            if (rd32(a) != ATTR_DATA) return false;
            if (a[9] != 0) return false;            // must be the unnamed stream
            if (a[8] == 0) return false;            // $MFT $DATA is non-resident
            uint16_t runOff = rd16(a + 32);
            uint64_t alloc  = rd64(a + 40);
            auto ex = fs->decodeRuns(a + runOff, 0, alloc);
            if (!ex.empty()) fs->mftExtents_ = std::move(ex);
            return true;
        });
    }
    return fs;
}

std::vector<uint8_t> NtfsFilesystem::readMftRecord(uint64_t recno) {
    uint64_t vbo = recno * mftRecordSize_; // virtual byte offset within the MFT
    // Map through the MFT's own extents to an absolute byte offset.
    uint64_t seen = 0;
    for (const auto& e : mftExtents_) {
        if (vbo < seen + e.lengthByte) {
            if (e.sparse) return {};
            uint64_t abs = e.startByte + (vbo - seen);
            auto rec = vol_->read(abs, mftRecordSize_);
            if (std::memcmp(rec.data(), "FILE", 4) != 0) return {};
            if (!applyFixup(rec, bytesPerSector_)) return {};
            return rec;
        }
        seen += e.lengthByte;
    }
    return {};
}

std::vector<NtfsFilesystem::Extent>
NtfsFilesystem::decodeRuns(const uint8_t* rl, size_t maxLen, uint64_t allocSize) {
    std::vector<Extent> out;
    int64_t curLcn = 0;
    uint64_t producedBytes = 0;
    size_t i = 0;
    // maxLen==0 means "trust the header byte terminator"; cap the walk anyway.
    const size_t hardCap = maxLen ? maxLen : (1u << 20);
    while (i < hardCap) {
        uint8_t hdr = rl[i++];
        if (hdr == 0) break;
        unsigned lenBytes = hdr & 0x0F;
        unsigned offBytes = (hdr >> 4) & 0x0F;
        if (lenBytes == 0 || lenBytes > 8 || offBytes > 8) break;
        uint64_t runLen = rdUnsigned(rl + i, lenBytes);
        i += lenBytes;
        Extent e{};
        e.lengthByte = runLen * clusterSize_;
        if (offBytes == 0) {
            // Sparse run (a hole): no LCN, reads back as zeros.
            e.sparse = true;
            e.startByte = 0;
        } else {
            curLcn += rdSigned(rl + i, offBytes);
            i += offBytes;
            e.sparse = false;
            e.startByte = static_cast<uint64_t>(curLcn) * clusterSize_;
        }
        producedBytes += e.lengthByte;
        out.push_back(e);
        if (allocSize && producedBytes >= allocSize) break;
    }
    return out;
}

FsNode NtfsFilesystem::root() {
    FsNode n;
    n.id = ROOT_RECNO;
    n.name = "/";
    n.isDir = true;
    return n;
}

std::vector<uint8_t> NtfsFilesystem::attrValue(const uint8_t* a) {
    if (a[8] == 0) { // resident
        uint32_t vlen = rd32(a + 16);
        uint16_t voff = rd16(a + 20);
        return std::vector<uint8_t>(a + voff, a + voff + vlen);
    }
    uint16_t runOff = rd16(a + 32);
    uint64_t alloc  = rd64(a + 40);
    uint64_t realSz = rd64(a + 48);
    std::vector<uint8_t> data;
    for (const auto& e : decodeRuns(a + runOff, 0, alloc)) {
        if (data.size() >= realSz) break;
        uint64_t want = std::min<uint64_t>(e.lengthByte, realSz - data.size());
        if (e.sparse) data.insert(data.end(), want, 0);
        else { auto c = vol_->read(e.startByte, want); data.insert(data.end(), c.begin(), c.end()); }
    }
    if (data.size() > realSz) data.resize(realSz);
    return data;
}

std::vector<std::vector<uint8_t>>
NtfsFilesystem::collectAttributes(const std::vector<uint8_t>& baseRec, uint64_t baseNo) {
    std::vector<std::vector<uint8_t>> attrs;
    std::vector<uint8_t> listData;
    forEachAttribute(baseRec, [&](const uint8_t* a, uint32_t len) {
        if (rd32(a) == ATTR_ATTRIBUTE_LIST) listData = attrValue(a);
        else attrs.emplace_back(a, a + len);
        return false;
    });
    if (listData.empty()) return attrs;

    // Parse the attribute list into the set of extension record numbers that
    // hold overflow attributes, then pull their attributes in.
    std::set<uint64_t> extRecs;
    for (size_t i = 0; i + 0x18 <= listData.size();) {
        uint16_t entLen = rd16(&listData[i + 4]);
        if (entLen < 0x18 || i + entLen > listData.size()) break;
        uint64_t ref = rd64(&listData[i + 0x10]) & 0x0000FFFFFFFFFFFFull;
        if (ref != baseNo) extRecs.insert(ref);
        i += entLen;
    }
    for (uint64_t r : extRecs) {
        auto ext = readMftRecord(r);
        if (ext.empty()) continue;
        forEachAttribute(ext, [&](const uint8_t* a, uint32_t len) {
            if (rd32(a) != ATTR_ATTRIBUTE_LIST) attrs.emplace_back(a, a + len);
            return false;
        });
    }
    return attrs;
}

std::vector<FsNode> NtfsFilesystem::listDir(const FsNode& dir) {
    std::vector<FsNode> out;
    auto rec = readMftRecord(dir.id);
    if (rec.empty()) return out;
    // Gather attributes from the base record plus any $ATTRIBUTE_LIST extension
    // records (large directories keep $INDEX_ALLOCATION in an extension record).
    auto attrs = collectAttributes(rec, dir.id);

    // Collect index blocks to scan: the resident $INDEX_ROOT node, plus every
    // INDX block referenced by $INDEX_ALLOCATION. Each directory key lives in
    // exactly one node across the whole B-tree, so scanning them all and taking
    // the real entries yields every child once.
    auto scanNode = [&](const uint8_t* entries, size_t region) {
        size_t p = 0;
        while (p + 0x10 <= region) {
            uint64_t ref = rd64(entries + p) & 0x0000FFFFFFFFFFFFull;
            uint16_t entLen = rd16(entries + p + 8);
            uint16_t keyLen = rd16(entries + p + 10);
            uint16_t flags  = rd16(entries + p + 12);
            if (entLen < 0x10 || p + entLen > region) break;
            if (flags & 0x02) break;                 // last entry in node
            if (keyLen >= 0x42 && p + 0x10 + keyLen <= region) {
                const uint8_t* key = entries + p + 0x10;
                uint8_t nameLen = key[0x40];
                uint8_t nameSpace = key[0x41];
                // Skip the DOS 8.3 alias so files aren't listed twice.
                if (nameSpace != 2 && 0x42 + static_cast<size_t>(nameLen) * 2 <= keyLen) {
                    FsNode child;
                    child.id = ref;
                    child.name = utf16leToUtf8(key + 0x42, nameLen);
                    uint32_t fnFlags = rd32(key + 0x38);
                    child.isDir = (fnFlags & 0x10000000u) != 0; // FILE_ATTR_DIRECTORY
                    child.size = rd64(key + 0x30);              // real size
                    child.mtime = static_cast<int64_t>(rd64(key + 0x18));
                    if (!child.name.empty() && child.name != ".")
                        out.push_back(std::move(child));
                }
            }
            p += entLen;
        }
    };

    for (const auto& av : attrs) {
        const uint8_t* a = av.data();
        uint32_t alen = static_cast<uint32_t>(av.size());
        if (rd32(a) != ATTR_INDEX_ROOT) continue;
        uint16_t valOff = rd16(a + 20);
        uint32_t valLen = rd32(a + 16);
        if (valOff + valLen > alen) continue;
        const uint8_t* val = a + valOff;
        // Index node header sits at val+0x10; entries follow its offset.
        uint32_t firstEntry = rd32(val + 0x10);
        uint32_t entriesEnd = rd32(val + 0x14);
        size_t base = 0x10 + firstEntry;
        if (base < valLen && entriesEnd + 0x10 <= valLen)
            scanNode(val + base, entriesEnd - firstEntry);
    }

    // $INDEX_ALLOCATION: non-resident stream of INDX blocks for large dirs.
    for (const auto& av : attrs) {
        const uint8_t* a = av.data();
        if (rd32(a) != ATTR_INDEX_ALLOC || a[8] == 0) continue;
        uint16_t runOff = rd16(a + 32);
        uint64_t alloc  = rd64(a + 40);
        for (const auto& e : decodeRuns(a + runOff, 0, alloc)) {
            if (e.sparse) continue;
            for (uint64_t o = 0; o + 24 <= e.lengthByte; o += clusterSize_) {
                auto blk = vol_->read(e.startByte + o, clusterSize_);
                if (blk.size() < 0x18 || std::memcmp(blk.data(), "INDX", 4) != 0)
                    continue;
                applyFixup(blk, bytesPerSector_);
                uint32_t firstEntry = rd32(&blk[0x18 + 0x00]);
                uint32_t entriesEnd = rd32(&blk[0x18 + 0x04]);
                size_t base = 0x18 + firstEntry;
                if (base < blk.size() && 0x18 + entriesEnd <= blk.size())
                    scanNode(&blk[base], entriesEnd - firstEntry);
            }
        }
    }

    return out;
}

bool NtfsFilesystem::readFileStream(const FsNode& file, const DataSink& sink) {
    auto rec = readMftRecord(file.id);
    if (rec.empty()) return true;
    auto attrs = collectAttributes(rec, file.id);
    constexpr size_t kChunk = 4 * 1024 * 1024; // bounded working buffer

    // Resident unnamed $DATA: the whole file is inline in one record.
    for (const auto& av : attrs) {
        const uint8_t* a = av.data();
        if (rd32(a) == ATTR_DATA && a[9] == 0 && a[8] == 0) {
            uint32_t vlen = rd32(a + 16);
            uint16_t voff = rd16(a + 20);
            if (voff + vlen <= av.size()) return sink(a + voff, vlen);
            return true;
        }
    }

    // Non-resident: a fragmented file can split its $DATA across several
    // attributes (base + $ATTRIBUTE_LIST extension records). Order them by
    // starting VCN and stream their runs in sequence; the real size lives on
    // the fragment that starts at VCN 0.
    struct Frag { uint64_t vcn; const std::vector<uint8_t>* av; };
    std::vector<Frag> frags;
    uint64_t realSz = 0;
    bool haveData = false;
    for (const auto& av : attrs) {
        const uint8_t* a = av.data();
        if (rd32(a) != ATTR_DATA || a[9] != 0 || a[8] == 0) continue;
        haveData = true;
        uint64_t vcn = rd64(a + 16);
        if (vcn == 0) realSz = rd64(a + 48);
        frags.push_back({vcn, &av});
    }
    if (!haveData) return true;
    std::sort(frags.begin(), frags.end(),
              [](const Frag& x, const Frag& y) { return x.vcn < y.vcn; });

    std::vector<uint8_t> buf(kChunk);
    uint64_t produced = 0;
    bool aborted = false;
    for (const auto& f : frags) {
        if (aborted || (realSz && produced >= realSz)) break;
        const uint8_t* a = f.av->data();
        uint16_t runOff = rd16(a + 32);
        uint64_t alloc  = rd64(a + 40);
        for (const auto& e : decodeRuns(a + runOff, 0, alloc)) {
            if (aborted || (realSz && produced >= realSz)) break;
            uint64_t remain = e.lengthByte;
            if (realSz) remain = std::min<uint64_t>(remain, realSz - produced);
            if (e.sparse) {
                std::fill(buf.begin(), buf.end(), 0);
                while (remain > 0) {
                    size_t n = static_cast<size_t>(std::min<uint64_t>(remain, buf.size()));
                    if (!sink(buf.data(), n)) { aborted = true; break; }
                    remain -= n; produced += n;
                }
            } else {
                uint64_t off = e.startByte;
                while (remain > 0) {
                    size_t n = static_cast<size_t>(std::min<uint64_t>(remain, buf.size()));
                    size_t got = vol_->readAt(off, buf.data(), n);
                    if (got == 0) break;
                    if (!sink(buf.data(), got)) { aborted = true; break; }
                    off += got; remain -= got; produced += got;
                }
            }
        }
    }
    return !aborted;
}

std::vector<uint8_t> NtfsFilesystem::readFile(const FsNode& file) {
    std::vector<uint8_t> out;
    auto rec = readMftRecord(file.id);
    if (rec.empty()) return out;

    forEachAttribute(rec, [&](const uint8_t* a, uint32_t alen) {
        if (rd32(a) != ATTR_DATA) return false;
        if (a[9] != 0) return false; // unnamed (default) stream only
        uint16_t attrFlags = rd16(a + 12);
        bool compressed = (attrFlags & 0x0001) != 0;

        if (a[8] == 0) {
            // Resident: the data lives inline in the record.
            uint32_t valLen = rd32(a + 16);
            uint16_t valOff = rd16(a + 20);
            if (valOff + valLen <= alen)
                out.assign(a + valOff, a + valOff + valLen);
            return true;
        }

        // Non-resident: follow the run list, honouring the real data size.
        uint16_t runOff = rd16(a + 32);
        uint64_t alloc  = rd64(a + 40);
        uint64_t realSz = rd64(a + 48);
        // TODO: compressed streams need LZNT1 decompression per compression
        // unit; for now we surface the raw clusters and flag it upstream.
        (void)compressed;
        auto extents = decodeRuns(a + runOff, 0, alloc);
        out.reserve(realSz);
        for (const auto& e : extents) {
            if (out.size() >= realSz) break;
            uint64_t want = std::min<uint64_t>(e.lengthByte, realSz - out.size());
            if (e.sparse) {
                out.insert(out.end(), want, 0);
            } else {
                auto chunk = vol_->read(e.startByte, want);
                out.insert(out.end(), chunk.begin(), chunk.end());
            }
        }
        if (out.size() > realSz) out.resize(realSz);
        return true;
    });
    return out;
}

} // namespace de

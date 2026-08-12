#include "fs/compression/decmpfs.h"
#include "core/byte_reader.h"
#include <algorithm>
#include <cstring>
#include <zlib.h>

namespace de::compression {

namespace {

constexpr uint32_t DECMPFS_MAGIC = 0x636D7066; // 'fpmc', little-endian on disk
constexpr size_t DECMPFS_HDR = 16;
constexpr size_t BLOCK = 64 * 1024; // decmpfs always works in 64 KiB blocks

// A compressed block whose first byte has its low nibble set to 0xF is stored
// uncompressed (the data did not compress), with that marker byte in front.
bool blockIsRaw(const uint8_t* p, size_t len) {
    return len > 0 && (p[0] & 0x0F) == 0x0F;
}

bool inflateBlock(const uint8_t* src, size_t srcLen, std::vector<uint8_t>& out,
                  size_t expect, std::string* err) {
    if (blockIsRaw(src, srcLen)) {
        if (srcLen - 1 != expect) {
            if (err) *err = "stored (uncompressed) decmpfs block has the wrong length";
            return false;
        }
        out.assign(src + 1, src + srcLen);
        return true;
    }
    out.resize(expect);
    uLongf dstLen = static_cast<uLongf>(expect);
    int rc = uncompress(out.data(), &dstLen, src, static_cast<uLong>(srcLen));
    if (rc != Z_OK || dstLen != expect) {
        if (err) *err = "zlib block failed to decompress (damaged data)";
        return false;
    }
    return true;
}

bool lzvnBlock(const uint8_t* src, size_t srcLen, std::vector<uint8_t>& out,
               size_t expect, std::string* err) {
    // The LZVN variants use 0x06 as their stored-data marker.
    if (srcLen > 0 && src[0] == 0x06) {
        if (srcLen - 1 != expect) {
            if (err) *err = "stored (uncompressed) LZVN block has the wrong length";
            return false;
        }
        out.assign(src + 1, src + srcLen);
        return true;
    }
    out.resize(expect);
    size_t n = lzvnDecode(src, srcLen, out.data(), expect);
    if (n != expect) {
        if (err) *err = "LZVN block failed to decompress (damaged data)";
        return false;
    }
    return true;
}

// Walk the resource fork's block table, handing each decompressed block to the
// sink. `zlibStyle` selects the HFS+ resource-fork layout (a 0x100-byte header
// then offset/size pairs) versus the LZVN layout (a bare offset table).
bool streamResourceFork(const std::vector<uint8_t>& rsrc, uint64_t total,
                        bool zlibStyle, const DecmpfsSink& sink, std::string* err) {
    const size_t nblocks = static_cast<size_t>((total + BLOCK - 1) / BLOCK);
    std::vector<uint8_t> out;
    uint64_t produced = 0;

    if (zlibStyle) {
        // A real Macintosh resource fork: a big-endian header whose data_offset
        // (0x100 in every file Apple has ever written) points at the resource
        // data, which itself opens with a 4-byte length. The compression table
        // - a block count followed by offset/size pairs - starts just past
        // that, and its offsets are relative to the table's own base.
        if (rsrc.size() < 16) { if (err) *err = "resource fork too small"; return false; }
        uint32_t dataOffset = rdBE32(rsrc.data());
        uint64_t base = static_cast<uint64_t>(dataOffset) + 4;
        if (base + 4 > rsrc.size()) {
            if (err) *err = "resource fork header points outside the fork";
            return false;
        }
        uint32_t count = rd32(rsrc.data() + base);
        if (count != nblocks) {
            if (err) *err = "resource fork block count disagrees with the file size";
            return false;
        }
        for (size_t i = 0; i < nblocks; ++i) {
            uint64_t ent = base + 4 + i * 8;
            if (ent + 8 > rsrc.size()) { if (err) *err = "block table truncated"; return false; }
            uint32_t off = rd32(rsrc.data() + ent);
            uint32_t len = rd32(rsrc.data() + ent + 4);
            uint64_t start = base + off;
            if (start + len > rsrc.size()) {
                if (err) *err = "compressed block runs past the end of the resource fork";
                return false;
            }
            size_t expect = static_cast<size_t>(std::min<uint64_t>(BLOCK, total - produced));
            if (!inflateBlock(rsrc.data() + start, len, out, expect, err)) return false;
            if (!sink(out.data(), out.size())) { if (err) *err = "aborted"; return false; }
            produced += out.size();
        }
    } else {
        // LZVN layout: (nblocks + 1) little-endian offsets, each block running
        // from its offset to the next one.
        size_t need = (nblocks + 1) * 4;
        if (rsrc.size() < need) { if (err) *err = "LZVN offset table truncated"; return false; }
        for (size_t i = 0; i < nblocks; ++i) {
            uint32_t start = rd32(rsrc.data() + i * 4);
            uint32_t end = rd32(rsrc.data() + (i + 1) * 4);
            if (end < start || end > rsrc.size()) {
                if (err) *err = "LZVN block offsets are inconsistent";
                return false;
            }
            size_t expect = static_cast<size_t>(std::min<uint64_t>(BLOCK, total - produced));
            if (!lzvnBlock(rsrc.data() + start, end - start, out, expect, err)) return false;
            if (!sink(out.data(), out.size())) { if (err) *err = "aborted"; return false; }
            produced += out.size();
        }
    }
    if (produced != total) {
        if (err) *err = "decompressed size does not match the recorded file size";
        return false;
    }
    return true;
}

} // namespace

bool parseDecmpfsHeader(const uint8_t* attr, size_t len, DecmpfsHeader& out) {
    if (len < DECMPFS_HDR) return false;
    out.magic = rd32(attr);
    if (out.magic != DECMPFS_MAGIC) return false;
    out.type = rd32(attr + 4);
    out.uncompressedSize = rd64(attr + 8);
    return true;
}

bool decmpfsUsesResourceFork(uint32_t type) {
    return type == CMP_RSRC_ZLIB || type == CMP_RSRC_LZVN ||
           type == CMP_RSRC_RAW || type == CMP_RSRC_LZFSE;
}

bool decmpfsDecompress(const std::vector<uint8_t>& attr,
                       const std::function<std::vector<uint8_t>()>& fetchResourceFork,
                       const DecmpfsSink& sink, std::string* err) {
    DecmpfsHeader h;
    if (!parseDecmpfsHeader(attr.data(), attr.size(), h)) {
        if (err) *err = "not a decmpfs attribute";
        return false;
    }
    const uint8_t* payload = attr.data() + DECMPFS_HDR;
    size_t payloadLen = attr.size() - DECMPFS_HDR;
    std::vector<uint8_t> out;

    switch (h.type) {
        case CMP_ATTR_RAW: {
            if (payloadLen != h.uncompressedSize) {
                if (err) *err = "uncompressed decmpfs attribute has the wrong length";
                return false;
            }
            return sink(payload, payloadLen);
        }
        case CMP_ATTR_ZLIB: {
            if (!inflateBlock(payload, payloadLen, out,
                              static_cast<size_t>(h.uncompressedSize), err))
                return false;
            return sink(out.data(), out.size());
        }
        case CMP_ATTR_LZVN: {
            if (!lzvnBlock(payload, payloadLen, out,
                           static_cast<size_t>(h.uncompressedSize), err))
                return false;
            return sink(out.data(), out.size());
        }
        case CMP_RSRC_RAW: {
            auto rsrc = fetchResourceFork();
            if (rsrc.size() < h.uncompressedSize) {
                if (err) *err = "resource fork is shorter than the recorded file size";
                return false;
            }
            return sink(rsrc.data(), static_cast<size_t>(h.uncompressedSize));
        }
        case CMP_RSRC_ZLIB:
            return streamResourceFork(fetchResourceFork(), h.uncompressedSize, true,
                                      sink, err);
        case CMP_RSRC_LZVN:
            return streamResourceFork(fetchResourceFork(), h.uncompressedSize, false,
                                      sink, err);
        case CMP_ATTR_LZFSE:
        case CMP_RSRC_LZFSE:
            if (err)
                *err = "file uses LZFSE compression, which this build cannot "
                       "decode yet";
            return false;
        default:
            if (err)
                *err = "unknown decmpfs compression type " + std::to_string(h.type);
            return false;
    }
}

} // namespace de::compression

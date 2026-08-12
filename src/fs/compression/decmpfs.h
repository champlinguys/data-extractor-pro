#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Apple's transparent per-file compression ("decmpfs"), shared by HFS+ and
// APFS. A compressed file has an empty data fork; its real contents live in the
// com.apple.decmpfs extended attribute, or - when they are too big for an
// attribute - in the com.apple.ResourceFork, chopped into 64 KiB blocks with a
// lookup table in front.
//
// This matters for recovery: on a Mac volume a large share of the files under
// /System, /usr and inside app bundles are compressed, and a reader that
// ignores decmpfs exports them all as zero-byte files without complaining.
namespace de::compression {

// The 16-byte header at the front of the com.apple.decmpfs attribute.
struct DecmpfsHeader {
    uint32_t magic = 0; // 'fpmc'
    uint32_t type = 0;  // compression scheme, see below
    uint64_t uncompressedSize = 0;
};

// Compression types. Odd numbers keep the payload in the attribute itself,
// even numbers keep it in the resource fork.
constexpr uint32_t CMP_ATTR_ZLIB = 3;
constexpr uint32_t CMP_RSRC_ZLIB = 4;
constexpr uint32_t CMP_ATTR_RAW = 9;
constexpr uint32_t CMP_RSRC_RAW = 10;
constexpr uint32_t CMP_ATTR_LZVN = 7;
constexpr uint32_t CMP_RSRC_LZVN = 8;
constexpr uint32_t CMP_ATTR_LZFSE = 11;
constexpr uint32_t CMP_RSRC_LZFSE = 12;

bool parseDecmpfsHeader(const uint8_t* attr, size_t len, DecmpfsHeader& out);

// True if the payload lives in the resource fork rather than the attribute.
bool decmpfsUsesResourceFork(uint32_t type);

// Decompress a decmpfs file. `attr` is the whole com.apple.decmpfs attribute;
// `fetchResourceFork` is called at most once, and only for the resource-fork
// variants. Data is handed to `sink` in blocks; a false return from the sink
// aborts and is reported as failure.
//
// Returns false with a message in `err` for schemes we cannot decode (LZFSE)
// or for damaged input - deliberately, rather than emitting a short or
// zero-filled file that would silently look like a successful recovery.
using DecmpfsSink = std::function<bool(const uint8_t* data, size_t len)>;
bool decmpfsDecompress(const std::vector<uint8_t>& attr,
                       const std::function<std::vector<uint8_t>()>& fetchResourceFork,
                       const DecmpfsSink& sink, std::string* err);

// LZVN block decompressor (the "vn" scheme Apple uses for files that compress
// poorly under zlib). Returns the number of bytes written to `dst`, or 0 on
// malformed input.
size_t lzvnDecode(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen);

} // namespace de::compression

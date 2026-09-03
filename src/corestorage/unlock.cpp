#include "corestorage/unlock.h"
#include "core/byte_reader.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <algorithm>
#include <cstring>

namespace de::corestorage {
namespace {

// CoreStorage metadata is written in 8 KiB blocks whatever the volume's block
// size is, each with a 64-byte header carrying the block type.
constexpr size_t METADATA_BLOCK       = 8192;
constexpr size_t BLOCK_HEADER         = 64;
constexpr size_t BLOCK_TYPE_OFFSET    = 0x0A;

// The volume groups block states where its descriptor is as an offset from the
// block's own start, and that offset can land *past* the 8 KiB the checksum
// covers - a 12.73 TiB disk puts it at exactly 8192, in the block that follows.
// So the block is read with a second block's worth of room after it; only the
// first METADATA_BLOCK bytes are checksummed, the rest is there to be pointed
// into.
constexpr size_t METADATA_WINDOW      = 2 * METADATA_BLOCK;

// Block types we care about. 0x0011 is the plaintext block that says where the
// encrypted metadata lives; 0x0019 carries the plist that holds the wrapped
// keys, continued across 0x0024 blocks when it is compressed.
constexpr uint16_t TYPE_VOLUME_GROUPS = 0x0011;
constexpr uint16_t TYPE_PLIST         = 0x0019;
constexpr uint16_t TYPE_PLIST_CONT    = 0x0024;

// Sanity ceiling on the encrypted metadata region. Real volumes use a few MiB;
// a corrupt size field must not turn into a multi-gigabyte read.
constexpr uint64_t MAX_ENCRYPTED_METADATA = 64ull << 20;

// How far into the volume to search when the header's own block numbers do not
// lead anywhere. CoreStorage keeps its metadata near the front, so this is
// generous; it only ever runs after the direct route has failed.
constexpr uint64_t SEARCH_LIMIT = 256ull << 20;

// The "weak CRC-32" CoreStorage stamps on every metadata block: CRC-32C, the
// checksum stored at offset 0 over everything from offset 8 on.
uint32_t weakCrc32(const uint8_t* data, size_t len, uint32_t crc) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int bit = 0; bit < 8; ++bit)
                c = (c & 1) ? (0x82f63b78u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        built = true;
    }
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc;
}

// Is this 8 KiB really a CoreStorage metadata block? The checksum makes this a
// near-certain test, which is what lets the block be *searched* for rather than
// trusted to be where a header field says - and, once decrypted, what proves
// the decryption key was right.
bool metadataBlockValid(const uint8_t* block) {
    // A block whose logical volume was wiped keeps its marker and drops the
    // checksum; it is genuine metadata, just empty.
    if (std::memcmp(block, "LVFwiped", 8) == 0) return true;
    uint32_t initial = rd32(block + 4);
    if (initial != 0xFFFFFFFFu) return false;
    if (rd16(block + 8) != 1) return false;                 // format version
    if (rd32(block + 48) != METADATA_BLOCK) return false;   // block size
    return rd32(block) == weakCrc32(block + 8, METADATA_BLOCK - 8, initial);
}

// One AES-XTS data unit, decrypted in place. CoreStorage encrypts each metadata
// block as a single 8 KiB unit, with the block's index as the tweak - unlike
// the volume data, which is a unit per 512-byte sector.
bool xtsDecryptUnit(const uint8_t key[16], const uint8_t tweakKey[16],
                    uint64_t unit, uint8_t* data, size_t len) {
    uint8_t material[32];
    std::memcpy(material, key, 16);
    std::memcpy(material + 16, tweakKey, 16);

    uint8_t tweak[16] = {};
    for (int i = 0; i < 8; ++i) tweak[i] = (unit >> (8 * i)) & 0xFF;   // LE unit

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    std::vector<uint8_t> out(len);
    int outLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), nullptr, material, tweak) == 1 &&
              EVP_DecryptUpdate(ctx, out.data(), &outLen, data,
                                static_cast<int>(len)) == 1;
    EVP_CIPHER_CTX_free(ctx);
    std::memset(material, 0, sizeof material);
    if (!ok) return false;
    std::memcpy(data, out.data(), len);
    return true;
}

// RFC 3394 AES key unwrap. The wrapped blob carries its own integrity block, so
// a wrong key fails here rather than yielding a wrong-but-plausible key: this
// is what makes a password check a check and not a guess.
std::optional<std::vector<uint8_t>> aesKeyUnwrap(const uint8_t kek[16],
                                                 const uint8_t* wrapped,
                                                 size_t len) {
    if (len < 24 || len % 8 != 0) return std::nullopt;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    // Key wrapping is off by default in OpenSSL; a null IV means the standard
    // A6A6A6A6A6A6A6A6 integrity value, which is the one CoreStorage uses.
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    std::vector<uint8_t> out(len);
    int outLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_wrap(), nullptr, kek, nullptr) == 1 &&
              EVP_DecryptUpdate(ctx, out.data(), &outLen, wrapped,
                                static_cast<int>(len)) == 1 &&
              outLen > 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return std::nullopt;
    out.resize(static_cast<size_t>(outLen));
    return out;
}

std::vector<uint8_t> pbkdf2Sha256(const std::string& password,
                                  const uint8_t* salt, size_t saltLen,
                                  uint32_t iterations, size_t outLen) {
    std::vector<uint8_t> out(outLen);
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt, static_cast<int>(saltLen),
                          static_cast<int>(iterations), EVP_sha256(),
                          static_cast<int>(outLen), out.data()) != 1)
        return {};
    return out;
}

// Inflate `in` to exactly `expected` bytes. macOS writes the plist zlib-wrapped;
// the raw-deflate retry costs nothing and covers a writer that omits the header.
std::vector<uint8_t> inflateData(const std::vector<uint8_t>& in, size_t expected) {
    if (in.empty() || expected == 0 || expected > (32u << 20)) return {};
    std::vector<uint8_t> out(expected);
    uLongf outLen = static_cast<uLongf>(expected);
    if (uncompress(out.data(), &outLen, in.data(),
                   static_cast<uLong>(in.size())) == Z_OK) {
        out.resize(outLen);
        return out;
    }
    z_stream zs{};
    if (inflateInit2(&zs, -15) != Z_OK) return {};
    zs.next_in = const_cast<Bytef*>(in.data());
    zs.avail_in = static_cast<uInt>(in.size());
    zs.next_out = out.data();
    zs.avail_out = static_cast<uInt>(expected);
    int rc = inflate(&zs, Z_FINISH);
    size_t got = expected - zs.avail_out;
    inflateEnd(&zs);
    if ((rc != Z_STREAM_END && rc != Z_OK) || got == 0) return {};
    out.resize(got);
    return out;
}

std::vector<uint8_t> base64Decode(const std::string& in) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    uint32_t acc = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        int v = value(c);
        if (v < 0) continue;                    // whitespace and XML indentation
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

// Every <data> that follows a <key>name</key> in `xml`, base64-decoded.
//
// A plist parser would be the tidier tool, but this file needs exactly two keys
// out of a document macOS wrote, and a scan cannot be tripped up by a construct
// the parser does not know. Every blob found is checked for its own structure
// before it is used, so a wrong match costs a failed unwrap, not a bad key.
// Find the next `<name` that really starts a tag, i.e. one whose name ends
// rather than merely begins there. CoreStorage writes these elements plain on
// some volumes and with an ID attribute on others - `<dict ID="0">`,
// `<data ID="4">` - so the '>' cannot be assumed to follow the name. Reports
// where the tag ends and whether it closed itself.
size_t findTagStart(const std::string& text, const std::string& name,
                    size_t from, size_t* tagEnd, bool* selfClosing) {
    while (from < text.size()) {
        size_t at = text.find(name, from);
        if (at == std::string::npos) return std::string::npos;
        size_t after = at + name.size();
        char next = after < text.size() ? text[after] : '\0';
        if (next == '>' || next == '/' || next == ' ' || next == '\t' ||
            next == '\n' || next == '\r') {
            size_t close = text.find('>', after);
            if (close == std::string::npos) return std::string::npos;
            if (tagEnd) *tagEnd = close + 1;
            if (selfClosing) *selfClosing = close > 0 && text[close - 1] == '/';
            return at;
        }
        from = after;                       // "<dictionary", not "<dict"
    }
    return std::string::npos;
}

std::vector<std::vector<uint8_t>> plistDataForKey(const std::string& xml,
                                                  const std::string& key) {
    std::vector<std::vector<uint8_t>> found;
    const std::string tag = "<key>" + key + "</key>";
    for (size_t pos = xml.find(tag); pos != std::string::npos;
         pos = xml.find(tag, pos + tag.size())) {
        size_t bodyStart = 0;
        bool selfClosing = false;
        size_t open = findTagStart(xml, "<data", pos, &bodyStart, &selfClosing);
        if (open == std::string::npos || selfClosing) continue;
        size_t close = xml.find("</data>", bodyStart);
        if (close == std::string::npos) continue;
        // Only take a <data> that belongs to this key: anything but whitespace
        // between the two means the key's own value was something else.
        if (xml.find_first_not_of(" \t\r\n", pos + tag.size()) != open) continue;
        found.push_back(base64Decode(xml.substr(bodyStart, close - bodyStart)));
    }
    return found;
}

std::optional<std::string> plistStringForKey(const std::string& xml,
                                             const std::string& key) {
    const std::string tag = "<key>" + key + "</key>";
    size_t pos = xml.find(tag);
    if (pos == std::string::npos) return std::nullopt;
    size_t bodyStart = 0;
    bool selfClosing = false;
    size_t open = findTagStart(xml, "<string", pos, &bodyStart, &selfClosing);
    if (open == std::string::npos) return std::nullopt;
    if (selfClosing) return std::string();
    size_t close = xml.find("</string>", bodyStart);
    if (close == std::string::npos) return std::nullopt;
    return xml.substr(bodyStart, close - bodyStart);
}

// "0123abcd-..." to 16 bytes in the order the UUID is written, which is the
// order the tweak key derivation hashes them in.
bool parseUuid(const std::string& s, uint8_t out[16]) {
    int nibble = 0;
    size_t n = 0;
    for (char c : s) {
        int v;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else if (c == '-') continue;
        else return false;
        if (nibble == 0) { if (n >= 16) return false; out[n] = static_cast<uint8_t>(v << 4); nibble = 1; }
        else             { out[n++] |= static_cast<uint8_t>(v); nibble = 0; }
    }
    return n == 16 && nibble == 0;
}

// Collect every XML plist sitting in the clear in a decrypted metadata block.
// The uncompressed ones are whole and self-contained, so finding them by their
// own markup is more robust than trusting a length field in a block header.
void collectPlainPlists(const uint8_t* body, size_t bodySize,
                        std::vector<std::string>& out) {
    static const std::string open = "<dict";
    static const std::string close = "</dict>";
    std::string text(reinterpret_cast<const char*>(body), bodySize);
    size_t pos = 0;
    while (true) {
        size_t tagEnd = 0;
        bool selfClosing = false;
        pos = findTagStart(text, open, pos, &tagEnd, &selfClosing);
        if (pos == std::string::npos) break;
        if (selfClosing) { pos = tagEnd; continue; }   // <dict/> holds nothing

        // Dictionaries nest - the crypto users are a list of them - so the
        // plist ends at the </dict> that closes this one, not the first.
        size_t scan = tagEnd;
        size_t end = std::string::npos;
        for (int depth = 1; depth > 0; ) {
            size_t nestedEnd = 0;
            bool nestedSelf = false;
            size_t nextOpen = findTagStart(text, open, scan, &nestedEnd, &nestedSelf);
            size_t nextClose = text.find(close, scan);
            if (nextClose == std::string::npos) break;
            if (nextOpen != std::string::npos && nextOpen < nextClose) {
                if (!nestedSelf) ++depth;
                scan = nestedEnd;
            } else {
                if (--depth == 0) end = nextClose;
                scan = nextClose + close.size();
            }
        }
        if (end == std::string::npos) break;
        out.push_back(text.substr(pos, end + close.size() - pos));
        pos = end + close.size();
    }
}

// Where the encrypted metadata lives, as the plaintext metadata states it:
// block numbers, which still have to be turned into byte offsets.
struct EncryptedMetadataLocation {
    uint64_t firstBlock = 0;
    uint64_t blocks = 0;
};

std::optional<EncryptedMetadataLocation>
parseVolumeGroupsBlock(const uint8_t* block, size_t available) {
    const uint8_t* body = block + BLOCK_HEADER;
    if (available < BLOCK_HEADER) return std::nullopt;
    const size_t bodySize = available - BLOCK_HEADER;

    // The descriptor offset is measured from the start of the block, header
    // included; everything else here indexes the body.
    uint32_t vgd = rd32(body + 156);
    if (vgd < BLOCK_HEADER + 48) return std::nullopt;
    vgd -= BLOCK_HEADER;
    if (vgd + 48 > bodySize) return std::nullopt;

    uint64_t blocks = rd64(body + vgd + 8);
    uint64_t first  = rd64(body + vgd + 32);
    // The top 16 bits are the physical volume this copy sits on. A logical
    // volume group can span several disks; we are looking at one of them, so
    // only a copy on this disk is reachable.
    if ((first >> 48) != 0) return std::nullopt;
    first &= 0x0000ffffffffffffull;
    if (blocks == 0 || first == 0) return std::nullopt;
    return EncryptedMetadataLocation{first, blocks};
}

// Block numbers in the header are counted in units of the volume's block size.
// That field has been read correctly off every volume seen so far, but the
// whole key store hangs off it, so the sizes CoreStorage actually uses are
// tried in turn and the one that lands on a real metadata block wins. Costs a
// few reads and removes a single point of failure.
std::vector<uint32_t> blockSizeCandidates(const VolumeHeader& header) {
    std::vector<uint32_t> sizes;
    for (uint32_t candidate : {header.metadataBlockSize, 8192u, 4096u, 512u,
                               65536u, 16384u, 32768u}) {
        if (candidate == 0) continue;
        if (std::find(sizes.begin(), sizes.end(), candidate) == sizes.end())
            sizes.push_back(candidate);
    }
    return sizes;
}

// The stride for a blind sweep: the smallest boundary a metadata block could be
// placed on. Bounded below so a nonsense header cannot turn the sweep into a
// byte-by-byte crawl of 256 MiB.
uint64_t smallestBlockStep(const VolumeHeader& header) {
    uint64_t step = METADATA_BLOCK;
    for (uint32_t candidate : blockSizeCandidates(header))
        if (candidate >= 512 && candidate < step) step = candidate;
    return step;
}

// Read the block at `offset` and say whether it is a metadata block of `type`.
// Reads a window rather than a single block, so a descriptor that points past
// the checksummed block is still in memory; `available` reports how much of the
// window the volume actually held, which is all a parse may index. The block
// itself must be whole - only the room after it may be short, at the very end
// of a volume.
bool readMetadataBlock(ImageSource& pv, uint64_t offset, uint16_t type,
                       std::vector<uint8_t>& block, size_t* available) {
    if (offset + METADATA_BLOCK > pv.size()) return false;
    size_t want = METADATA_WINDOW;
    if (offset + want > pv.size()) want = static_cast<size_t>(pv.size() - offset);
    size_t got = pv.readAt(offset, block.data(), want);
    if (got < METADATA_BLOCK) return false;
    if (!metadataBlockValid(block.data())) return false;
    if (rd16(block.data() + BLOCK_TYPE_OFFSET) != type) return false;
    if (available) *available = got;
    return true;
}

// The plaintext block that describes the key store, with the block size that
// found it. Tries where the header says first, then searches: a checksummed
// 8 KiB block is distinctive enough to find on its own, and a volume whose
// first metadata copy is damaged still has three more.
struct VolumeGroups {
    EncryptedMetadataLocation location;
    uint32_t blockSize = 0;
};

std::optional<VolumeGroups> findVolumeGroups(ImageSource& pv,
                                             const VolumeHeader& header,
                                             std::string* diagnostic) {
    std::vector<uint8_t> block(METADATA_WINDOW);
    size_t available = 0;
    uint64_t span = std::max<uint64_t>(header.metadataSize, METADATA_BLOCK * 8);

    for (uint32_t blockSize : blockSizeCandidates(header)) {
        for (uint64_t blockNumber : header.metadataBlocks) {
            uint64_t base = blockNumber * blockSize;
            for (uint64_t off = 0; off + METADATA_BLOCK <= span; off += METADATA_BLOCK) {
                if (!readMetadataBlock(pv, base + off, TYPE_VOLUME_GROUPS, block,
                                       &available))
                    continue;
                if (auto loc = parseVolumeGroupsBlock(block.data(), available))
                    return VolumeGroups{*loc, blockSize};
            }
        }
    }

    // Nothing where the header pointed. Sweep the front of the volume for the
    // block itself; CoreStorage keeps its metadata there.
    if (diagnostic)
        *diagnostic += "  the header's metadata block numbers led nowhere; "
                       "searched the volume instead\n";
    // Step by the volume's own block size, not by the metadata block size: the
    // blocks are 8 KiB but they are *placed* on block-number boundaries, so a
    // sweep in 8 KiB strides steps straight over one sitting at, say, 4096.
    uint64_t step = smallestBlockStep(header);
    uint64_t limit = std::min<uint64_t>(pv.size(), SEARCH_LIMIT);
    for (uint64_t off = 0; off + METADATA_BLOCK <= limit; off += step) {
        if (!readMetadataBlock(pv, off, TYPE_VOLUME_GROUPS, block, &available))
            continue;
        if (auto loc = parseVolumeGroupsBlock(block.data(), available)) {
            // The block was found, so its own block number says what the
            // header's numbers are counted in.
            uint64_t number = rd64(block.data() + 32);
            uint32_t blockSize = number ? static_cast<uint32_t>(off / number)
                                        : header.metadataBlockSize;
            if (blockSize == 0) blockSize = METADATA_BLOCK;
            return VolumeGroups{*loc, blockSize};
        }
    }
    return std::nullopt;
}

// Where the encrypted metadata starts, in bytes. The location is stated in
// block numbers, and a block number is only as good as the size it is scaled
// by - so each candidate is *tested*, by decrypting its first block and asking
// whether a real metadata block comes out. That check proves the offset and the
// header's key data together.
std::optional<uint64_t> locateEncryptedMetadata(ImageSource& pv,
                                                const VolumeHeader& header,
                                                const VolumeGroups& groups) {
    std::vector<uint8_t> block(METADATA_BLOCK);
    auto verify = [&](uint64_t offset) {
        if (offset + METADATA_BLOCK > pv.size()) return false;
        if (pv.readAt(offset, block.data(), METADATA_BLOCK) != METADATA_BLOCK) return false;
        if (!xtsDecryptUnit(header.keyData, header.identifierBytes, 0,
                            block.data(), METADATA_BLOCK))
            return false;
        return metadataBlockValid(block.data());
    };

    if (verify(groups.location.firstBlock * groups.blockSize))
        return groups.location.firstBlock * groups.blockSize;
    for (uint32_t blockSize : blockSizeCandidates(header)) {
        uint64_t offset = groups.location.firstBlock * blockSize;
        if (verify(offset)) return offset;
    }

    // Fall back to finding the region by decrypting for it. The first block of
    // the region is the one encrypted with data unit 0, so a candidate that
    // decrypts to a valid block is the region's start and nothing else.
    uint64_t limit = std::min<uint64_t>(pv.size(), SEARCH_LIMIT);
    for (uint64_t off = 0; off + METADATA_BLOCK <= limit; off += METADATA_BLOCK)
        if (verify(off)) return off;
    return std::nullopt;
}

} // namespace

std::optional<KeyMaterial> readKeyMaterial(ImageSource& pv,
                                           const VolumeHeader& header,
                                           std::string* note) {
    // A running account of what was tried, so a volume this fails on can say
    // why rather than just "no". Only surfaced when the read fails.
    std::string diagnostic;
    auto fail = [&](const std::string& reason) {
        if (note) {
            *note = reason;
            if (!diagnostic.empty()) *note += "\n" + diagnostic;
        }
        return std::nullopt;
    };

    char line[160];
    std::snprintf(line, sizeof line,
                  "  block size %u, metadata %u bytes, %zu metadata copies\n",
                  header.metadataBlockSize, header.metadataSize,
                  header.metadataBlocks.size());
    diagnostic += line;

    auto groups = findVolumeGroups(pv, header, &diagnostic);
    if (!groups)
        return fail("could not find the CoreStorage metadata that describes the "
                    "key store");
    std::snprintf(line, sizeof line,
                  "  key store described at block %llu (x%u), %llu blocks\n",
                  (unsigned long long)groups->location.firstBlock,
                  groups->blockSize,
                  (unsigned long long)groups->location.blocks);
    diagnostic += line;

    auto offset = locateEncryptedMetadata(pv, header, *groups);
    if (!offset)
        return fail("the CoreStorage key store did not decrypt with the key in "
                    "the volume header");
    uint64_t size = std::min<uint64_t>(groups->location.blocks * groups->blockSize,
                                       MAX_ENCRYPTED_METADATA);
    if (size < METADATA_BLOCK || *offset + METADATA_BLOCK > pv.size())
        return fail("the CoreStorage key store is out of bounds for this volume");
    size = std::min<uint64_t>(size, pv.size() - *offset);
    std::snprintf(line, sizeof line, "  key store at byte %llu, %llu bytes\n",
                  (unsigned long long)*offset, (unsigned long long)size);
    diagnostic += line;

    const uint64_t regionOffset = *offset;
    const uint64_t regionSize = size;

    KeyMaterial material;
    std::vector<uint8_t> compressed;    // a plist chained across several blocks
    size_t compressedFilled = 0;
    size_t uncompressedSize = 0;

    // A compressed plist ends when the chain names no successor - which for a
    // small key store is already true of the block that starts it.
    auto finishCompressed = [&] {
        compressed.resize(compressedFilled);
        auto xml = inflateData(compressed, uncompressedSize);
        if (!xml.empty())
            material.plists.emplace_back(
                reinterpret_cast<const char*>(xml.data()), xml.size());
        compressed.clear();
        compressedFilled = 0;
    };

    std::vector<uint8_t> block(METADATA_BLOCK);
    const uint64_t blocks = regionSize / METADATA_BLOCK;
    for (uint64_t i = 0; i < blocks; ++i) {
        if (pv.readAt(regionOffset + i * METADATA_BLOCK, block.data(),
                      METADATA_BLOCK) != METADATA_BLOCK)
            break;
        // The region is allocated whole and filled as the volume is used; the
        // first untouched block ends the walk.
        if (std::all_of(block.begin(), block.end(), [](uint8_t b) { return b == 0; }))
            break;
        if (!xtsDecryptUnit(header.keyData, header.identifierBytes, i,
                            block.data(), METADATA_BLOCK))
            break;

        const uint8_t* body = block.data() + BLOCK_HEADER;
        const size_t bodySize = METADATA_BLOCK - BLOCK_HEADER;
        uint16_t type = rd16(block.data() + BLOCK_TYPE_OFFSET);

        if (type == TYPE_PLIST) {
            uint32_t compressedSize   = rd32(body + 40);
            uint32_t uncompressed     = rd32(body + 44);
            uint32_t dataOffset       = rd32(body + 48);
            uint32_t dataSize         = rd32(body + 52);
            if (compressedSize != uncompressed && dataOffset >= BLOCK_HEADER &&
                compressedSize <= (32u << 20) &&
                dataOffset - BLOCK_HEADER + dataSize <= bodySize &&
                dataSize <= compressedSize) {
                // Start of a compressed plist. Anything the block does not hold
                // arrives in continuation blocks, so hold it until the chain
                // says it is complete.
                compressed.assign(compressedSize, 0);
                std::memcpy(compressed.data(), body + dataOffset - BLOCK_HEADER, dataSize);
                compressedFilled = dataSize;
                uncompressedSize = uncompressed;
                if (rd64(body + 32) == 0 || compressedFilled == compressed.size())
                    finishCompressed();
                continue;
            }
        } else if (type == TYPE_PLIST_CONT && !compressed.empty()) {
            uint64_t next     = rd64(body + 0);
            uint32_t dataSize = rd32(body + 8);
            if (dataSize <= bodySize - 16 &&
                compressedFilled + dataSize <= compressed.size()) {
                std::memcpy(compressed.data() + compressedFilled, body + 16, dataSize);
                compressedFilled += dataSize;
            }
            if (next == 0 || compressedFilled == compressed.size())
                finishCompressed();
            continue;
        }
        collectPlainPlists(body, bodySize, material.plists);
    }

    for (const auto& xml : material.plists) {
        auto uuid = plistStringForKey(xml, "com.apple.corestorage.lv.familyUUID");
        if (uuid && parseUuid(*uuid, material.familyUuid)) {
            material.haveFamilyUuid = true;
            break;
        }
    }

    if (material.plists.empty())
        return fail("the CoreStorage metadata decrypted but held no key store");
    return material;
}

std::optional<VolumeKey> volumeKeyFromPassword(const KeyMaterial& material,
                                               const std::string& password,
                                               std::string* note) {
    if (!material.haveFamilyUuid) {
        if (note) *note = "the CoreStorage metadata did not name the logical "
                          "volume, so the tweak key cannot be derived";
        return std::nullopt;
    }

    // Each crypto user - every account that can unlock the disk, plus the
    // personal recovery key - carries a KEK wrapped with their own passphrase.
    // Which one belongs to this password is not written down, so every one is
    // tried; the wrong ones fail their integrity check.
    std::vector<std::vector<uint8_t>> wrappedKeks, wrappedVolumeKeys;
    for (const auto& xml : material.plists) {
        for (auto& b : plistDataForKey(xml, "PassphraseWrappedKEKStruct"))
            wrappedKeks.push_back(std::move(b));
        for (auto& b : plistDataForKey(xml, "KEKWrappedVolumeKeyStruct"))
            wrappedVolumeKeys.push_back(std::move(b));
    }
    if (wrappedKeks.empty() || wrappedVolumeKeys.empty()) {
        if (note) *note = "this volume's metadata holds no passphrase-wrapped key, "
                          "so it cannot be opened with a password";
        return std::nullopt;
    }

    for (const auto& blob : wrappedKeks) {
        // Layout: a 16-byte salt at 8, the wrapped KEK at 32, and the PBKDF2
        // iteration count at 168. The two type/size pairs in front of them say
        // as much, and are checked rather than assumed.
        if (blob.size() < 172) continue;
        if (rd32(blob.data() + 0) != 3 || rd32(blob.data() + 4) != 16) continue;
        if (rd32(blob.data() + 24) != 0x10 || rd32(blob.data() + 28) != 24) continue;
        uint32_t iterations = rd32(blob.data() + 168);
        if (iterations == 0 || iterations > 10'000'000) continue;

        auto passphraseKey = pbkdf2Sha256(password, blob.data() + 8, 16, iterations, 16);
        if (passphraseKey.size() != 16) continue;

        auto kek = aesKeyUnwrap(passphraseKey.data(), blob.data() + 32, 24);
        std::fill(passphraseKey.begin(), passphraseKey.end(), 0);
        if (!kek || kek->size() < 16) continue;      // not this user's password

        for (const auto& wrappedVolumeKey : wrappedVolumeKeys) {
            if (wrappedVolumeKey.size() < 32) continue;
            auto vmk = aesKeyUnwrap(kek->data(), wrappedVolumeKey.data() + 8, 24);
            if (!vmk || vmk->size() < 16) continue;

            // The XTS pair: the volume master key is the cipher key, and the
            // tweak key is the first half of SHA-256 over the master key and
            // the logical volume's family UUID.
            uint8_t tweakInput[32];
            std::memcpy(tweakInput, vmk->data(), 16);
            std::memcpy(tweakInput + 16, material.familyUuid, 16);
            uint8_t digest[SHA256_DIGEST_LENGTH];
            SHA256(tweakInput, sizeof tweakInput, digest);
            std::memset(tweakInput, 0, sizeof tweakInput);

            VolumeKey key;
            key.material.assign(vmk->begin(), vmk->begin() + 16);
            key.material.insert(key.material.end(), digest, digest + 16);
            if (note) *note = "password accepted; volume key derived from the "
                              "CoreStorage key store";
            return key;
        }
    }

    if (note) *note = "no key in this volume's metadata unwrapped with that "
                      "password";
    return std::nullopt;
}

std::optional<VolumeKey> volumeKeyFromPassword(ImageSource& pv,
                                               const VolumeHeader& header,
                                               const std::string& password,
                                               std::string* note) {
    auto material = readKeyMaterial(pv, header, note);
    if (!material) return std::nullopt;
    return volumeKeyFromPassword(*material, password, note);
}

} // namespace de::corestorage

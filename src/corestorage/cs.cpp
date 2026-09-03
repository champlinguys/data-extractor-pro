#include "corestorage/cs.h"
#include "core/byte_reader.h"
#include <cctype>
#include <cstdio>
#include <cstring>

namespace de::corestorage {
namespace {

// "CS" sits well inside the block, not at offset 0: the first bytes are a
// checksum over the rest.
constexpr size_t SIGNATURE_OFFSET          = 0x58;
constexpr size_t VERSION_OFFSET            = 0x08;
constexpr size_t BLOCK_TYPE_OFFSET         = 0x0A;
constexpr size_t BLOCK_SIZE_OFFSET         = 0x30;
constexpr size_t VOLUME_SIZE_OFFSET        = 0x40;
constexpr size_t METADATA_BLOCK_SIZE_OFFSET= 0x60;
constexpr size_t METADATA_SIZE_OFFSET      = 0x64;
constexpr size_t METADATA_BLOCKS_OFFSET    = 0x68;  // four u64s, unused slots zeroed
constexpr size_t METADATA_BLOCK_SLOTS      = 4;
constexpr size_t KEY_DATA_OFFSET           = 0xB0; // 128 bytes; the first 16 are
                                                   // the metadata's AES-XTS key
constexpr size_t ENCRYPTION_METHOD_OFFSET  = 0xAC;
constexpr size_t UUID_OFFSET               = 0x130; // big-endian, i.e. RFC 4122 order

// Block type 0x0010 is the volume header itself; the metadata blocks it points
// at carry other types. Checked so a stray "CS" cannot pass for a header.
constexpr uint16_t VOLUME_HEADER_BLOCK_TYPE = 0x0010;

// Format a 16-byte big-endian UUID the way macOS displays it.
std::string formatUuid(const uint8_t* p) {
    char buf[37];
    std::snprintf(buf, sizeof buf,
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                  "%02x%02x%02x%02x%02x%02x",
                  p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                  p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    return buf;
}

} // namespace

const char* VolumeHeader::methodName() const {
    switch (encryptionMethod) {
        case ENCRYPTION_NONE:    return "unencrypted";
        case ENCRYPTION_AES_XTS: return "AES-XTS 128-bit";
        default:                 return "unknown method";
    }
}

std::string VolumeHeader::description() const {
    return std::string("CoreStorage (FileVault 2), ") + methodName();
}

bool looksLikeCoreStorage(const uint8_t* head, size_t len) {
    if (!head || len < HEADER_SIZE) return false;
    if (std::memcmp(head + SIGNATURE_OFFSET, "CS", 2) != 0) return false;
    return rd16(head + BLOCK_TYPE_OFFSET) == VOLUME_HEADER_BLOCK_TYPE;
}

std::optional<VolumeHeader> parseHeader(ImageSource& vol) {
    uint8_t head[HEADER_SIZE];
    if (vol.readAt(0, head, sizeof head) < sizeof head) return std::nullopt;
    if (!looksLikeCoreStorage(head, sizeof head)) return std::nullopt;

    VolumeHeader h;
    h.version            = rd16(head + VERSION_OFFSET);
    h.blockSize          = rd64(head + BLOCK_SIZE_OFFSET);
    h.physicalVolumeSize = rd64(head + VOLUME_SIZE_OFFSET);
    h.encryptionMethod   = rd32(head + ENCRYPTION_METHOD_OFFSET);
    h.identifier         = formatUuid(head + UUID_OFFSET);
    std::memcpy(h.identifierBytes, head + UUID_OFFSET, 16);
    std::memcpy(h.keyData, head + KEY_DATA_OFFSET, 16);
    h.metadataBlockSize  = rd32(head + METADATA_BLOCK_SIZE_OFFSET);
    h.metadataSize       = rd32(head + METADATA_SIZE_OFFSET);
    for (size_t i = 0; i < METADATA_BLOCK_SLOTS; ++i) {
        uint64_t n = rd64(head + METADATA_BLOCKS_OFFSET + i * 8);
        if (n) h.metadataBlocks.push_back(n);
    }
    return h;
}

std::optional<VolumeKey> parseVolumeKey(const std::string& hex) {
    VolumeKey key;
    int hi = -1;
    for (char c : hex) {
        if (c == ' ' || c == ':' || c == '-' || c == '\t') continue;
        int v;
        if      (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return std::nullopt;
        if (hi < 0) hi = v;
        else { key.material.push_back(static_cast<uint8_t>((hi << 4) | v)); hi = -1; }
    }
    if (hi >= 0) return std::nullopt;          // odd number of hex digits
    if (!key.valid()) return std::nullopt;
    return key;
}

} // namespace de::corestorage

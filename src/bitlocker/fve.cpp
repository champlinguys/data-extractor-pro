#include "bitlocker/fve.h"
#include "core/byte_reader.h"
#include <cstring>

namespace de::bitlocker {

namespace {

// FVE metadata entry types (libbde "metadata entry type").
constexpr uint16_t ENTRY_VMK          = 0x0002;
constexpr uint16_t ENTRY_FVEK         = 0x0003;
constexpr uint16_t ENTRY_DESCRIPTION  = 0x0007;
constexpr uint16_t ENTRY_VOLUME_HDR   = 0x000F;

// FVE value types (libbde "metadata value type").
constexpr uint16_t VALUE_STRETCH_KEY = 0x0003;
constexpr uint16_t VALUE_AESCCM_KEY  = 0x0005;
constexpr uint16_t VALUE_UNICODE     = 0x0002;

std::string protName(uint16_t t) {
    switch (t) {
        case 0x0000: return "clear key";
        case 0x0100: return "TPM";
        case 0x0200: return "startup key";
        case 0x0500: return "TPM+PIN";
        case 0x0800: return "recovery password";
        case 0x2000: return "passphrase";
        default:     return "unknown(0x" + std::to_string(t) + ")";
    }
}

std::string utf16le(const uint8_t* p, size_t bytes) {
    std::string s;
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        uint16_t c = rd16(p + i);
        if (c == 0) break;
        if (c < 0x80) s.push_back(char(c));
        else s.push_back('?');
    }
    return s;
}

// Parse an AES-CCM encrypted-key value: 12-byte nonce, 16-byte MAC, ciphertext.
std::optional<AesCcmKey> parseAesCcm(const uint8_t* v, size_t len) {
    if (len < 12 + 16) return std::nullopt;
    AesCcmKey k;
    std::memcpy(k.nonce, v, 12);
    k.macAndData.assign(v + 12, v + len); // MAC(16) + ciphertext
    return k;
}

// Walk metadata entries in [p, p+len). `fn(type, valueType, data, dataLen)`.
template <typename Fn>
void walkEntries(const uint8_t* p, size_t len, Fn&& fn) {
    size_t off = 0;
    while (off + 8 <= len) {
        uint16_t esize = rd16(p + off);
        uint16_t etype = rd16(p + off + 2);
        uint16_t vtype = rd16(p + off + 4);
        if (esize < 8 || off + esize > len) break;
        fn(etype, vtype, p + off + 8, esize - 8);
        off += esize;
    }
}

// A VMK entry: GUID(16) + FILETIME(8) + u16 + u16 protection_type, then nested
// entries (stretch key, AES-CCM key).
void parseVmk(const uint8_t* v, size_t len, VmkProtector& out) {
    if (len < 0x1C) return;
    out.protectionTypeRaw = rd16(v + 0x1A);
    out.protectionType = protName(out.protectionTypeRaw);
    walkEntries(v + 0x1C, len - 0x1C, [&](uint16_t, uint16_t vt,
                                          const uint8_t* d, size_t dl) {
        if (vt == VALUE_STRETCH_KEY && dl >= 4 + 16) {
            // stretch key carries only the derivation salt (u32 method + salt).
            // The stretch key value also contains decoy nested AES-CCM entries;
            // the VMK-encrypting AES-CCM is a *sibling* of the stretch key, so
            // we do NOT descend here.
            std::memcpy(out.salt, d + 4, 16);
            out.hasSalt = true;
        } else if (vt == VALUE_AESCCM_KEY && !out.encryptedVmk) {
            out.encryptedVmk = parseAesCcm(d, dl); // VMK wrapped by the stretch key
        }
    });
}

} // namespace

const char* methodName(EncryptionMethod m) {
    switch (m) {
        case EncryptionMethod::AesCbc128Diffuser: return "AES-CBC-128 + diffuser";
        case EncryptionMethod::AesCbc256Diffuser: return "AES-CBC-256 + diffuser";
        case EncryptionMethod::AesCbc128:         return "AES-CBC-128";
        case EncryptionMethod::AesCbc256:         return "AES-CBC-256";
        case EncryptionMethod::AesXts128:         return "AES-XTS-128";
        case EncryptionMethod::AesXts256:         return "AES-XTS-256";
        default:                                  return "unknown";
    }
}

std::optional<FveMetadata> parseFve(ImageSource& volume) {
    auto boot = volume.read(0, 512);
    if (std::memcmp(boot.data() + 3, "-FVE-FS-", 8) != 0)
        return std::nullopt;

    // Three FVE metadata block offsets (volume-relative) at 0xB0/0xB8/0xC0.
    uint64_t fveOff = rd64(&boot[0xB0]);
    if (fveOff == 0 || fveOff > volume.size()) return std::nullopt;

    auto blk = volume.read(fveOff, 8192);
    if (std::memcmp(blk.data(), "-FVE-FS-", 8) != 0) return std::nullopt;

    // FVE metadata header sits at block+0x40; entries follow header_size.
    const uint8_t* h = &blk[0x40];
    uint32_t metaSize   = rd32(h + 0x00);
    uint32_t headerSize = rd32(h + 0x08);
    if (metaSize < headerSize || 0x40 + metaSize > blk.size()) return std::nullopt;

    FveMetadata md;
    std::memcpy(md.volumeGuid, h + 0x10, 16);
    md.method = static_cast<EncryptionMethod>(rd16(h + 0x24));

    const uint8_t* entries = h + headerSize;
    size_t entriesLen = metaSize - headerSize;
    walkEntries(entries, entriesLen, [&](uint16_t et, uint16_t vt,
                                         const uint8_t* d, size_t dl) {
        if (et == ENTRY_DESCRIPTION && vt == VALUE_UNICODE) {
            md.description = utf16le(d, dl);
        } else if (et == ENTRY_VMK) {
            VmkProtector v;
            parseVmk(d, dl, v);
            md.vmks.push_back(std::move(v));
        } else if (et == ENTRY_FVEK && vt == VALUE_AESCCM_KEY) {
            md.encryptedFvek = parseAesCcm(d, dl);
        } else if (et == ENTRY_VOLUME_HDR && dl >= 16) {
            // u64 backup offset (where original boot sectors live) + u64 size.
            md.headerBlockOffset = rd64(d);
            md.headerBlockSize = rd64(d + 8);
        }
    });
    return md;
}

} // namespace de::bitlocker

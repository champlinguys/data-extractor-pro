#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "core/image_source.h"

// CoreStorage (FileVault 2) support: the Apple counterpart to the BitLocker
// layer next door. A CoreStorage physical volume holds a *logical* volume some
// way further in, encrypted with AES-XTS; the filesystem (HFS+ in practice)
// lives inside that logical volume.
//
// Field offsets were read off a real FileVault 2 volume (a 14 TB WD Ultrastar)
// and cross-checked against libfvde, which is also the oracle the decryption
// was verified against: 20/20 exact 4 KiB matches at offsets from 1 KiB to
// 928 GiB.
//
// The key hierarchy - passphrase -> KEK -> volume key - lives next door in
// unlock.h, which walks the encrypted CoreStorage metadata to get there. This
// file stops at the volume header and the ready-made volume key. Everything
// downstream of the key - the mapping, the sector decryption, the volume
// discovery - is ours and has no size ceiling.
namespace de::corestorage {

// The header sits in the first sector of the CoreStorage physical volume.
inline constexpr uint64_t HEADER_SIZE = 512;

// libfvde's encryption-method numbering. 0 means CoreStorage without
// encryption (a plain logical volume group), which must not be offered for
// unlocking; 2 is FileVault 2 proper.
enum : uint32_t {
    ENCRYPTION_NONE     = 0,
    ENCRYPTION_AES_XTS  = 2,
};

// The parsed CoreStorage volume header.
struct VolumeHeader {
    uint16_t version = 0;
    uint64_t blockSize = 0;             // bytes per physical block (512 here)
    uint64_t physicalVolumeSize = 0;    // bytes; matches the GPT partition size
    uint32_t encryptionMethod = 0;
    std::string identifier;             // physical volume UUID, as macOS shows it
    uint32_t metadataBlockSize = 0;     // bytes per metadata block number
    uint32_t metadataSize = 0;          // bytes of metadata at each copy
    std::vector<uint64_t> metadataBlocks;

    // Raw material the key hierarchy needs (see unlock.h). `keyData` is the
    // AES-XTS key the CoreStorage metadata itself is encrypted with, and the
    // physical volume UUID doubles as its tweak key - so these two together
    // open the metadata, and the metadata leads to the volume key.
    uint8_t keyData[16] = {};
    uint8_t identifierBytes[16] = {};

    bool isEncrypted() const { return encryptionMethod != ENCRYPTION_NONE; }
    const char* methodName() const;
    std::string description() const;    // one line for the UI
};

// True if `head` (the volume's first sector) is a CoreStorage header. Checks
// the signature *and* the block type, because two bytes on their own are weak:
// mislabelling a volume as encrypted sends the tech hunting for a password
// that does not exist.
bool looksLikeCoreStorage(const uint8_t* head, size_t len);

// Parse the header at offset 0 of `vol`, or nullopt if it is not one.
std::optional<VolumeHeader> parseHeader(ImageSource& vol);

// The AES-XTS volume key: the cipher key and the tweak key, concatenated as
// OpenSSL wants them. 32 bytes for AES-XTS-128, 64 for AES-XTS-256.
struct VolumeKey {
    std::vector<uint8_t> material;
    bool xts256() const { return material.size() >= 64; }
    bool valid()  const { return material.size() == 32 || material.size() == 64; }
};

// Parse a hex volume key ("e982...7650"), ignoring spaces, colons and dashes.
// Returns nullopt unless it comes to exactly 32 or 64 bytes.
std::optional<VolumeKey> parseVolumeKey(const std::string& hex);

} // namespace de::corestorage

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include "core/image_source.h"

// BitLocker (FVE) metadata parser. Reads the on-disk metadata that a BitLocker
// boot record points to: the encryption method, the volume GUID, and the key
// protectors (VMK entries) plus the FVEK. This is enough to drive the key flow:
//   recovery password -> stretch key -> unwrap a VMK -> unwrap the FVEK ->
//   AES-XTS decrypt the volume.
//
// Structures follow the well-documented libbde layout. Validated against a real
// Windows 10 AES-XTS-128 volume recovered from an Optane reconstruction.
namespace de::bitlocker {

enum class EncryptionMethod : uint16_t {
    AesCbc128Diffuser = 0x8000,
    AesCbc256Diffuser = 0x8001,
    AesCbc128         = 0x8002,
    AesCbc256         = 0x8003,
    AesXts128         = 0x8004,
    AesXts256         = 0x8005,
    Unknown           = 0xFFFF,
};

// A key protected with AES-CCM: nonce + MAC + ciphertext, as stored in an
// FVE "AES-CCM encrypted key" property. Decrypting yields the wrapped key.
struct AesCcmKey {
    uint8_t nonce[12] = {};
    std::vector<uint8_t> macAndData;   // 16-byte MAC followed by ciphertext
};

// One Volume Master Key protector.
struct VmkProtector {
    std::string protectionType;        // "recovery password", "TPM", "startup key", ...
    uint16_t protectionTypeRaw = 0;
    uint8_t salt[16] = {};             // stretch-key salt (recovery/passphrase)
    bool hasSalt = false;
    std::optional<AesCcmKey> encryptedVmk;   // VMK wrapped by the protector's key
    // Present only on a clear-key protector (type 0x0000), which BitLocker
    // writes while encryption is *suspended*: the key that unwraps the VMK is
    // stored beside it in the clear, so the volume opens with no credential at
    // all. Empty for every other protector type.
    std::vector<uint8_t> clearKey;
};

struct FveMetadata {
    EncryptionMethod method = EncryptionMethod::Unknown;
    uint8_t volumeGuid[16] = {};
    std::string description;
    std::vector<VmkProtector> vmks;
    std::optional<AesCcmKey> encryptedFvek;  // FVEK wrapped by the VMK
    // Volume header block: BitLocker relocates the volume's first
    // `headerBlockSize` bytes (the original NTFS boot region) to
    // `headerBlockOffset`. Decrypted reads of the start must come from there.
    uint64_t headerBlockOffset = 0;
    uint64_t headerBlockSize = 0;
    // Size of the encrypted volume in bytes, as recorded in the FVE metadata
    // block header. This lives *inside* the volume, so unlike a partition table
    // it cannot be stale relative to the volume it describes - which makes it
    // the better authority when the two disagree.
    uint64_t encryptedVolumeSize = 0;
};

// Parse FVE metadata given the volume (partition) source. Reads the BitLocker
// boot record at offset 0, follows its first FVE metadata offset, and parses
// the metadata header + entries. Returns nullopt if not a BitLocker volume.
std::optional<FveMetadata> parseFve(ImageSource& volume);

const char* methodName(EncryptionMethod m);

// Reconcile a partition window against the BitLocker volume's own declared
// size. On a disk whose partition table is a generation behind (an Optane
// write-back cache that never flushed the final GPT write is the case that
// motivated this), the table can describe a shorter volume than BitLocker
// itself does, silently truncating the tail of the filesystem. Returns `vol`
// unchanged when they agree, otherwise a window of the declared size. `note`,
// if given, receives a description of any adjustment made.
std::shared_ptr<ImageSource> reconcileVolumeSize(std::shared_ptr<ImageSource> parent,
                                                 uint64_t baseByte,
                                                 std::shared_ptr<ImageSource> vol,
                                                 std::string* note = nullptr);

} // namespace de::bitlocker

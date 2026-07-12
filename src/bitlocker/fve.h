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
    std::optional<AesCcmKey> encryptedVmk;   // VMK wrapped by the stretch key
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
};

// Parse FVE metadata given the volume (partition) source. Reads the BitLocker
// boot record at offset 0, follows its first FVE metadata offset, and parses
// the metadata header + entries. Returns nullopt if not a BitLocker volume.
std::optional<FveMetadata> parseFve(ImageSource& volume);

const char* methodName(EncryptionMethod m);

} // namespace de::bitlocker

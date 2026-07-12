#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include "bitlocker/fve.h"

// BitLocker key flow: recovery password -> stretch key -> unwrap VMK -> unwrap
// FVEK, then AES-XTS sector decryption. Implemented with OpenSSL.
namespace de::bitlocker {

// The unlocked keys needed to decrypt the volume.
struct VolumeKeys {
    std::vector<uint8_t> fvek;        // full volume encryption key material
    EncryptionMethod method = EncryptionMethod::Unknown;
};

// Convert a 48-digit recovery password ("XXXXXX-...", 8 groups) to its 16-byte
// binary form. Returns nullopt if malformed (groups not divisible by 11, etc.).
std::optional<std::vector<uint8_t>> parseRecoveryPassword(const std::string& pw);

// Derive the 32-byte stretch key from a 16-byte recovery binary + 16-byte salt
// (SHA-256 chained 0x100000 times).
std::vector<uint8_t> deriveStretchKey(const std::vector<uint8_t>& recoveryBin,
                                      const uint8_t salt[16]);

// AES-CCM decrypt (AES-256) with MAC verification. Returns plaintext, or
// nullopt if the MAC fails (wrong key). `macAndData` is 16-byte MAC + ciphertext.
std::optional<std::vector<uint8_t>>
aesCcmDecrypt(const std::vector<uint8_t>& key, const uint8_t nonce[12],
              const std::vector<uint8_t>& macAndData);

// Full unlock: derive from the recovery password, unwrap the VMK via the
// recovery protector, then unwrap the FVEK. nullopt if the password is wrong
// (any MAC fails) or no recovery protector is present.
std::optional<VolumeKeys> unlockWithRecovery(const FveMetadata& md,
                                             const std::string& recoveryPassword);

// AES-XTS decrypt one 512-byte data unit in place. `dataUnit` is the unit
// number (volume byte offset / 512). Uses key1||key2 from the FVEK.
void aesXtsDecryptSector(const VolumeKeys& keys, uint64_t dataUnit,
                         uint8_t* sector /*512 bytes*/);

} // namespace de::bitlocker

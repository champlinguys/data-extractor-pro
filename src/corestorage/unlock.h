#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include "core/image_source.h"
#include "corestorage/cs.h"

// The CoreStorage (FileVault 2) key hierarchy: a password on one end, the
// AES-XTS volume key cs.h wants on the other.
//
// The chain, as macOS built it and as libfvde reads it back:
//
//   volume header  ->  key data + physical volume UUID
//                      (the AES-XTS key pair the *metadata* is encrypted with)
//   metadata       ->  EncryptedRoot.plist, and the logical volume family UUID
//   plist + password
//                  ->  PBKDF2-SHA256 -> passphrase key
//                  ->  AES key unwrap -> KEK
//                  ->  AES key unwrap -> volume master key (16 bytes)
//   VMK + family UUID
//                  ->  the XTS pair: key = VMK, tweak = SHA-256(VMK||family)
//
// Every step past the first is verified by the step after it: an AES key unwrap
// checks its own integrity block, so a wrong password fails at the first unwrap
// rather than producing a plausible-looking key. The volume key that comes out
// is then still put through the ordinary HFS+ check in source.h, so a unlock
// that reports success has proved itself twice.
//
// Offsets and the order of operations were taken from libfvde, which is also
// the oracle tools/verify_corestorage_password.sh checks the result against.
namespace de::corestorage {

// What the encrypted metadata yields: the plist that holds the wrapped keys,
// and the logical volume's family UUID, which the tweak key is derived from.
struct KeyMaterial {
    std::vector<std::string> plists;      // every XML plist found, in disk order
    uint8_t familyUuid[16] = {};
    bool haveFamilyUuid = false;
};

// Decrypt this physical volume's CoreStorage metadata and pull out the key
// material. Needs no credential: the metadata is encrypted with a key written
// in the clear in the volume header, which is why a password can be *checked*
// at all without the volume key. `note` receives a line on failure.
std::optional<KeyMaterial> readKeyMaterial(ImageSource& physicalVolume,
                                           const VolumeHeader& header,
                                           std::string* note = nullptr);

// Walk the hierarchy: password -> volume master key -> AES-XTS volume key.
// Returns nullopt if no user's wrapped KEK unwraps with this password, which
// is what a wrong password looks like. `note` receives a line either way.
//
// A FileVault 2 personal recovery key (the 24-character grouped form macOS
// prints when encryption is switched on) is one more crypto user in the same
// plist, so it goes in here too, exactly as typed.
std::optional<VolumeKey> volumeKeyFromPassword(ImageSource& physicalVolume,
                                               const VolumeHeader& header,
                                               const std::string& password,
                                               std::string* note = nullptr);

// The same walk, starting from key material already read. Split out so the
// caller can read the metadata once and try several passwords against it.
std::optional<VolumeKey> volumeKeyFromPassword(const KeyMaterial& material,
                                               const std::string& password,
                                               std::string* note = nullptr);

} // namespace de::corestorage

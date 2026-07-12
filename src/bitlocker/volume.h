#pragma once
#include <memory>
#include "core/image_source.h"
#include "bitlocker/fve.h"
#include "bitlocker/keys.h"

namespace de::bitlocker {

// Presents the decrypted plaintext of a BitLocker volume as an ImageSource, so
// the ordinary filesystem parsers can browse it. Decryption is per 512-byte
// sector (AES-XTS, data unit = physical offset / 512), with the volume header
// block relocation applied to the first `headerBlockSize` bytes.
//
// Note: correctness depends on the underlying (encrypted) source actually
// holding current ciphertext. With the Optane span merge that is true for the
// span-covered range (which includes the boot region, FVE metadata, and - on
// this class of device - the $MFT); reads outside it fall back to stale QLC.
class BitLockerSource : public ImageSource {
public:
    BitLockerSource(std::shared_ptr<ImageSource> encrypted, VolumeKeys keys,
                    uint64_t headerBlockOffset, uint64_t headerBlockSize)
        : enc_(std::move(encrypted)), keys_(std::move(keys)),
          hdrOff_(headerBlockOffset), hdrSize_(headerBlockSize) {}

    uint64_t size() const override { return enc_->size(); }
    size_t readAt(uint64_t off, void* buf, size_t len) override;
    std::string name() const override { return "BitLocker (decrypted)"; }

private:
    std::shared_ptr<ImageSource> enc_;
    VolumeKeys keys_;
    uint64_t hdrOff_;
    uint64_t hdrSize_;
    static constexpr uint64_t SECTOR = 512;
};

// Convenience: from a BitLocker volume source + recovery password, build the
// decrypted view. Returns nullptr if not BitLocker or the password is wrong.
std::shared_ptr<ImageSource> unlockVolume(std::shared_ptr<ImageSource> encrypted,
                                          const std::string& recoveryPassword);

} // namespace de::bitlocker

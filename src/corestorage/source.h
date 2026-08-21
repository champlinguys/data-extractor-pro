#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <optional>
#include "core/image_source.h"
#include "corestorage/cs.h"

namespace de::corestorage {

// Presents the decrypted logical volume of a CoreStorage (FileVault 2) physical
// volume as an ImageSource, so the ordinary HFS+ parser can browse it.
//
// Two coordinate systems meet here, as they do for BitLocker, but they diverge
// further. Offsets in this source are *logical volume* offsets - byte 0 is the
// first byte of the volume the filesystem lives in. The bytes actually live
// `shift` further into the physical volume, behind CoreStorage's own metadata
// (64 MiB on the reference drive).
//
// Decryption is per 512-byte sector, AES-XTS, with the tweak taken from the
// *logical* sector index (offset / 512), not the physical one. That was
// established by matching this implementation against libfvde byte for byte.
//
// Unlike a libfvde-backed reader, this has no size ceiling: libfvde indexes the
// volume with a 32-bit element number and so refuses every read past 1 TiB,
// which on a 12.73 TiB volume hides 92 percent of the data. The mapping here is
// arithmetic, so it reads the whole volume.
class CoreStorageSource : public ImageSource {
public:
    CoreStorageSource(std::shared_ptr<ImageSource> encrypted, VolumeKey key,
                      uint64_t shift, std::string label = {})
        : enc_(std::move(encrypted)), key_(std::move(key)), shift_(shift),
          label_(std::move(label)) {}

    uint64_t size() const override {
        return enc_->size() > shift_ ? enc_->size() - shift_ : 0;
    }
    size_t readAt(uint64_t off, void* buf, size_t len) override;
    std::string name() const override {
        return label_.empty() ? "CoreStorage (decrypted)"
                              : "CoreStorage (decrypted): " + label_;
    }

    uint64_t shift() const { return shift_; }

private:
    std::shared_ptr<ImageSource> enc_;
    VolumeKey key_;
    uint64_t shift_;
    std::string label_;
    static constexpr uint64_t SECTOR = 512;
    // Cap on the per-call decrypt buffer; bounds memory while keeping reads big.
    static constexpr uint64_t MAX_BATCH = 1u << 20;
};

// Where the logical volume starts inside the physical volume, found rather than
// assumed: for each candidate shift the HFS+ volume header is decrypted and
// checked. Parsing CoreStorage's own segment descriptors would be the other way
// round, but it needs the encrypted metadata decoded first - and this has the
// better failure mode, since a candidate that verifies has proved the key and
// the offset together. A wrong key finds nothing at all rather than quietly
// producing garbage.
//
// Scans sector-aligned candidates up to `maxShift` at `step`. Returns nullopt
// if no candidate yields a plausible HFS+ header.
std::optional<uint64_t> findLogicalVolumeShift(ImageSource& encrypted,
                                               const VolumeKey& key,
                                               uint64_t maxShift = 1ull << 30,
                                               uint64_t step = 1ull << 20);

// Convenience: verify `encrypted` is CoreStorage, find the logical volume with
// `key`, and return the decrypted view. Returns nullptr if it is not a
// CoreStorage volume or the key does not unlock it; `note`, if given, receives
// a line describing what happened, for the UI and the log.
std::shared_ptr<ImageSource> unlockVolume(std::shared_ptr<ImageSource> encrypted,
                                          const VolumeKey& key,
                                          std::string* note = nullptr);

} // namespace de::corestorage

#include "corestorage/source.h"
#include "core/byte_reader.h"
#include <openssl/evp.h>
#include <algorithm>
#include <cstring>
#include <vector>

namespace de::corestorage {
namespace {

constexpr uint64_t SECTOR = 512;

// Decrypt `count` consecutive sectors in place. `firstUnit` is the logical
// sector index of the first one, which is the XTS data-unit number.
void xtsDecrypt(const VolumeKey& key, uint64_t firstUnit, uint8_t* p, uint64_t count) {
    const EVP_CIPHER* c = key.xts256() ? EVP_aes_256_xts() : EVP_aes_128_xts();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    uint8_t out[SECTOR];
    for (uint64_t i = 0; i < count; ++i) {
        uint8_t tweak[16] = {};
        uint64_t unit = firstUnit + i;
        for (int b = 0; b < 8; ++b) tweak[b] = (unit >> (8 * b)) & 0xFF;  // LE unit
        int len = 0;
        uint8_t* sec = p + i * SECTOR;
        if (EVP_DecryptInit_ex(ctx, c, nullptr, key.material.data(), tweak) == 1 &&
            EVP_DecryptUpdate(ctx, out, &len, sec, static_cast<int>(SECTOR)) == 1)
            std::memcpy(sec, out, SECTOR);
        EVP_CIPHER_CTX_reset(ctx);
    }
    EVP_CIPHER_CTX_free(ctx);
}

// An HFS+/HFSX volume header sits 1024 bytes into the volume. Signature plus
// version, so a random 512 bytes of failed decryption cannot pass.
bool plausibleHfsPlus(const uint8_t* vh) {
    uint16_t sig = rdBE16(vh);
    if (sig != 0x482B /* H+ */ && sig != 0x4858 /* HX */) return false;
    uint16_t version = rdBE16(vh + 2);
    return version == 4 || version == 5;
}

} // namespace

size_t CoreStorageSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= size()) return 0;
    if (off + len > size()) len = static_cast<size_t>(size() - off);

    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    std::vector<uint8_t> blk;
    while (done < len) {
        uint64_t vOff = off + done;                 // logical volume offset
        uint64_t sectorBase = vOff & ~(SECTOR - 1);
        uint64_t inSector = vOff - sectorBase;

        // Batch a whole run in one read and one decrypt pass rather than going
        // sector by sector: on a multi-terabyte export that is the difference
        // between ~500 bytes and ~1 MiB per syscall.
        uint64_t want = std::min<uint64_t>(len - done + inSector, MAX_BATCH);
        uint64_t nsec = (want + SECTOR - 1) / SECTOR;

        blk = enc_->read(shift_ + sectorBase, static_cast<size_t>(nsec * SECTOR));
        xtsDecrypt(key_, sectorBase / SECTOR, blk.data(), nsec);

        size_t chunk = static_cast<size_t>(
            std::min<uint64_t>(nsec * SECTOR - inSector, len - done));
        std::memcpy(out + done, blk.data() + inSector, chunk);
        done += chunk;
    }
    return done;
}

std::optional<uint64_t> findLogicalVolumeShift(ImageSource& encrypted,
                                               const VolumeKey& key,
                                               uint64_t maxShift, uint64_t step) {
    if (!key.valid()) return std::nullopt;
    if (step < SECTOR) step = SECTOR;
    step &= ~(SECTOR - 1);

    // The HFS+ header is at logical 1024, i.e. logical sector 2.
    constexpr uint64_t VH_OFFSET = 1024;
    for (uint64_t shift = 0; shift <= maxShift; shift += step) {
        if (shift + VH_OFFSET + SECTOR > encrypted.size()) break;
        uint8_t sec[SECTOR];
        if (encrypted.readAt(shift + VH_OFFSET, sec, sizeof sec) < sizeof sec) continue;
        xtsDecrypt(key, VH_OFFSET / SECTOR, sec, 1);
        if (plausibleHfsPlus(sec)) return shift;
    }
    return std::nullopt;
}

std::shared_ptr<ImageSource> unlockVolume(std::shared_ptr<ImageSource> encrypted,
                                          const VolumeKey& key, std::string* note) {
    auto header = parseHeader(*encrypted);
    if (!header) {
        if (note) *note = "not a CoreStorage volume";
        return nullptr;
    }
    if (!header->isEncrypted()) {
        if (note) *note = "CoreStorage volume is not encrypted; no key needed";
        return nullptr;
    }
    if (!key.valid()) {
        if (note) *note = "volume key must be 32 bytes (AES-XTS-128) or 64 (AES-XTS-256)";
        return nullptr;
    }
    auto shift = findLogicalVolumeShift(*encrypted, key);
    if (!shift) {
        if (note)
            *note = "no HFS+ volume found with that key - wrong key, or the "
                    "logical volume starts beyond the search window";
        return nullptr;
    }
    if (note)
        *note = "logical volume found " + std::to_string(*shift >> 20) +
                " MiB into the CoreStorage volume (" + header->identifier + ")";
    return std::make_shared<CoreStorageSource>(std::move(encrypted), key, *shift,
                                               header->identifier);
}

} // namespace de::corestorage

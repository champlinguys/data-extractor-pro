#include "bitlocker/volume.h"
#include <algorithm>
#include <cstring>

namespace de::bitlocker {

size_t BitLockerSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= size()) return 0;
    if (off + len > size()) len = static_cast<size_t>(size() - off);

    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    uint8_t sector[512];
    while (done < len) {
        uint64_t vOff = off + done;               // plaintext volume offset
        uint64_t sectorBase = vOff & ~(SECTOR - 1);
        uint64_t inSector = vOff - sectorBase;
        size_t chunk = static_cast<size_t>(std::min<uint64_t>(SECTOR - inSector,
                                                              len - done));
        // The volume's first hdrSize_ bytes were relocated to hdrOff_.
        uint64_t phys = sectorBase;
        if (hdrSize_ && sectorBase < hdrSize_) phys = hdrOff_ + sectorBase;

        auto enc = enc_->read(phys, SECTOR);
        std::memcpy(sector, enc.data(), SECTOR);
        aesXtsDecryptSector(keys_, phys / SECTOR, sector);
        std::memcpy(out + done, sector + inSector, chunk);
        done += chunk;
    }
    return done;
}

std::shared_ptr<ImageSource> unlockVolume(std::shared_ptr<ImageSource> encrypted,
                                          const std::string& recoveryPassword) {
    auto md = parseFve(*encrypted);
    if (!md) return nullptr;
    auto keys = unlockWithRecovery(*md, recoveryPassword);
    if (!keys) return nullptr;
    return std::make_shared<BitLockerSource>(encrypted, *keys,
                                             md->headerBlockOffset,
                                             md->headerBlockSize);
}

} // namespace de::bitlocker

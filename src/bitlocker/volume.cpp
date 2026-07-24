#include "bitlocker/volume.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace de::bitlocker {

size_t BitLockerSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= size()) return 0;
    if (off + len > size()) len = static_cast<size_t>(size() - off);

    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    std::vector<uint8_t> blk;
    while (done < len) {
        uint64_t vOff = off + done;               // plaintext volume offset
        uint64_t sectorBase = vOff & ~(SECTOR - 1);
        uint64_t inSector = vOff - sectorBase;

        // The volume's first hdrSize_ bytes were relocated to hdrOff_, so the
        // physical mapping is contiguous only up to that boundary. Batch within
        // one contiguous run: one read and one allocation for the whole run
        // instead of one per 512-byte sector, which is the difference between
        // ~500 bytes and ~1 MiB per syscall when exporting large files.
        bool relocated = hdrSize_ && sectorBase < hdrSize_;
        uint64_t runEnd = relocated ? hdrSize_ : size();
        uint64_t phys = relocated ? hdrOff_ + sectorBase : sectorBase;

        uint64_t want = std::min<uint64_t>(len - done + inSector, runEnd - sectorBase);
        want = std::min<uint64_t>(want, MAX_BATCH);
        uint64_t nsec = (want + SECTOR - 1) / SECTOR;

        blk = enc_->read(phys, static_cast<size_t>(nsec * SECTOR));
        for (uint64_t i = 0; i < nsec; ++i)
            decryptSector(keys_, phys / SECTOR + i, blk.data() + i * SECTOR);

        size_t chunk = static_cast<size_t>(
            std::min<uint64_t>(nsec * SECTOR - inSector, len - done));
        std::memcpy(out + done, blk.data() + inSector, chunk);
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

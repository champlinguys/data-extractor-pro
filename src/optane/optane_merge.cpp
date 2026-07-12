#include "optane/optane_merge.h"
#include <algorithm>
#include <cstring>

namespace de::optane {

OptaneMergeSource::OptaneMergeSource(std::shared_ptr<ImageSource> qlc,
                                     std::shared_ptr<ImageSource> optane,
                                     std::shared_ptr<NvCacheMap> map,
                                     uint64_t volumeSizeBytes)
    : qlc_(std::move(qlc)), optane_(std::move(optane)), map_(std::move(map)),
      volumeSize_(volumeSizeBytes) {}

size_t OptaneMergeSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= volumeSize_) return 0;
    if (off + len > volumeSize_) len = static_cast<size_t>(volumeSize_ - off);

    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        uint64_t abs = off + done;
        uint64_t lba = abs / SECTOR;
        uint64_t inSector = abs % SECTOR;
        size_t chunk = static_cast<size_t>(std::min<uint64_t>(SECTOR - inSector,
                                                              len - done));
        // Cache map wins when it holds a current copy of this sector; otherwise
        // fall through to the QLC. A null map => pure QLC passthrough.
        std::optional<uint64_t> hit;
        if (map_) hit = map_->lookup(lba);
        if (hit) {
            optane_->readAt(*hit + inSector, out + done, chunk);
        } else {
            qlc_->readAt(abs, out + done, chunk);
        }
        done += chunk;
    }
    return done;
}

} // namespace de::optane

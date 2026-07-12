#include "optane/span_map.h"
#include "optane/imsm.h"
#include "core/byte_reader.h"
#include <cstring>

namespace de::optane {

std::shared_ptr<ImageSource> makeSpanMerge(std::shared_ptr<ImageSource> qlc,
                                           std::shared_ptr<ImageSource> optane,
                                           uint64_t cacheHintBytes) {
    // Optane offset 0 must be a filesystem/BitLocker boot record for the span
    // to be a linear volume copy. Its hidden-sectors field is the disk LBA the
    // span begins at.
    auto vbr = optane->read(0, 512);
    bool isVbr = std::memcmp(vbr.data() + 3, "-FVE-FS-", 8) == 0 ||
                 std::memcmp(vbr.data() + 3, "NTFS    ", 8) == 0;
    if (!isVbr || vbr[510] != 0x55 || vbr[511] != 0xAA)
        return nullptr;
    uint64_t spanStart = rd32(&vbr[0x1C]); // NTFS/BDE hidden sectors

    // Span length = start of the Intel Cache metadata region (end of the span
    // component). Fall back to the whole Optane image if IMSM isn't found.
    uint64_t spanLenSectors = optane->size() / 512;
    if (auto md = parseImsm(*optane, cacheHintBytes))
        spanLenSectors = md->cacheRegionOffset / 512;

    auto map = std::make_shared<SpanCacheMap>(spanStart, spanLenSectors);
    return std::make_shared<OptaneMergeSource>(qlc, optane, map, qlc->size());
}

} // namespace de::optane

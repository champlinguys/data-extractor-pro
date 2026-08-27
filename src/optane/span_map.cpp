#include "optane/span_map.h"
#include "optane/imsm.h"
#include "core/byte_reader.h"
#include <cstring>

namespace de::optane {

std::shared_ptr<ImageSource> makeSpanMerge(std::shared_ptr<ImageSource> qlc,
                                           std::shared_ptr<ImageSource> optane,
                                           uint64_t cacheHintBytes,
                                           std::string* why) {
    auto fail = [&](const char* msg) -> std::shared_ptr<ImageSource> {
        if (why) *why = msg;
        return nullptr;
    };
    // Optane offset 0 must be a filesystem/BitLocker boot record for the span
    // to be a linear volume copy. Its hidden-sectors field is the disk LBA the
    // span begins at.
    auto vbr = optane->read(0, 512);
    bool isVbr = std::memcmp(vbr.data() + 3, "-FVE-FS-", 8) == 0 ||
                 std::memcmp(vbr.data() + 3, "NTFS    ", 8) == 0;
    if (!isVbr || vbr[510] != 0x55 || vbr[511] != 0xAA)
        return fail("no linear span at Optane offset 0 (not a boot record) - "
                    "this module caches through the mapping table only");
    uint64_t spanStart = rd32(&vbr[0x1C]); // NTFS/BDE hidden sectors

    // Span length = start of the Intel Cache metadata region (end of the span
    // component). Without it we do not know where the linear copy stops, and
    // guessing long is destructive: past the span the Optane holds cache
    // metadata, so we would serve ~20 GB of metadata as volume data and make
    // the reconstruction worse than the plain QLC. Decline instead.
    auto md = parseImsm(*optane, cacheHintBytes);
    if (!md)
        return fail("found a linear span but no Intel Cache region, so its "
                    "length is unknown - re-run with the Intel Cache partition "
                    "start sector to use it");
    uint64_t spanLenSectors = md->cacheRegionOffset / 512;

    auto map = std::make_shared<SpanCacheMap>(spanStart, spanLenSectors);
    return std::make_shared<OptaneMergeSource>(qlc, optane, map, qlc->size());
}

} // namespace de::optane

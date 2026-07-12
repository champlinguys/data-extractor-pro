#pragma once
#include <memory>
#include "optane/optane_merge.h"
#include "core/image_source.h"

namespace de::optane {

// The verified, decodable half of Intel Optane reconstruction: the Optane
// "span component" is a linear, sector-for-sector copy of the cached volume
// starting at a fixed disk LBA (see FORMAT_NOTES.md §2c). This map serves that
// region from the Optane and everything else from the QLC.
//
// It does NOT cover blocks held only in the hashed NV-cache (§3, undecoded), so
// it is exact for the span range (which crucially includes the BitLocker FVE
// metadata) and falls back to the QLC elsewhere.
class SpanCacheMap : public NvCacheMap {
public:
    // spanDiskStartLba: disk LBA that Optane offset 0 corresponds to.
    // spanLenSectors:   length of the linear span, in 512-byte sectors.
    SpanCacheMap(uint64_t spanDiskStartLba, uint64_t spanLenSectors)
        : start_(spanDiskStartLba), len_(spanLenSectors) {}

    std::optional<uint64_t> lookup(uint64_t volumeLba) const override {
        if (volumeLba >= start_ && volumeLba < start_ + len_)
            return (volumeLba - start_) * 512; // byte offset within the Optane
        return std::nullopt;
    }

    uint64_t startLba() const { return start_; }
    uint64_t lenSectors() const { return len_; }

private:
    uint64_t start_;
    uint64_t len_;
};

// Auto-detect the span parameters from the two images and build the merged
// reconstructed disk as a single ImageSource. Returns nullptr if the Optane
// image doesn't look like a span-backed Optane device.
//
// Detection: spanDiskStart = the VBR hidden-sectors field at Optane offset 0
// (an NTFS/BitLocker boot record records its own partition start there);
// spanLen = the IMSM Intel-Cache region offset (end of the span component).
// `cacheHintBytes` is the Intel Cache region offset if known, to skip the slow
// full-device IMSM signature scan.
std::shared_ptr<ImageSource> makeSpanMerge(std::shared_ptr<ImageSource> qlc,
                                           std::shared_ptr<ImageSource> optane,
                                           uint64_t cacheHintBytes = UINT64_MAX);

} // namespace de::optane

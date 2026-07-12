#pragma once
#include <memory>
#include <optional>
#include <cstdint>
#include "core/image_source.h"
#include "optane/imsm.h"

namespace de::optane {

// The decoded NV-cache mapping: for a volume LBA that is resident in Optane,
// where to read it from. This is the piece still under reverse-engineering
// (see FORMAT_NOTES.md section 3); the interface is fixed so the merge logic is ready.
class NvCacheMap {
public:
    virtual ~NvCacheMap() = default;
    // If `volumeLba` (512-byte sector) currently lives in Optane, return the
    // byte offset within the Optane image holding its current data.
    virtual std::optional<uint64_t> lookup(uint64_t volumeLba) const = 0;
};

// Merged Optane+QLC volume presented as a single ImageSource. Reads are served
// per-sector from Optane where the cache map has a current copy, otherwise from
// the QLC. Everything above (partition scan, filesystem parsers) runs unchanged
// on top of this - including handing partition 3 to the BitLocker layer.
//
// With a null map it degrades to a pure QLC passthrough (the stale view), so
// the rest of the tool works today and gains correctness the moment the map is
// decoded.
class OptaneMergeSource : public ImageSource {
public:
    OptaneMergeSource(std::shared_ptr<ImageSource> qlc,
                      std::shared_ptr<ImageSource> optane,
                      std::shared_ptr<NvCacheMap> map,
                      uint64_t volumeSizeBytes);

    uint64_t size() const override { return volumeSize_; }
    size_t readAt(uint64_t off, void* buf, size_t len) override;
    std::string name() const override { return "Optane merge (QLC+Optane)"; }

private:
    std::shared_ptr<ImageSource> qlc_;
    std::shared_ptr<ImageSource> optane_;
    std::shared_ptr<NvCacheMap> map_;
    uint64_t volumeSize_;
    static constexpr uint64_t SECTOR = 512;
};

} // namespace de::optane

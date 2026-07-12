#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include "core/image_source.h"

namespace de {

// A discovered partition: an offset+length window into the image, plus a hint
// about what it is. The `scheme` records how we found it.
struct Partition {
    uint64_t firstByte = 0;
    uint64_t lengthBytes = 0;
    std::string typeName;   // e.g. "NTFS / exFAT", "Linux filesystem", "EFI System"
    std::string scheme;     // "MBR" or "GPT"
    int index = 0;          // 1-based ordinal for display

    // Present this partition to a filesystem parser as a standalone source.
    std::shared_ptr<ImageSource> asSource(std::shared_ptr<ImageSource> parent) const {
        return std::make_shared<SubImageSource>(
            parent, firstByte, lengthBytes, "partition " + std::to_string(index));
    }
};

// Scan an image for partitions. Recognises a GPT (via its protective MBR) and
// falls back to a classic MBR partition table. If neither is present, returns a
// single whole-image "partition" so the caller can still try to mount an FS
// that lives directly on the media (common for USB sticks and, notably, for the
// reconstructed volume behind an Intel RST/Optane cached device).
std::vector<Partition> scanPartitions(const std::shared_ptr<ImageSource>& img);

} // namespace de

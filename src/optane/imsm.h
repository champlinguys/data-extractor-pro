#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include "core/image_source.h"

// Parser for Intel IMSM (Matrix Storage Manager / RST) metadata — the
// "Intel Raid ISM Cfg Sig." structure, identical to the format Linux mdadm
// reads as "imsm". On an Optane Memory module this metadata lives in the Intel
// Cache region of the Optane device and describes the cached (QLC) disk and the
// logical volume geometry.
//
// This is the DOCUMENTED half of Optane reconstruction and is fully
// implementable today. The NV-cache mapping table (which LBAs are resident in
// Optane) is the still-open half — see FORMAT_NOTES.md.
namespace de::optane {

struct ImsmDisk {
    std::string serial;
    uint64_t totalBlocks = 0;   // in 512-byte sectors
    uint32_t status = 0;
};

struct ImsmVolume {
    std::string name;
    uint64_t sizeBlocks = 0;    // logical volume size in 512-byte sectors
};

struct ImsmMetadata {
    uint32_t familyNum = 0;
    uint32_t generationNum = 0;
    uint8_t numDisks = 0;
    uint8_t numRaidDevs = 0;
    std::vector<ImsmDisk> disks;
    std::vector<ImsmVolume> volumes;

    // Byte offset (within the Optane image) of the Intel Cache metadata region.
    // Empirically the "Intel Cache partition" start; used to locate signatures.
    uint64_t cacheRegionOffset = 0;
};

// Scan an Optane image for the Intel Cache region and parse the IMSM super.
// Returns nullopt if no `Intel Raid ISM Cfg Sig.` block is found.
//
// `hintCacheOffset` is the byte offset of the Intel Cache metadata region if
// known (e.g. a reference tool's "Intel Cache partition" start); passing it avoids
// a slow full-device scan for the signature.
std::optional<ImsmMetadata> parseImsm(ImageSource& optane,
                                      uint64_t hintCacheOffset = UINT64_MAX);

} // namespace de::optane

#include "fs/filesystem.h"
#include "fs/ntfs/ntfs.h"
#include <cstring>

namespace de {

std::string detectFilesystemName(ImageSource& vol) {
    if (NtfsFilesystem::probe(vol)) return "NTFS";

    // BitLocker volume: FVE boot record signature at offset 3.
    uint8_t vbr[512];
    if (vol.readAt(0, vbr, sizeof vbr) >= 11 &&
        std::memcmp(vbr + 3, "-FVE-FS-", 8) == 0)
        return "BitLocker (encrypted)";

    // Cheap signature sniffing for the filesystems still on the roadmap, so the
    // UI can label volumes it can't yet browse.
    uint8_t buf[2048];
    size_t n = vol.readAt(1024, buf, sizeof buf); // ext superblock @ 1024
    if (n >= 0x40) {
        uint16_t magic = static_cast<uint16_t>(buf[0x38] | (buf[0x39] << 8));
        if (magic == 0xEF53) return "ext2/3/4 (browsing not yet implemented)";
    }
    uint8_t hdr[8];
    if (vol.readAt(1024, hdr, 8) >= 2) {
        if (std::memcmp(hdr, "H+", 2) == 0) return "HFS+ (browsing not yet implemented)";
        if (std::memcmp(hdr, "HX", 2) == 0) return "HFSX (browsing not yet implemented)";
    }
    return "Unknown";
}

std::unique_ptr<Filesystem> detectFilesystem(std::shared_ptr<ImageSource> vol) {
    if (auto ntfs = NtfsFilesystem::open(vol)) return ntfs;
    // HFS+ and ext4 will slot in here as they come online.
    return nullptr;
}

} // namespace de

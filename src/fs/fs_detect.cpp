#include "fs/filesystem.h"
#include "fs/ntfs/ntfs.h"
#include "fs/hfs/hfs.h"
#include "fs/apfs/apfs.h"
#include "fs/hfsplus/hfsplus.h"
#include "corestorage/cs.h"
#include <cstring>

namespace de {

std::string detectFilesystemName(ImageSource& vol) {
    if (NtfsFilesystem::probe(vol)) return "NTFS";
    if (HfsFilesystem::probe(vol)) return "HFS";
    if (ApfsFilesystem::probe(vol)) return "APFS";
    if (HfsPlusFilesystem::probe(vol)) return "HFS+";

    // BitLocker volume: FVE boot record signature at offset 3.
    uint8_t vbr[512] = {};
    size_t vbrLen = vol.readAt(0, vbr, sizeof vbr);
    if (vbrLen >= 11 && std::memcmp(vbr + 3, "-FVE-FS-", 8) == 0)
        return "BitLocker (encrypted)";

    // CoreStorage (FileVault 2): the volume's own header, not the GPT type, so
    // this still labels the volume correctly when the partition table is gone.
    if (de::corestorage::looksLikeCoreStorage(vbr, vbrLen)) {
        if (auto h = de::corestorage::parseHeader(vol))
            return h->isEncrypted() ? "CoreStorage / FileVault 2 (encrypted)"
                                    : "CoreStorage (unencrypted)";
        return "CoreStorage / FileVault 2 (encrypted)";
    }

    // Cheap signature sniffing for the filesystems still on the roadmap, so the
    // UI can label volumes it can't yet browse.
    uint8_t buf[2048];
    size_t n = vol.readAt(1024, buf, sizeof buf); // ext superblock @ 1024
    if (n >= 0x40) {
        uint16_t magic = static_cast<uint16_t>(buf[0x38] | (buf[0x39] << 8));
        if (magic == 0xEF53) return "ext2/3/4 (browsing not yet implemented)";
    }
    return "Unknown";
}

std::unique_ptr<Filesystem> detectFilesystem(std::shared_ptr<ImageSource> vol) {
    if (auto ntfs = NtfsFilesystem::open(vol)) return ntfs;
    if (auto hfs = HfsFilesystem::open(vol)) return hfs;
    if (auto hfsp = HfsPlusFilesystem::open(vol)) return hfsp;
    if (auto apfs = ApfsFilesystem::open(vol)) return apfs;
    // ext4 will slot in here as it comes online.
    return nullptr;
}

} // namespace de

#include "fs/filesystem.h"
#include "fs/ntfs/ntfs.h"
#include "fs/hfs/hfs.h"
#include "fs/apfs/apfs.h"
#include "fs/hfsplus/hfsplus.h"
#include "fs/exfat/exfat.h"
#include "fs/fat/fat.h"
#include "corestorage/cs.h"
#include "core/byte_reader.h"
#include <cstring>

namespace de {

std::string detectFilesystemName(ImageSource& vol) {
    if (NtfsFilesystem::probe(vol)) return "NTFS";
    if (HfsFilesystem::probe(vol)) return "HFS";
    if (ApfsFilesystem::probe(vol)) return "APFS";
    if (HfsPlusFilesystem::probe(vol)) return "HFS+";
    if (ExfatFilesystem::probe(vol)) return "exFAT";
    if (FatFilesystem::probe(vol)) return "FAT32";

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

    // FAT12/FAT16: the same BPB FAT32 extends, but with a fixed-size root
    // directory and narrower FAT entries, so FatFilesystem does not accept them.
    // The boot sector still says what they are, and a volume labelled "FAT16"
    // is far more use to someone staring at an old drive than "Unknown".
    if (vbrLen >= 512 && vbr[510] == 0x55 && vbr[511] == 0xAA &&
        rd16(vbr + 0x0B) >= 512 &&        // a plausible sector size
        rd16(vbr + 0x11) != 0 &&          // a root directory of fixed size
        rd16(vbr + 0x16) != 0) {          // ...and a 16-bit FAT size: not FAT32
        if (std::memcmp(vbr + 0x36, "FAT12", 5) == 0)
            return "FAT12 (browsing not yet implemented)";
        if (std::memcmp(vbr + 0x36, "FAT16", 5) == 0)
            return "FAT16 (browsing not yet implemented)";
        if (std::memcmp(vbr + 0x36, "FAT", 3) == 0)
            return "FAT12/16 (browsing not yet implemented)";
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
    if (auto exfat = ExfatFilesystem::open(vol)) return exfat;
    if (auto fat = FatFilesystem::open(vol)) return fat;
    // ext4 will slot in here as it comes online.
    return nullptr;
}

} // namespace de

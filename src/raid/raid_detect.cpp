#include "raid/raid_detect.h"
#include "core/byte_reader.h"
#include "fs/apfs/apfs.h"
#include "fs/apfs/apfs_container.h"
#include "fs/hfs/hfs.h"
#include "fs/hfsplus/hfsplus.h"
#include "fs/ntfs/ntfs.h"
#include "fs/filesystem.h"
#include "partition/partition.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <numeric>
#include <zlib.h>

namespace de::raid {

namespace {

// A score at or above this, with the deep filesystem check enabled, means we
// really did reassemble the original disk: it takes a correct geometry to make
// APFS list a directory or a GPT's CRCs agree.
constexpr int CONFIDENT_SCORE = 12;

// Find `needle` in a region of a device, at `step`-aligned positions.
std::vector<uint64_t> findSignature(ImageSource& dev, const char* needle, size_t nlen,
                                    uint64_t from, uint64_t to, uint64_t step,
                                    size_t maxHits) {
    std::vector<uint64_t> hits;
    const size_t CHUNK = 1u << 20;
    std::vector<uint8_t> buf(CHUNK);
    for (uint64_t off = from; off < to && hits.size() < maxHits; off += CHUNK) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(CHUNK, to - off));
        size_t got = dev.readAt(off, buf.data(), want);
        if (got < nlen) break;
        for (uint64_t p = 0; p + nlen <= got; p += step) {
            if (std::memcmp(buf.data() + p, needle, nlen) == 0) {
                hits.push_back(off + p);
                if (hits.size() >= maxHits) break;
            }
        }
    }
    return hits;
}

// Pull a <key>NAME</key><string>VALUE</string> pair out of an XML plist.
std::optional<std::string> plistString(const std::string& xml, const std::string& key) {
    std::string k = "<key>" + key + "</key>";
    size_t p = xml.find(k);
    if (p == std::string::npos) return std::nullopt;
    size_t s = xml.find("<string>", p);
    if (s == std::string::npos) return std::nullopt;
    size_t e = xml.find("</string>", s);
    if (e == std::string::npos) return std::nullopt;
    // Guard against picking up a value that belongs to a later key.
    if (s > p + k.size() + 64) return std::nullopt;
    return xml.substr(s + 8, e - s - 8);
}

std::optional<uint64_t> plistInt(const std::string& xml, const std::string& key) {
    std::string k = "<key>" + key + "</key>";
    size_t p = xml.find(k);
    if (p == std::string::npos) return std::nullopt;
    size_t s = xml.find("<integer>", p);
    if (s == std::string::npos) return std::nullopt;
    size_t e = xml.find("</integer>", s);
    if (e == std::string::npos) return std::nullopt;
    if (s > p + k.size() + 64) return std::nullopt;
    return std::strtoull(xml.substr(s + 9, e - s - 9).c_str(), nullptr, 10);
}

std::optional<Level> levelFromName(const std::string& name) {
    std::string n;
    for (char c : name) n += static_cast<char>(std::tolower(c));
    if (n.find("stripe") != std::string::npos || n.find("raid 0") != std::string::npos ||
        n.find("raid0") != std::string::npos)
        return Level::Stripe;
    if (n.find("mirror") != std::string::npos || n.find("raid 1") != std::string::npos ||
        n.find("raid1") != std::string::npos)
        return Level::Mirror;
    if (n.find("concat") != std::string::npos || n.find("jbod") != std::string::npos ||
        n.find("span") != std::string::npos)
        return Level::Concat;
    return std::nullopt;
}

// NUL-padded fixed-width ASCII out of a metadata block.
std::string fixedString(const uint8_t* p, size_t max) {
    size_t n = 0;
    while (n < max && p[n] >= 0x20 && p[n] < 0x7F) ++n;
    return std::string(reinterpret_cast<const char*>(p), n);
}

uint32_t crc32of(const uint8_t* p, size_t n) {
    return static_cast<uint32_t>(crc32(0, p, static_cast<uInt>(n)));
}

// Check a GPT header's own CRC (computed with the CRC field zeroed).
bool gptHeaderCrcOk(std::vector<uint8_t> hdr) {
    if (hdr.size() < 92) return false;
    uint32_t hdrSize = rd32(hdr.data() + 12);
    if (hdrSize < 92 || hdrSize > hdr.size()) return false;
    uint32_t stored = rd32(hdr.data() + 16);
    std::memset(hdr.data() + 16, 0, 4);
    return crc32of(hdr.data(), hdrSize) == stored;
}

// Offsets at which a member's *data* might begin: 0, plus anywhere near the
// front of the disk that a GPT or an APFS container header turns up. RAID
// implementations that reserve room for their own metadata push the real disk
// image down by a fixed amount, and this finds that amount without having to
// know the metadata format.
std::vector<uint64_t> dataStartCandidates(ImageSource& dev) {
    std::vector<uint64_t> out{0};
    const uint64_t limit = std::min<uint64_t>(dev.size(), 64ull << 20);
    std::vector<uint8_t> buf(1u << 20);
    for (uint64_t base = 0; base < limit && out.size() < 4; base += buf.size()) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(buf.size(), limit - base));
        size_t got = dev.readAt(base, buf.data(), want);
        for (uint64_t p = 0; p + 4096 <= got; p += 4096) {
            uint64_t off = base + p;
            if (off == 0) continue;
            bool gpt = std::memcmp(buf.data() + p + 512, "EFI PART", 8) == 0;
            bool nxsb = rd32(buf.data() + p + 32) == apfs::NX_MAGIC;
            if (gpt || nxsb) {
                out.push_back(off);
                if (out.size() >= 4) break;
            }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Confirming a geometry from file contents.
//
// Metadata checks are necessary but not sufficient. A wrong stripe size
// aliases: with a guess of 128 KiB against a true 64 KiB, half the address
// space still maps correctly, and if the volume header, catalog and backup
// header all happen to land in that half, every structural check passes while
// the file data is quietly interleaved wrong. That is the worst possible
// failure for a recovery tool - a clean-looking listing and shredded files.
//
// So we check the data itself. Files whose names promise a particular format
// must actually start with that format's signature. This is what an engineer
// does by eye when confirming a stripe size, and it samples the whole address
// space because file data is most of the disk.

struct Signature {
    const char* ext;
    const uint8_t* magic;
    size_t len;
    size_t offset;
};

const uint8_t MAGIC_JPEG[] = {0xFF, 0xD8, 0xFF};
const uint8_t MAGIC_TIFF_LE[] = {'I', 'I', 0x2A, 0x00};
const uint8_t MAGIC_TIFF_BE[] = {'M', 'M', 0x00, 0x2A};
const uint8_t MAGIC_CR2[] = {'I', 'I', 0x2A, 0x00};
const uint8_t MAGIC_PNG[] = {0x89, 'P', 'N', 'G'};
const uint8_t MAGIC_PDF[] = {'%', 'P', 'D', 'F'};
const uint8_t MAGIC_ZIP[] = {'P', 'K', 0x03, 0x04};
const uint8_t MAGIC_FTYP[] = {'f', 't', 'y', 'p'};
const uint8_t MAGIC_GIF[] = {'G', 'I', 'F', '8'};
const uint8_t MAGIC_PSD[] = {'8', 'B', 'P', 'S'};
const uint8_t MAGIC_RIFF[] = {'R', 'I', 'F', 'F'};
const uint8_t MAGIC_FORM[] = {'F', 'O', 'R', 'M'};
const uint8_t MAGIC_OLE[] = {0xD0, 0xCF, 0x11, 0xE0};
const uint8_t MAGIC_GZ[] = {0x1F, 0x8B};
const uint8_t MAGIC_ID3[] = {'I', 'D', '3'};

// Extension -> what the first bytes must look like. Raw camera formats are all
// TIFF containers, which is what makes this so useful on a photo archive.
const std::vector<std::pair<std::string, std::vector<Signature>>> SIGNATURES = {
    {"jpg", {{"jpg", MAGIC_JPEG, 3, 0}}},
    {"jpeg", {{"jpeg", MAGIC_JPEG, 3, 0}}},
    {"nef", {{"nef", MAGIC_TIFF_LE, 4, 0}, {"nef", MAGIC_TIFF_BE, 4, 0}}},
    {"cr2", {{"cr2", MAGIC_CR2, 4, 0}}},
    {"cr3", {{"cr3", MAGIC_FTYP, 4, 4}}},
    {"dng", {{"dng", MAGIC_TIFF_LE, 4, 0}, {"dng", MAGIC_TIFF_BE, 4, 0}}},
    {"arw", {{"arw", MAGIC_TIFF_LE, 4, 0}}},
    {"orf", {{"orf", MAGIC_TIFF_LE, 4, 0}}},
    {"rw2", {{"rw2", MAGIC_TIFF_LE, 4, 0}}},
    {"tif", {{"tif", MAGIC_TIFF_LE, 4, 0}, {"tif", MAGIC_TIFF_BE, 4, 0}}},
    {"tiff", {{"tiff", MAGIC_TIFF_LE, 4, 0}, {"tiff", MAGIC_TIFF_BE, 4, 0}}},
    {"png", {{"png", MAGIC_PNG, 4, 0}}},
    {"gif", {{"gif", MAGIC_GIF, 4, 0}}},
    {"pdf", {{"pdf", MAGIC_PDF, 4, 0}}},
    {"psd", {{"psd", MAGIC_PSD, 4, 0}}},
    {"zip", {{"zip", MAGIC_ZIP, 4, 0}}},
    {"docx", {{"docx", MAGIC_ZIP, 4, 0}}},
    {"xlsx", {{"xlsx", MAGIC_ZIP, 4, 0}}},
    {"pptx", {{"pptx", MAGIC_ZIP, 4, 0}}},
    {"key", {{"key", MAGIC_ZIP, 4, 0}}},
    {"pages", {{"pages", MAGIC_ZIP, 4, 0}}},
    {"mov", {{"mov", MAGIC_FTYP, 4, 4}}},
    {"mp4", {{"mp4", MAGIC_FTYP, 4, 4}}},
    {"m4v", {{"m4v", MAGIC_FTYP, 4, 4}}},
    {"m4a", {{"m4a", MAGIC_FTYP, 4, 4}}},
    {"heic", {{"heic", MAGIC_FTYP, 4, 4}}},
    {"wav", {{"wav", MAGIC_RIFF, 4, 0}}},
    {"avi", {{"avi", MAGIC_RIFF, 4, 0}}},
    {"aif", {{"aif", MAGIC_FORM, 4, 0}}},
    {"aiff", {{"aiff", MAGIC_FORM, 4, 0}}},
    {"mp3", {{"mp3", MAGIC_ID3, 3, 0}}},
    {"doc", {{"doc", MAGIC_OLE, 4, 0}}},
    {"xls", {{"xls", MAGIC_OLE, 4, 0}}},
    {"ppt", {{"ppt", MAGIC_OLE, 4, 0}}},
    {"gz", {{"gz", MAGIC_GZ, 2, 0}}},
    {"tgz", {{"tgz", MAGIC_GZ, 2, 0}}},
};

std::string lowerExt(const std::string& name) {
    size_t dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 >= name.size()) return "";
    std::string ext = name.substr(dot + 1);
    if (ext.size() > 5) return "";
    for (auto& c : ext) c = static_cast<char>(std::tolower(c));
    return ext;
}

const std::vector<Signature>* signaturesFor(const std::string& name) {
    std::string ext = lowerExt(name);
    if (ext.empty()) return nullptr;
    for (const auto& e : SIGNATURES)
        if (e.first == ext) return &e.second;
    return nullptr;
}

struct ContentCheck {
    int checked = 0;
    int matched = 0;
    int filesSeen = 0;
};

// Walk a mounted filesystem, sampling files whose type we can recognise, and
// report how many actually start the way they should.
ContentCheck checkFileContents(Filesystem& fs, const FsNode& root, int wanted) {
    ContentCheck cc;
    std::function<void(const FsNode&, int)> walk = [&](const FsNode& dir, int depth) {
        if (cc.checked >= wanted || depth > 12) return;
        for (const auto& n : fs.listDir(dir)) {
            if (cc.checked >= wanted) return;
            if (n.isDir) {
                walk(n, depth + 1);
                continue;
            }
            ++cc.filesSeen;
            const auto* sigs = signaturesFor(n.name);
            if (!sigs || n.size < 32) continue;
            auto head = fs.readHead(n, 64);
            if (head.size() < 16) continue;
            ++cc.checked;
            for (const auto& s : *sigs) {
                if (head.size() >= s.offset + s.len &&
                    std::memcmp(head.data() + s.offset, s.magic, s.len) == 0) {
                    ++cc.matched;
                    break;
                }
            }
        }
    };
    walk(root, 0);
    return cc;
}

} // namespace

MemberMetadata readMemberMetadata(ImageSource& dev) {
    MemberMetadata md;
    const uint64_t size = dev.size();

    // Apple software RAID: a header block carrying an XML plist that spells the
    // whole set out. It is not at a fixed offset across versions, so search the
    // ends of the disk where it is always kept.
    auto hits = findSignature(dev, "AppleRAIDHeader", 15, 0,
                              std::min<uint64_t>(size, 1ull << 20), 512, 2);
    if (hits.empty() && size > (32ull << 20)) {
        auto tail = findSignature(dev, "AppleRAIDHeader", 15, size - (32ull << 20),
                                  size, 512, 2);
        hits.insert(hits.end(), tail.begin(), tail.end());
    }
    if (!hits.empty()) {
        md.format = "AppleRAID";
        auto blob = dev.read(hits[0], 128u << 10);
        std::string xml(reinterpret_cast<const char*>(blob.data()), blob.size());
        size_t x = xml.find("<?xml");
        if (x != std::string::npos) {
            xml = xml.substr(x);
            size_t end = xml.find("</plist>");
            if (end != std::string::npos) xml = xml.substr(0, end);
            if (auto v = plistString(xml, "AppleRAID-LevelName")) {
                md.levelName = *v;
                md.level = levelFromName(*v);
            }
            if (auto v = plistString(xml, "AppleRAID-SetName")) md.setName = *v;
            if (auto v = plistString(xml, "AppleRAID-UUID")) md.setUuid = *v;
            if (auto v = plistString(xml, "AppleRAID-MemberUUID")) md.memberUuid = *v;
            if (auto v = plistInt(xml, "AppleRAID-ChunkSize")) md.chunkSize = *v;
            if (auto v = plistInt(xml, "AppleRAID-MemberIndex"))
                md.memberIndex = static_cast<int>(*v);
            if (auto v = plistInt(xml, "AppleRAID-MemberCount"))
                md.memberCount = static_cast<int>(*v);
            if (auto v = plistInt(xml, "AppleRAID-SequenceNumber")) md.sequence = *v;
        } else {
            md.notes.push_back("AppleRAID header found but its property list "
                               "could not be read; geometry will be verified by "
                               "reconstruction instead");
        }
        return md;
    }

    // An unlabelled descriptor in the very last sector of each member, seen on
    // hardware-striped enclosures (an OWC Gemini pair carried it). It is not a
    // published format, so only the fields that are unambiguous across the
    // members of a set are read, and even those are treated as a hint: the
    // reconstruction check still has the final say.
    //
    //   0   'As!' 0x09 magic
    //   13  member index within the set
    //   32  total sectors in the assembled set (big-endian, 64-bit)
    //   40  set name, NUL-padded ASCII
    if (size >= 512) {
        auto tail = dev.read(size - 512, 512);
        if (tail.size() >= 512 && std::memcmp(tail.data(), "As!\x09", 4) == 0) {
            md.format = "enclosure RAID descriptor";
            md.memberIndex = tail[13];
            uint64_t sectors = 0;
            for (int i = 0; i < 8; ++i)
                sectors = (sectors << 8) | tail[32 + i];
            // Sanity: the set cannot be smaller than one member or absurdly
            // larger than the members could add up to.
            if (sectors > size / 512 && sectors < (size / 512) * 64)
                md.setSectors = sectors;
            md.setName = fixedString(tail.data() + 40, 24);
            // The remaining bytes plausibly encode the stripe size and member
            // count, but one set is not enough to be sure of them, so they are
            // left to the geometry search - which verifies its answer anyway.
            md.notes.push_back(
                "carries an enclosure RAID descriptor in its last sector"
                + (md.setName.empty() ? std::string()
                                      : " for the set '" + md.setName + "'"));
            return md;
        }
    }

    // SoftRAID (what OWC ships with its enclosures) keeps a proprietary
    // descriptor we do not decode. Note it and let reconstruction decide the
    // geometry - that check does not care who wrote the set.
    auto soft = findSignature(dev, "SoftRAID", 8, 0,
                              std::min<uint64_t>(size, 4ull << 20), 512, 1);
    if (soft.empty() && size > (4ull << 20))
        soft = findSignature(dev, "SoftRAID", 8, size - (4ull << 20), size, 512, 1);
    if (!soft.empty()) {
        md.format = "SoftRAID";
        md.notes.push_back("SoftRAID metadata present; its layout is not "
                           "published, so the geometry below was recovered by "
                           "reconstructing and verifying the volume");
    }
    return md;
}

int scoreAssembled(const std::shared_ptr<ImageSource>& disk, bool deep,
                   std::string* evidence, bool* fsVerified) {
    int score = 0;
    std::string ev;
    bool verified = false;
    if (fsVerified) *fsVerified = false;
    if (!disk || disk->size() < 4096) return 0;

    // Structures near the front of a disk survive almost any wrong guess: the
    // first stripe is the same bytes whatever the stripe size, so a GPT header
    // and a volume header can look perfect on a geometry that is nonsense
    // everywhere else. What actually decides it is *consistency across the
    // whole address space* - the copies at the far end, and whether the sizes
    // the filesystems claim fit the disk we assembled. Those checks subtract,
    // hard, rather than merely failing to add.
    const int CONTRADICTION = 25;

    // --- primary GPT ---
    auto lba1 = disk->read(512, 512);
    bool haveGpt = false;
    if (std::memcmp(lba1.data(), "EFI PART", 8) == 0) {
        score += 2;
        ev += "GPT signature; ";
        if (gptHeaderCrcOk(lba1)) {
            haveGpt = true;
            score += 3;
            ev += "GPT header CRC ok; ";
            uint64_t entryLba = rd64(lba1.data() + 72);
            uint32_t num = rd32(lba1.data() + 80);
            uint32_t esz = rd32(lba1.data() + 84);
            uint32_t acrc = rd32(lba1.data() + 88);
            uint64_t bytes = static_cast<uint64_t>(num) * esz;
            if (bytes && bytes <= (1u << 20)) {
                auto tbl = disk->read(entryLba * 512, static_cast<size_t>(bytes));
                if (crc32of(tbl.data(), tbl.size()) == acrc) {
                    score += 5;
                    ev += "partition table CRC ok; ";
                }
            }
        }
    }

    // --- backup GPT ---
    // A GPT always has a second copy near the end of the disk, and the primary
    // header names the sector it lives in. Checking *that* sector rather than
    // simply the last one matters: a RAID set reserves space at the end of
    // each member for its own metadata, so the logical disk stops short of
    // where the members add up to, and looking only at the final sector would
    // condemn a perfectly good geometry.
    //
    // Either way this is strong evidence, because the backup only lands in the
    // right place if the total size and member ordering are both right.
    if (haveGpt && disk->size() >= 1024) {
        uint64_t altLba = rd64(lba1.data() + 32);
        bool found = false;
        if (altLba && (altLba + 1) * 512 <= disk->size()) {
            auto at = disk->read(altLba * 512, 512);
            found = std::memcmp(at.data(), "EFI PART", 8) == 0 && gptHeaderCrcOk(at);
            if (found) ev += "backup GPT verified where the header says it is; ";
        }
        if (!found) {
            auto tail = disk->read(disk->size() - 512, 512);
            found = std::memcmp(tail.data(), "EFI PART", 8) == 0 && gptHeaderCrcOk(tail);
            if (found) ev += "backup GPT at the end verified; ";
        }
        if (found) {
            score += 8;
        } else {
            score -= CONTRADICTION;
            ev += "NO valid backup GPT (assembled size is wrong); ";
        }
    }

    // --- filesystems ---
    auto parts = scanPartitions(disk);
    bool deepDone = false;
    for (const auto& p : parts) {
        // A partition that runs off the end of the assembled disk means the
        // disk is too small: the members are in the wrong order, or one of
        // them is being counted twice (a stripe read as a mirror).
        if (p.firstByte + p.lengthBytes > disk->size()) {
            score -= CONTRADICTION;
            ev += "a partition extends past the end of the assembled disk; ";
            continue;
        }
        auto vol = p.asSource(disk);
        if (NtfsFilesystem::probe(*vol)) {
            score += 3;
            ev += "NTFS volume; ";
            continue;
        }
        if (HfsFilesystem::probe(*vol)) {
            score += 3;
            ev += "HFS volume; ";
            continue;
        }
        if (HfsPlusFilesystem::probe(*vol)) {
            score += 4;
            ev += "HFS+ volume; ";
            auto fs = HfsPlusFilesystem::open(vol);
            if (!fs) {
                score -= CONTRADICTION;
                ev += "but its volume header does not parse; ";
                continue;
            }
            const auto& st = fs->stats();
            // The volume records its own size. If that does not fit the space
            // it sits in, we have assembled the wrong disk.
            if (st.sizeBytes > p.lengthBytes + (1u << 20)) {
                score -= CONTRADICTION;
                ev += "volume claims to be bigger than the partition holding "
                      "it; ";
                continue;
            }
            // The backup volume header lives at the far end of the volume, so
            // it can only be found if the whole address space maps correctly.
            if (st.alternateHeaderMatches) {
                score += 12;
                ev += "backup volume header at the end matches; ";
            } else {
                score -= CONTRADICTION;
                ev += "backup volume header at the end is missing or "
                      "different; ";
            }
            if (!deep || deepDone) continue;

            // Decisive: walk the catalog and compare what we find against the
            // file and folder counts the volume header records. Catalog nodes
            // are scattered over the whole volume, so a wrong stripe size
            // starts reading garbage nodes almost immediately - and a walk
            // that quietly returns fewer files than the volume says it has is
            // exactly the failure we must never ship as a successful recovery.
            uint64_t files = 0, folders = 0;
            bool complete = true;
            const uint64_t BUDGET = 20000;
            std::function<void(const FsNode&)> walk = [&](const FsNode& dir) {
                if (files + folders > BUDGET) { complete = false; return; }
                auto kids = fs->listDir(dir);
                for (const auto& k : kids) {
                    if (k.isDir) { ++folders; walk(k); }
                    else ++files;
                    if (files + folders > BUDGET) { complete = false; return; }
                }
            };
            walk(fs->root());
            if (files + folders == 0) {
                score -= CONTRADICTION;
                ev += "catalog lists nothing; ";
                continue;
            }
            score += 6;
            ev += "walked " + std::to_string(files) + " files/" +
                  std::to_string(folders) + " folders; ";

            // The decisive test: do the files themselves hold what their names
            // say they hold? Metadata can survive a wrong geometry; a hundred
            // photo headers cannot.
            auto cc = checkFileContents(*fs, fs->root(), 40);
            if (cc.checked >= 4) {
                if (cc.matched * 10 >= cc.checked * 9) {
                    score += 25;
                    verified = true;
                    ev += std::to_string(cc.matched) + "/" +
                          std::to_string(cc.checked) +
                          " sampled files start with the right signature; ";
                } else {
                    score -= CONTRADICTION * 2;
                    ev += "only " + std::to_string(cc.matched) + " of " +
                          std::to_string(cc.checked) +
                          " sampled files contain what their names say - the "
                          "data is interleaved wrong; ";
                }
            } else {
                // Nothing recognisable to check against. Say so rather than
                // pretending the structural checks settled it.
                verified = true;
                ev += "no files of a known type to confirm the data with; ";
            }
            if (complete) {
                // The counts exclude the private folders Mac OS keeps, so
                // allow a small margin rather than demanding equality.
                uint64_t claimed = st.fileCount + st.folderCount;
                uint64_t seen = files + folders;
                uint64_t diff = claimed > seen ? claimed - seen : seen - claimed;
                if (diff <= 4 + claimed / 100) {
                    score += 15;
                    ev += "count matches the volume header; ";
                } else {
                    score -= CONTRADICTION;
                    ev += "volume header says " + std::to_string(claimed) +
                          " objects but the catalog yields " +
                          std::to_string(seen) + "; ";
                }
            }
            deepDone = true;
            continue;
        }
        if (!apfs::Container::probe(*vol)) continue;
        score += 4;
        ev += "APFS container; ";
        if (!deep || deepDone) continue;

        // The decisive test: mount the container and list a real directory.
        // Its metadata blocks are scattered over the whole address space and
        // each carries a Fletcher-64 checksum, so this only succeeds when the
        // stripe size, member order and offsets are all correct.
        auto fs = ApfsFilesystem::open(vol);
        if (!fs) continue;
        score += 4;
        ev += "container superblock verified; ";
        auto vols = fs->listDir(fs->root());
        for (const auto& v : vols) {
            auto kids = fs->listDir(v);
            if (!kids.empty()) {
                score += 10;
                ev += "listed " + std::to_string(kids.size()) + " entries in '" +
                      v.name + "'; ";
                auto cc = checkFileContents(*fs, v, 40);
                if (cc.checked >= 4) {
                    if (cc.matched * 10 >= cc.checked * 9) {
                        score += 25;
                        verified = true;
                        ev += std::to_string(cc.matched) + "/" +
                              std::to_string(cc.checked) +
                              " sampled files start with the right signature; ";
                    } else {
                        score -= CONTRADICTION * 2;
                        ev += "sampled files do not contain what their names "
                              "say - the data is interleaved wrong; ";
                    }
                } else {
                    verified = true;
                }
                deepDone = true;
                break;
            }
        }
    }

    if (evidence) *evidence = ev.empty() ? "nothing recognisable" : ev;
    if (fsVerified) *fsVerified = verified;
    return score;
}

namespace {

// Build a layout from an ordering, level, stripe size and per-member offset.
Layout makeLayout(const std::vector<std::shared_ptr<ImageSource>>& devs,
                  const std::vector<size_t>& order, Level level, uint64_t stripe,
                  uint64_t dataOffset, uint64_t sizeLimitBytes = 0) {
    Layout l;
    l.level = level;
    l.stripeBytes = stripe;
    l.sizeLimitBytes = sizeLimitBytes;
    for (size_t idx : order) {
        Member m;
        m.src = devs[idx];
        m.offset = dataOffset;
        m.label = devs[idx]->name();
        l.members.push_back(std::move(m));
    }
    return l;
}

} // namespace

DetectResult detect(const std::vector<std::shared_ptr<ImageSource>>& devices,
                    const DetectOptions& opt) {
    DetectResult r;
    if (devices.empty()) {
        r.summary = "no devices given";
        return r;
    }

    for (const auto& d : devices) {
        auto md = readMemberMetadata(*d);
        for (const auto& n : md.notes) r.notes.push_back(d->name() + ": " + n);
        if (!md.format.empty()) {
            std::string line = d->name() + ": " + md.format + " member";
            if (!md.levelName.empty()) line += ", level " + md.levelName;
            if (md.chunkSize) line += ", chunk " + std::to_string(md.chunkSize / 1024) + " KiB";
            if (md.memberIndex >= 0)
                line += ", member " + std::to_string(md.memberIndex + 1);
            if (md.memberCount > 0) line += " of " + std::to_string(md.memberCount);
            r.notes.push_back(line);
        }
        r.metadata.push_back(std::move(md));
    }

    // Is any device already a complete disk on its own? If so this may not be
    // a RAID set at all - or it is a mirror, where each member is a full copy.
    for (size_t i = 0; i < devices.size(); ++i) {
        std::string ev;
        if (scoreAssembled(devices[i], true, &ev) >= CONFIDENT_SCORE) {
            r.standalone.push_back(i);
            r.notes.push_back(devices[i]->name() +
                              " is a complete, readable disk on its own (" + ev + ")");
        }
    }

    // Member data may start past a metadata reservation; find the offsets that
    // look like the start of a real disk image.
    auto offsets = dataStartCandidates(*devices[0]);
    for (const auto& md : r.metadata)
        if (md.dataOffset &&
            std::find(offsets.begin(), offsets.end(), md.dataOffset) == offsets.end())
            offsets.push_back(md.dataOffset);

    // Orderings. Metadata member indices, when present, give us the real one;
    // otherwise try permutations (capped so a large set stays bounded).
    std::vector<std::vector<size_t>> orders;
    {
        std::vector<size_t> byIndex(devices.size());
        bool haveIndices = true;
        std::vector<bool> seen(devices.size(), false);
        for (size_t i = 0; i < devices.size(); ++i) {
            int mi = r.metadata[i].memberIndex;
            if (mi < 0 || mi >= static_cast<int>(devices.size()) || seen[mi]) {
                haveIndices = false;
                break;
            }
            seen[mi] = true;
            byIndex[mi] = i;
        }
        if (haveIndices) orders.push_back(byIndex);

        std::vector<size_t> base(devices.size());
        std::iota(base.begin(), base.end(), 0);
        do {
            if (orders.size() >= opt.maxPermutations) break;
            if (std::find(orders.begin(), orders.end(), base) == orders.end())
                orders.push_back(base);
        } while (std::next_permutation(base.begin(), base.end()));
    }

    // Candidate geometries.
    // If a member's own descriptor states the size of the assembled set, honour
    // it: the difference is the space the RAID reserves for its metadata, and
    // getting it right puts the backup GPT exactly where it belongs.
    uint64_t sizeLimit = 0;
    for (const auto& md : r.metadata)
        if (md.setSectors) sizeLimit = md.setSectors * 512;
    if (sizeLimit) {
        uint64_t members = 0;
        for (const auto& d : devices) members += d->size();
        if (members > sizeLimit)
            r.notes.push_back("the set reserves " +
                              std::to_string((members - sizeLimit) / (1024 * 1024)) +
                              " MiB at the end of the drives for its own metadata");
    }

    std::vector<Candidate> cands;
    for (const auto& order : orders) {
        for (uint64_t off : offsets) {
            cands.push_back({makeLayout(devices, order, Level::Concat, 0, off, sizeLimit), 0, "", false});
            for (uint64_t s : opt.stripeSizes)
                cands.push_back({makeLayout(devices, order, Level::Stripe, s, off, sizeLimit), 0, "", false});
            if (devices.size() > 1)
                cands.push_back({makeLayout(devices, order, Level::Mirror, 0, off, sizeLimit), 0, "", false});
            if (order.size() > 1) break; // one ordering's worth of offsets is enough
        }
    }

    // Cheap pass: signatures and CRCs only, to rank the field.
    for (auto& c : cands) {
        auto disk = assemble(c.layout);
        if (!disk) continue;
        c.score = scoreAssembled(disk, false, &c.evidence);
        // A geometry that matches what the metadata claims gets a nudge, so it
        // wins ties - but it still has to prove itself below.
        for (const auto& md : r.metadata) {
            if (md.level && *md.level == c.layout.level) c.score += 1;
            if (md.chunkSize && c.layout.level == Level::Stripe &&
                md.chunkSize == c.layout.stripeBytes)
                c.score += 2;
        }
    }
    std::sort(cands.begin(), cands.end(),
              [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

    // Deep pass on the front-runners: actually mount and list.
    size_t deepN = std::min(opt.deepCandidates, cands.size());
    for (size_t i = 0; i < deepN; ++i) {
        auto disk = assemble(cands[i].layout);
        if (!disk) continue;
        cands[i].score = scoreAssembled(disk, true, &cands[i].evidence,
                                        &cands[i].fsVerified);
    }
    std::sort(cands.begin(), cands.end(),
              [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

    r.ranked.assign(cands.begin(), cands.begin() + std::min<size_t>(cands.size(), 8));
    // Only a geometry whose filesystem we actually read counts as solved. A
    // partition table on its own proves nothing: it sits in the first stripe,
    // which is identical under every stripe size.
    if (!cands.empty() && cands[0].score >= CONFIDENT_SCORE && cands[0].fsVerified) {
        r.assembled = true;
        r.layout = cands[0].layout;
        r.layout.origin = r.metadata.empty() || r.metadata[0].format.empty()
                              ? "recovered by reconstruction"
                              : (r.metadata[0].format + " metadata, verified by "
                                                        "reconstruction");
        r.summary = r.layout.describe() + " - " + cands[0].evidence;
        // If the runner-up scores as well as the winner, the geometry is
        // genuinely ambiguous and the user should see both.
        if (r.ranked.size() > 1 && r.ranked[1].fsVerified &&
            r.ranked[1].score >= cands[0].score)
            r.notes.push_back("another geometry fits equally well (" +
                              r.ranked[1].layout.describe() +
                              "); check the file listing before trusting the export");
    } else {
        r.summary = "could not work out how these drives fit together";
        if (!cands.empty()) {
            r.notes.push_back("best attempt was " + cands[0].layout.describe() +
                              " (" + cands[0].evidence + ")");
            if (cands[0].score >= CONFIDENT_SCORE && !cands[0].fsVerified)
                r.notes.push_back("a partition table was found, but no "
                                  "filesystem on it could be read - and a "
                                  "partition table alone is the same under every "
                                  "stripe size, so it does not confirm anything");
        }
    }
    return r;
}

} // namespace de::raid

// Headless driver for the engine: scan partitions, browse a filesystem tree,
// and export files. Handy for scripting and for verifying the engine without
// the GUI.
#include "core/image_source.h"
#include "core/file_times.h"
#include "partition/partition.h"
#include "fs/filesystem.h"
#include "optane/imsm.h"
#include "optane/span_map.h"
#include "bitlocker/fve.h"
#include "bitlocker/keys.h"
#include "bitlocker/volume.h"
#include "raid/raid.h"
#include "raid/raid_detect.h"
#include "report/tree_report.h"
#include <cstdio>
#include <cstring>
#include <memory>
#include <fstream>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>

using namespace de;

static void usage() {
    std::fprintf(stderr,
        "usage:\n"
        "  de-cli <source>                      list partitions & filesystems\n"
        "  de-cli <source> ls <part#> [recno]   list a directory (default root)\n"
        "  de-cli <source> cat <part#> <recno>  dump a file's data to stdout\n"
        "  de-cli <source> extract <part#> <recno> <out>   write one file\n"
        "  de-cli <source> export <part#> <recno> <outdir> recursively export a\n"
        "                                       folder, preserving dates\n"
        "  de-cli <source> find <part#> <word> [word...]   search every folder and\n"
        "                                       file name; prints full paths\n"
        "  de-cli <source> tree <part#> <out.txt> [out.html] [--dirs-only]\n"
        "                                       write the whole listing to a file\n"
        "                                       (.html gets a search box)\n"
        "  de-cli <optane> imsm [hintSector]    parse Intel IMSM/RST metadata\n"
        "\n"
        "<source> is an image file, a device (/dev/sdc), or a RAID set:\n"
        "  raid:auto:/dev/sdc,/dev/sdd          work the geometry out and verify it\n"
        "  raid:stripe:128k:/dev/sdc,/dev/sdd   RAID 0 with a known stripe size\n"
        "  raid:concat:/dev/sdc,/dev/sdd        spanned / JBOD\n"
        "  raid:mirror:/dev/sdc,/dev/sdd        RAID 1\n"
        "\n"
        "  de-cli raid <dev> <dev> [...]        analyse a set and show the\n"
        "                                       geometries that fit, best first\n");
}

// Split "a,b,c" into its parts.
static std::vector<std::string> splitCommas(const std::string& s) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t comma = s.find(',', start);
        if (comma == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, comma - start));
        start = comma + 1;
    }
    return out;
}

// "128k", "1M", "65536" -> bytes.
static uint64_t parseSize(const std::string& s) {
    char* end = nullptr;
    uint64_t v = std::strtoull(s.c_str(), &end, 10);
    if (end && (*end == 'k' || *end == 'K')) v *= 1024;
    else if (end && (*end == 'm' || *end == 'M')) v *= 1024 * 1024;
    return v;
}

static std::shared_ptr<ImageSource> openRaw(const std::string& path) {
    try {
        return std::make_shared<RawImageSource>(path);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return nullptr;
    }
}

// Turn a source spec into one addressable disk. A plain path opens as-is; a
// "raid:..." spec assembles the members, either from a geometry the user
// states or by working it out and verifying it against the filesystems found.
static std::shared_ptr<ImageSource> openSource(const std::string& spec) {
    if (spec.rfind("raid:", 0) != 0) return openRaw(spec);

    std::string rest = spec.substr(5);
    size_t colon = rest.find(':');
    if (colon == std::string::npos) { usage(); return nullptr; }
    std::string mode = rest.substr(0, colon);
    rest = rest.substr(colon + 1);

    uint64_t stripe = 64 * 1024;
    if (mode == "stripe") {
        size_t c2 = rest.find(':');
        if (c2 == std::string::npos) { usage(); return nullptr; }
        stripe = parseSize(rest.substr(0, c2));
        rest = rest.substr(c2 + 1);
    }

    std::vector<std::shared_ptr<ImageSource>> devs;
    for (const auto& path : splitCommas(rest)) {
        if (path.empty()) continue;
        auto d = openRaw(path);
        if (!d) return nullptr;
        devs.push_back(std::move(d));
    }
    if (devs.empty()) { usage(); return nullptr; }

    if (mode == "auto") {
        std::fprintf(stderr, "working out the RAID geometry (this reads a little "
                             "from each drive)...\n");
        auto r = de::raid::detect(devs);
        for (const auto& n : r.notes) std::fprintf(stderr, "  %s\n", n.c_str());
        if (!r.assembled) {
            std::fprintf(stderr, "could not reassemble these drives: %s\n",
                         r.summary.c_str());
            std::fprintf(stderr, "you can still force a geometry, e.g. "
                                 "raid:stripe:128k:<dev>,<dev>\n");
            return nullptr;
        }
        std::fprintf(stderr, "using %s\n", r.summary.c_str());
        return de::raid::assemble(r.layout);
    }

    de::raid::Layout layout;
    layout.stripeBytes = stripe;
    layout.origin = "specified on the command line";
    if (mode == "stripe") layout.level = de::raid::Level::Stripe;
    else if (mode == "concat") layout.level = de::raid::Level::Concat;
    else if (mode == "mirror") layout.level = de::raid::Level::Mirror;
    else { usage(); return nullptr; }
    for (auto& d : devs) {
        de::raid::Member m;
        m.label = d->name();
        m.src = std::move(d);
        layout.members.push_back(std::move(m));
    }
    auto disk = de::raid::assemble(layout);
    if (!disk) {
        std::fprintf(stderr, "that geometry is not usable (check the stripe size)\n");
        return nullptr;
    }
    // Say whether the forced geometry actually holds up, rather than letting a
    // wrong stripe size quietly produce shredded files.
    std::string ev;
    bool fsVerified = false;
    int score = de::raid::scoreAssembled(disk, true, &ev, &fsVerified);
    std::fprintf(stderr, "%s\n  verification: %s\n", layout.describe().c_str(),
                 ev.c_str());
    if (score < 12 || !fsVerified)
        std::fprintf(stderr, "  WARNING: this geometry does not verify - the "
                             "filesystems on it do not parse. Anything you "
                             "export may be corrupt.\n");
    return disk;
}

// Resolve a partition and mount its filesystem, or return nullptr with a message.
static std::unique_ptr<Filesystem> mount(const std::shared_ptr<ImageSource>& img,
                                         int partNo, std::shared_ptr<ImageSource>& volOut) {
    auto parts = scanPartitions(img);
    if (partNo < 1 || partNo > static_cast<int>(parts.size())) {
        std::fprintf(stderr, "no such partition %d (found %zu)\n", partNo, parts.size());
        return nullptr;
    }
    volOut = parts[partNo - 1].asSource(img);
    auto fs = detectFilesystem(volOut);
    if (!fs) std::fprintf(stderr, "unrecognised filesystem on partition %d\n", partNo);
    return fs;
}

// Build the reconstructed disk from a QLC+Optane pair. If the Optane image has
// no decodable linear span, say why and carry on with the QLC alone rather than
// refusing to run: on many modules the QLC is already current for everything
// except recently written blocks, so a possibly-stale volume we can browse
// beats no volume at all.
static std::shared_ptr<ImageSource> reconstruct(std::shared_ptr<ImageSource> qlc,
                                                std::shared_ptr<ImageSource> opt,
                                                uint64_t hint) {
    std::string why;
    if (auto merged = de::optane::makeSpanMerge(qlc, opt, hint, &why))
        return merged;
    std::fprintf(stderr,
                 "warning: Optane reconstruction unavailable (%s)\n"
                 "         continuing on the QLC alone - blocks written shortly\n"
                 "         before the failure may be stale or missing\n",
                 why.c_str());
    return qlc;
}

// Recursively export a subtree, preserving dates and resource forks. This is
// the workflow that matters when the destination is smaller than the source:
// pick one folder, take only that.
static int exportTree(Filesystem& fs, const FsNode& start, const std::string& outRoot) {
    uint64_t files = 0, bytes = 0, failed = 0;
    std::function<void(const FsNode&, const std::string&)> rec =
        [&](const FsNode& dir, const std::string& path) {
            std::error_code ec;
            std::filesystem::create_directories(path, ec);
            for (auto& c : fs.listDir(dir)) {
                std::string safe = c.name;
                for (auto& ch : safe)
                    if (ch == '/' || ch == '\\' || static_cast<unsigned char>(ch) < 0x20)
                        ch = '_';
                if (safe.empty() || safe == "." || safe == "..") safe = "unnamed";
                std::string cp = path + "/" + safe;
                if (c.isDir) {
                    rec(c, cp);
                    // After its contents, which would otherwise bump its mtime.
                    de::applyFileTimes(cp, fs.fileTimes(c));
                    continue;
                }
                std::ofstream os(cp, std::ios::binary);
                if (!os) { ++failed; continue; }
                uint64_t before = bytes;
                bool ok = fs.readFileStream(c, [&](const uint8_t* d, size_t n) {
                    os.write(reinterpret_cast<const char*>(d),
                             static_cast<std::streamsize>(n));
                    bytes += n;
                    return static_cast<bool>(os);
                });
                os.close();
                if (!ok) {
                    ++failed;
                    std::fprintf(stderr, "  could not fully read: %s\n", cp.c_str());
                }
                ++files;
                de::FsTimes t = fs.fileTimes(c);
                if (auto rsrc = fs.readResourceFork(c); !rsrc.empty()) {
                    std::ofstream rs(cp + ".rsrc", std::ios::binary);
                    rs.write(reinterpret_cast<const char*>(rsrc.data()),
                             static_cast<std::streamsize>(rsrc.size()));
                    bytes += rsrc.size();
                    rs.close();
                    de::applyFileTimes(cp + ".rsrc", t);
                }
                de::applyFileTimes(cp, t);
                if (files % 200 == 0)
                    std::fprintf(stderr, "\r  %llu files, %.2f GB...",
                                 (unsigned long long)files, bytes / 1e9);
                (void)before;
            }
        };
    rec(start, outRoot);
    std::fprintf(stderr, "\rexported %llu files, %.2f GB to %s\n",
                 (unsigned long long)files, bytes / 1e9, outRoot.c_str());
    if (failed)
        std::fprintf(stderr, "%llu file(s) could not be read in full\n",
                     (unsigned long long)failed);
    return failed ? 1 : 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }

    // Analyse a set of drives and report the geometries that fit.
    // `de-cli raid <dev> <dev> [...]`
    if (std::string(argv[1]) == "raid") {
        if (argc < 4) { usage(); return 2; }
        std::vector<std::shared_ptr<ImageSource>> devs;
        for (int i = 2; i < argc; ++i) {
            auto d = openRaw(argv[i]);
            if (!d) return 1;
            std::printf("member: %s (%.2f TB)\n", argv[i], d->size() / 1e12);
            devs.push_back(std::move(d));
        }
        auto r = de::raid::detect(devs);
        std::printf("\n");
        for (const auto& n : r.notes) std::printf("note: %s\n", n.c_str());
        if (!r.standalone.empty()) {
            std::printf("\n%zu of these drives read as complete disks on their "
                        "own - if that is unexpected, they may not belong to a "
                        "set at all.\n", r.standalone.size());
        }
        std::printf("\ngeometries tried, best first:\n");
        for (const auto& c : r.ranked)
            std::printf("  [%3d] %-58s %s\n", c.score, c.layout.describe().c_str(),
                        c.evidence.c_str());
        std::printf("\n");
        if (r.assembled) {
            std::printf("RESULT: %s\n", r.summary.c_str());
            std::string spec = "raid:";
            switch (r.layout.level) {
                case de::raid::Level::Stripe:
                    spec += "stripe:" + std::to_string(r.layout.stripeBytes / 1024) + "k:";
                    break;
                case de::raid::Level::Concat: spec += "concat:"; break;
                case de::raid::Level::Mirror: spec += "mirror:"; break;
            }
            for (size_t i = 0; i < r.layout.members.size(); ++i)
                spec += (i ? "," : "") + r.layout.members[i].label;
            std::printf("\nuse it with:\n  de-cli '%s'\n", spec.c_str());
            // Show what is actually on the assembled disk.
            auto disk = de::raid::assemble(r.layout);
            std::printf("\npartitions on the assembled disk:\n");
            for (auto& p : scanPartitions(disk)) {
                auto vol = p.asSource(disk);
                std::printf("  [%d] %-8s @ sector %llu, %.2f GB  type=%s  fs=%s\n",
                            p.index, p.scheme.c_str(),
                            (unsigned long long)(p.firstByte / 512),
                            p.lengthBytes / 1e9, p.typeName.c_str(),
                            detectFilesystemName(*vol).c_str());
            }
            return 0;
        }
        std::printf("RESULT: %s\n", r.summary.c_str());
        return 1;
    }

    // Dump BitLocker FVE metadata from the reconstructed BitLocker partition.
    // `de-cli bde <qlc> <optane> [cacheHintSector]`
    if (std::string(argv[1]) == "bde") {
        if (argc < 4) { usage(); return 2; }
        std::shared_ptr<ImageSource> qlc, opt;
        try {
            qlc = std::make_shared<RawImageSource>(argv[2]);
            opt = std::make_shared<RawImageSource>(argv[3]);
        } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
        uint64_t hint = argc >= 5 ? std::strtoull(argv[4], nullptr, 10) * 512ull : UINT64_MAX;
        auto merged = reconstruct(qlc, opt, hint);
        for (auto& p : scanPartitions(merged)) {
            auto vol = p.asSource(merged);
            auto md = de::bitlocker::parseFve(*vol);
            if (!md) continue;
            std::printf("BitLocker volume on partition %d (sector %llu)\n",
                        p.index, (unsigned long long)(p.firstByte / 512));
            std::printf("  encryption: %s\n", de::bitlocker::methodName(md->method));
            std::printf("  description: %s\n", md->description.c_str());
            std::printf("  key protectors (%zu):\n", md->vmks.size());
            for (auto& v : md->vmks)
                std::printf("    - %-20s  salt:%s  wrappedVMK:%s\n",
                            v.protectionType.c_str(), v.hasSalt ? "yes" : "no",
                            v.encryptedVmk ? "yes" : "no");
            std::printf("  FVEK present: %s\n", md->encryptedFvek ? "yes" : "no");
            return 0;
        }
        std::fprintf(stderr, "no BitLocker partition found\n");
        return 1;
    }

    // Unlock the reconstructed BitLocker volume with a recovery password and
    // decrypt a test sector.
    // `de-cli unlock <qlc> <optane> <cacheHintSector> <recovery-key> [testByteOffset]`
    if (std::string(argv[1]) == "unlock") {
        if (argc < 6) { usage(); return 2; }
        std::shared_ptr<ImageSource> qlc, opt;
        try {
            qlc = std::make_shared<RawImageSource>(argv[2]);
            opt = std::make_shared<RawImageSource>(argv[3]);
        } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
        uint64_t hint = std::strtoull(argv[4], nullptr, 10) * 512ull;
        std::string recovery = argv[5];
        auto merged = reconstruct(qlc, opt, hint);

        for (auto& p : scanPartitions(merged)) {
            auto vol = p.asSource(merged);
            auto md = de::bitlocker::parseFve(*vol);
            if (!md) continue;
            std::printf("BitLocker volume @ sector %llu - %s\n",
                        (unsigned long long)(p.firstByte / 512),
                        de::bitlocker::methodName(md->method));
            auto keys = de::bitlocker::unlockWithRecovery(*md, recovery);
            if (!keys) { std::fprintf(stderr, "UNLOCK FAILED (wrong key or no recovery protector)\n"); return 1; }
            std::printf("UNLOCK OK - VMK and FVEK recovered (MACs verified), FVEK %zu bytes\n",
                        keys->fvek.size());

            // Decrypt a test sector and show it. Default: 64 MiB into the volume
            // (normal encrypted data, past the header/metadata regions).
            uint64_t testOff = argc >= 7 ? std::strtoull(argv[6], nullptr, 10) : (64ull << 20);
            testOff &= ~511ull;
            auto enc = vol->read(testOff, 512);
            uint8_t sec[512];
            std::memcpy(sec, enc.data(), 512);
            de::bitlocker::decryptSector(*keys, testOff / 512, sec);
            std::printf("decrypted volume offset %llu - ASCII preview:\n  ",
                        (unsigned long long)testOff);
            for (int i = 0; i < 96; ++i)
                std::putchar((sec[i] >= 0x20 && sec[i] < 0x7F) ? sec[i] : '.');
            std::printf("\n");
            return 0;
        }
        std::fprintf(stderr, "no BitLocker partition found\n");
        return 1;
    }

    // Full pipeline: reconstruct + unlock + browse the decrypted volume.
    // `de-cli browse <qlc> <optane> <cacheHintSector> <recovery-key>`
    if (std::string(argv[1]) == "browse") {
        if (argc < 6) { usage(); return 2; }
        std::shared_ptr<ImageSource> qlc, opt;
        try {
            qlc = std::make_shared<RawImageSource>(argv[2]);
            opt = std::make_shared<RawImageSource>(argv[3]);
        } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
        uint64_t hint = std::strtoull(argv[4], nullptr, 10) * 512ull;
        auto merged = reconstruct(qlc, opt, hint);
        for (auto& p : scanPartitions(merged)) {
            auto vol = p.asSource(merged);
            std::string note;
            vol = de::bitlocker::reconcileVolumeSize(merged, p.firstByte, vol, &note);
            if (!note.empty())
                std::fprintf(stderr, "partition %d: %s\n", p.index, note.c_str());
            auto dec = de::bitlocker::unlockVolume(vol, argv[5]);
            if (!dec) continue;
            auto fs = detectFilesystem(dec);
            if (!fs) { std::fprintf(stderr, "decrypted, but no filesystem recognised\n"); return 1; }
            // Optional: `... browse <qlc> <optane> <hint> <key> ls <recno>`
            if (argc >= 8 && std::string(argv[6]) == "ls") {
                de::FsNode d; d.id = std::strtoull(argv[7], nullptr, 10); d.isDir = true;
                auto kids = fs->listDir(d);
                std::printf("directory record %llu: %zu entries\n",
                            (unsigned long long)d.id, kids.size());
                for (auto& c : kids)
                    std::printf("  %-8llu %s %14llu  %s\n",
                                (unsigned long long)c.id, c.isDir ? "<DIR>" : "     ",
                                (unsigned long long)c.size, c.name.c_str());
                return 0;
            }
            // Optional: `... browse <qlc> <optane> <hint> <key> cat <recno>`
            if (argc >= 8 && std::string(argv[6]) == "cat") {
                de::FsNode f; f.id = std::strtoull(argv[7], nullptr, 10);
                fs->readFileStream(f, [](const uint8_t* d, size_t n) {
                    std::fwrite(d, 1, n, stdout); return true;
                });
                return 0;
            }
            // Recursive folder export (mirrors the GUI's checkbox export):
            // `... browse <qlc> <optane> <hint> <key> extract <recno> <outDir>`
            if (argc >= 9 && std::string(argv[6]) == "extract") {
                uint64_t rootId = std::strtoull(argv[7], nullptr, 10);
                std::string outRoot = argv[8];
                int files = 0; uint64_t bytes = 0;
                std::function<void(uint64_t, const std::string&)> rec =
                    [&](uint64_t dirId, const std::string& path) {
                        std::filesystem::create_directories(path);
                        de::FsNode d; d.id = dirId; d.isDir = true;
                        for (auto& c : fs->listDir(d)) {
                            std::string safe = c.name;
                            for (auto& ch : safe) if (ch == '/') ch = '_';
                            std::string cp = path + "/" + safe;
                            if (c.isDir) {
                                rec(c.id, cp);
                                // After its contents, which bump its mtime.
                                de::applyFileTimes(cp, fs->fileTimes(c));
                            }
                            else {
                                std::ofstream os(cp, std::ios::binary);
                                fs->readFileStream(c, [&](const uint8_t* d, size_t n) {
                                    os.write(reinterpret_cast<const char*>(d),
                                             static_cast<std::streamsize>(n));
                                    bytes += n; return static_cast<bool>(os);
                                });
                                ++files;
                                os.close();
                                de::FsTimes t = fs->fileTimes(c);
                                if (auto rsrc = fs->readResourceFork(c); !rsrc.empty()) {
                                    std::ofstream rs(cp + ".rsrc", std::ios::binary);
                                    rs.write(reinterpret_cast<const char*>(rsrc.data()),
                                             static_cast<std::streamsize>(rsrc.size()));
                                    bytes += rsrc.size();
                                    rs.close();
                                    de::applyFileTimes(cp + ".rsrc", t);
                                }
                                // Restore the source dates, so a scripted export
                                // uploads with the same timeline as the GUI's.
                                de::applyFileTimes(cp, t);
                            }
                        }
                    };
                rec(rootId, outRoot);
                std::fprintf(stderr, "extracted %d files, %llu bytes to %s\n",
                             files, (unsigned long long)bytes, outRoot.c_str());
                return 0;
            }
            std::printf("Reconstructed + decrypted %s volume - root listing:\n",
                        fs->typeName().c_str());
            for (auto& c : fs->listDir(fs->root()))
                std::printf("  %-8llu %s %14llu  %s\n",
                            (unsigned long long)c.id, c.isDir ? "<DIR>" : "     ",
                            (unsigned long long)c.size, c.name.c_str());
            return 0;
        }
        std::fprintf(stderr, "no BitLocker partition found / wrong key\n");
        return 1;
    }

    // Optane reconstruction: merge a QLC + Optane image into one virtual disk,
    // then scan it. `de-cli merge <qlc> <optane> [cacheHintSector]`.
    if (std::string(argv[1]) == "merge") {
        if (argc < 4) { usage(); return 2; }
        std::shared_ptr<ImageSource> qlc, opt;
        try {
            qlc = std::make_shared<RawImageSource>(argv[2]);
            opt = std::make_shared<RawImageSource>(argv[3]);
        } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
        uint64_t hint = UINT64_MAX;
        if (argc >= 5) hint = std::strtoull(argv[4], nullptr, 10) * 512ull;
        auto merged = reconstruct(qlc, opt, hint);
        std::printf("Reconstructed disk: %.2f GB (QLC %.2f GB + Optane span)\n",
                    merged->size() / 1e9, qlc->size() / 1e9);
        for (auto& p : scanPartitions(merged)) {
            auto vol = p.asSource(merged);
            std::printf("  [%d] %-8s @ sector %llu, %.2f GB  type=%s  fs=%s\n",
                        p.index, p.scheme.c_str(),
                        (unsigned long long)(p.firstByte / 512), p.lengthBytes / 1e9,
                        p.typeName.c_str(), detectFilesystemName(*vol).c_str());
        }
        return 0;
    }

    std::shared_ptr<ImageSource> img = openSource(argv[1]);
    if (!img) return 1;

    if (argc == 2) {
        auto parts = scanPartitions(img);
        std::printf("Image: %s (%.2f MiB)\n", img->name().c_str(),
                    img->size() / 1048576.0);
        for (auto& p : parts) {
            auto vol = p.asSource(img);
            std::printf("  [%d] %-8s @ %llu, %.2f MiB  type=%s  fs=%s\n",
                        p.index, p.scheme.c_str(),
                        (unsigned long long)p.firstByte, p.lengthBytes / 1048576.0,
                        p.typeName.c_str(), detectFilesystemName(*vol).c_str());
        }
        return 0;
    }

    std::string cmd = argv[2];
    std::shared_ptr<ImageSource> vol;

    if (cmd == "imsm") {
        uint64_t hint = UINT64_MAX;
        if (argc >= 4) hint = std::strtoull(argv[3], nullptr, 10) * 512ull;
        auto md = de::optane::parseImsm(*img, hint);
        if (!md) { std::fprintf(stderr, "no IMSM metadata found\n"); return 1; }
        std::printf("Intel IMSM metadata @ cache region byte %llu\n",
                    (unsigned long long)md->cacheRegionOffset);
        std::printf("  family=0x%08x generation=%u  disks=%u volumes=%u\n",
                    md->familyNum, md->generationNum, md->numDisks, md->numRaidDevs);
        for (auto& d : md->disks)
            std::printf("  disk   '%s'  %llu sectors (%.2f GB)  status=0x%08x\n",
                        d.serial.c_str(), (unsigned long long)d.totalBlocks,
                        d.totalBlocks * 512 / 1e9, d.status);
        for (auto& v : md->volumes)
            std::printf("  volume '%s'  %llu sectors (%.2f GB)\n",
                        v.name.c_str(), (unsigned long long)v.sizeBlocks,
                        v.sizeBlocks * 512 / 1e9);
        return 0;
    }

    if (cmd == "ls") {
        if (argc < 4) { usage(); return 2; }
        auto fs = mount(img, std::atoi(argv[3]), vol);
        if (!fs) return 1;
        FsNode dir = fs->root();
        if (argc >= 5) { dir.id = std::strtoull(argv[4], nullptr, 10); dir.isDir = true; }
        for (auto& c : fs->listDir(dir)) {
            std::printf("  %-8llu %s %12llu  %s\n",
                        (unsigned long long)c.id, c.isDir ? "<DIR>" : "     ",
                        (unsigned long long)c.size, c.name.c_str());
        }
        return 0;
    }

    if (cmd == "export") {
        if (argc < 6) { usage(); return 2; }
        auto fs = mount(img, std::atoi(argv[3]), vol);
        if (!fs) return 1;
        FsNode start = fs->root();
        uint64_t id = std::strtoull(argv[4], nullptr, 10);
        if (id != start.id) { start.id = id; start.isDir = true; start.name.clear(); }
        return exportTree(*fs, start, argv[5]);
    }

    if (cmd == "find") {
        if (argc < 5) { usage(); return 2; }
        auto fs = mount(img, std::atoi(argv[3]), vol);
        if (!fs) return 1;
        std::vector<std::string> needles;
        for (int i = 4; i < argc; ++i) needles.push_back(argv[i]);

        de::report::Options opt;
        opt.progress = [](uint64_t f, uint64_t d) {
            std::fprintf(stderr, "\r  searching... %llu files, %llu folders",
                         (unsigned long long)f, (unsigned long long)d);
        };
        uint64_t hits = 0;
        auto stats = de::report::findNames(
            *fs, fs->root(), needles,
            [&](const std::string& path, const FsNode& n) {
                ++hits;
                // Print as we go: on a big volume the first answers are useful
                // long before the walk finishes.
                std::printf("%-9s %14llu  %s\n", n.isDir ? "<DIR>" : "",
                            (unsigned long long)n.size, path.c_str());
                std::fflush(stdout);
            },
            opt);
        std::fprintf(stderr, "\r%llu match(es) among %llu files and %llu folders\n",
                     (unsigned long long)hits, (unsigned long long)stats.files,
                     (unsigned long long)stats.dirs);
        return hits ? 0 : 1;
    }

    if (cmd == "tree") {
        if (argc < 5) { usage(); return 2; }
        auto fs = mount(img, std::atoi(argv[3]), vol);
        if (!fs) return 1;
        std::vector<std::string> outputs;
        de::report::Options opt;
        for (int i = 4; i < argc; ++i) {
            if (std::string(argv[i]) == "--dirs-only") opt.includeFiles = false;
            else outputs.push_back(argv[i]);
        }
        if (outputs.empty()) { usage(); return 2; }
        opt.progress = [](uint64_t f, uint64_t d) {
            std::fprintf(stderr, "\r  listing... %llu files, %llu folders",
                         (unsigned long long)f, (unsigned long long)d);
        };
        // Walking a 32 TB volume takes minutes, so do it once and write every
        // requested format from the one pass.
        de::report::Stats stats;
        auto entries = de::report::collectTree(*fs, fs->root(), stats, opt);
        std::fprintf(stderr, "\r  listed %llu files, %llu folders; writing...\n",
                     (unsigned long long)stats.files, (unsigned long long)stats.dirs);
        for (const auto& outPath : outputs) {
            std::ofstream os(outPath, std::ios::binary);
            if (!os) {
                std::fprintf(stderr, "cannot write %s\n", outPath.c_str());
                return 1;
            }
            bool html = outPath.size() > 5 &&
                        outPath.compare(outPath.size() - 5, 5, ".html") == 0;
            if (html) de::report::writeHtmlTree(entries, os, img->name());
            else de::report::writeTextTree(entries, os);
            os.close();
            std::fprintf(stderr, "wrote %s\n", outPath.c_str());
        }
        std::fprintf(stderr, "%llu files, %llu folders, %.2f GB of data\n",
                     (unsigned long long)stats.files,
                     (unsigned long long)stats.dirs, stats.bytes / 1e9);
        return 0;
    }

    if (cmd == "cat" || cmd == "extract") {
        if (argc < 5) { usage(); return 2; }
        auto fs = mount(img, std::atoi(argv[3]), vol);
        if (!fs) return 1;
        FsNode f;
        f.id = std::strtoull(argv[4], nullptr, 10);
        auto data = fs->readFile(f);
        if (cmd == "cat") {
            std::fwrite(data.data(), 1, data.size(), stdout);
        } else {
            if (argc < 6) { usage(); return 2; }
            std::ofstream out(argv[5], std::ios::binary);
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
            std::fprintf(stderr, "wrote %zu bytes to %s\n", data.size(), argv[5]);
            if (auto rsrc = fs->readResourceFork(f); !rsrc.empty()) {
                std::string rsrcPath = std::string(argv[5]) + ".rsrc";
                std::ofstream rs(rsrcPath, std::ios::binary);
                rs.write(reinterpret_cast<const char*>(rsrc.data()),
                         static_cast<std::streamsize>(rsrc.size()));
                std::fprintf(stderr, "wrote %zu bytes to %s\n", rsrc.size(), rsrcPath.c_str());
                rs.close();
                de::applyFileTimes(rsrcPath, fs->fileTimes(f));
            }
            out.close();
            de::applyFileTimes(argv[5], fs->fileTimes(f));
        }
        return 0;
    }

    usage();
    return 2;
}

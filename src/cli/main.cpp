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
        "  de-cli <image>                       list partitions & filesystems\n"
        "  de-cli <image> ls <part#> [recno]    list a directory (default root)\n"
        "  de-cli <image> cat <part#> <recno>   dump a file's data to stdout\n"
        "  de-cli <image> extract <part#> <recno> <out>  write a file to disk\n"
        "  de-cli <optane> imsm [hintSector]   parse Intel IMSM/RST metadata\n");
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

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }

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

    std::shared_ptr<ImageSource> img;
    try {
        img = std::make_shared<RawImageSource>(argv[1]);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }

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

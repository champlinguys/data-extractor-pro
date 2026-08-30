#pragma once
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "core/image_source.h"

namespace de::raid {

// How a set of member disks combines into one logical disk.
enum class Level {
    Concat, // JBOD / "spanned": member 2 continues where member 1 ends
    Stripe, // RAID 0: fixed-size stripes alternating across the members
    Mirror, // RAID 1: every member holds the same data
};

const char* levelName(Level l);

// A stripe size as people write it: "512 B", "32 KiB", "1 MiB". Plain division
// by 1024 turns the sub-kilobyte stripes some hardware bridges use into a
// meaningless "0 KiB", which is exactly when the number matters most.
std::string stripeSizeName(uint64_t bytes);

// One member of the set. `offset` skips any metadata the RAID implementation
// keeps at the front of the disk; `length` bounds the data area (0 = to the
// end of the device).
struct Member {
    std::shared_ptr<ImageSource> src;
    uint64_t offset = 0;
    uint64_t length = 0;
    std::string label;

    uint64_t dataLength() const {
        uint64_t avail = src ? src->size() : 0;
        if (offset >= avail) return 0;
        uint64_t rest = avail - offset;
        return length && length < rest ? length : rest;
    }
};

// A complete description of the set: enough to rebuild the logical disk, and
// enough to show the user exactly what we assumed.
struct Layout {
    Level level = Level::Concat;
    uint64_t stripeBytes = 64 * 1024; // Stripe only
    std::vector<Member> members;      // in RAID order
    std::string origin;               // where the geometry came from
    // The true size of the logical disk, when something authoritative says so
    // (a member descriptor, or the user). RAID implementations keep a reserve
    // at the end of each member, so the logical disk is smaller than the
    // members add up to. 0 = use everything the members offer.
    uint64_t sizeLimitBytes = 0;

    // Size of the assembled logical disk, after any size limit is applied.
    uint64_t logicalSize() const;
    // What the members alone would give, ignoring sizeLimitBytes.
    uint64_t rawLogicalSize() const;
    // One-line summary for the UI/CLI, e.g. "RAID 0, 2 members, 128 KiB stripe".
    std::string describe() const;
};

// The assembled disk. Everything above it - the partition scanner, APFS, NTFS,
// the export path - sees an ordinary ImageSource and never learns there were
// two drives.
class RaidSource : public ImageSource {
public:
    explicit RaidSource(Layout layout);

    uint64_t size() const override { return size_; }
    size_t readAt(uint64_t off, void* buf, size_t len) override;
    std::string name() const override { return name_; }

    const Layout& layout() const { return layout_; }
    // Members that returned short/failed reads while we were reading. On a
    // mirror these are recovered from the other member; elsewhere they are
    // holes, and the user should know which drive is the sick one.
    std::vector<std::string> readErrors() const;

private:
    // Read at most one contiguous run from a single member.
    size_t readRun(uint64_t off, uint8_t* out, size_t len);

    Layout layout_;
    uint64_t size_ = 0;
    std::string name_;
    // Per-member failed-byte counters. Reads run concurrently (preview thread
    // plus export worker), but the counters are only touched on the rare error
    // path, so a plain mutex costs nothing in the common case.
    mutable std::mutex errMutex_;
    std::vector<uint64_t> memberErrors_;
};

// Build the logical disk. Returns nullptr if the layout is unusable (no
// members, or a stripe size that is not a positive power of two).
std::shared_ptr<ImageSource> assemble(const Layout& layout);

} // namespace de::raid

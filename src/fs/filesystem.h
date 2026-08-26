#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include "core/image_source.h"

namespace de {

// Object timestamps, normalised to nanoseconds since the Unix epoch so the
// export path never has to know which filesystem they came from. 0 means
// "unknown" - the exporter leaves the corresponding attribute alone rather
// than stamping 1970 onto the file.
struct FsTimes {
    int64_t mtime = 0;   // last data modification
    int64_t crtime = 0;  // creation / birth
    int64_t atime = 0;   // last access

    bool any() const { return mtime || crtime || atime; }
};

// One entry in a filesystem tree. `id` is the filesystem-native identifier
// (for NTFS, the MFT record number) that the parser uses to re-locate the
// object on demand, so the GUI can browse lazily without holding the whole
// tree in memory.
struct FsNode {
    uint64_t id = 0;
    std::string name;
    bool isDir = false;
    bool isDeleted = false;   // recovered from an unallocated record
    uint64_t size = 0;
    FsTimes times;            // cheap timestamps captured while listing

    // Kept for convenience: the modification time, in Unix nanoseconds.
    int64_t mtime() const { return times.mtime; }

    bool operator==(const FsNode& o) const { return id == o.id && name == o.name; }
};

// Abstract filesystem. NTFS is the first implementation; HFS+ and ext4 will
// implement the same three-method surface (root / list / read) so the GUI and
// the export path are filesystem-agnostic.
class Filesystem {
public:
    virtual ~Filesystem() = default;

    virtual std::string typeName() const = 0;
    virtual FsNode root() = 0;
    virtual std::vector<FsNode> listDir(const FsNode& dir) = 0;

    // Read the (default/unnamed) data stream of a file fully into memory.
    // Convenient for small files/previews; use readFileStream for large ones.
    virtual std::vector<uint8_t> readFile(const FsNode& file) = 0;

    // Sink for streamed data: called with successive chunks; return false to
    // abort (e.g. on write error or user cancel).
    using DataSink = std::function<bool(const uint8_t* data, size_t len)>;

    // Stream the file's default data stream to `sink` in bounded-memory chunks.
    // Returns false if the sink aborted. The default buffers the whole file via
    // readFile; NTFS overrides it to read extent-by-extent without loading the
    // whole file - essential for multi-GB files like hiberfil.sys.
    virtual bool readFileStream(const FsNode& file, const DataSink& sink) {
        auto data = readFile(file);
        return sink(data.data(), data.size());
    }

    // Read up to `maxBytes` from the start of a file. Streams and stops as soon
    // as it has enough, so it stays cheap on multi-gigabyte files. Used for
    // previews and, importantly, by the RAID prober: checking that files
    // actually begin with the signature their name implies is what proves a
    // reassembled disk is really the original one.
    std::vector<uint8_t> readHead(const FsNode& file, size_t maxBytes) {
        std::vector<uint8_t> out;
        out.reserve(maxBytes);
        readFileStream(file, [&](const uint8_t* d, size_t n) {
            size_t take = std::min(n, maxBytes - out.size());
            out.insert(out.end(), d, d + take);
            return out.size() < maxBytes; // false stops the stream
        });
        return out;
    }

    // Resource fork of a file, or empty if none/not applicable. Default is
    // empty so existing filesystems (NTFS) need no changes; HFS overrides it.
    virtual std::vector<uint8_t> readResourceFork(const FsNode& /*file*/) { return {}; }

    // Authoritative timestamps for a node, used by the export path so restored
    // files carry the dates they had on the original volume. The default hands
    // back what listDir already captured; NTFS overrides it to read
    // $STANDARD_INFORMATION, which is what Explorer and timeline tools show
    // (the $FILE_NAME copy in the directory index goes stale after a rename).
    // May cost an extra read per file, so callers should use it per exported
    // object, not per browsed row.
    virtual FsTimes fileTimes(const FsNode& node) { return node.times; }

    // A stable identity for a *directory's contents*, used by recursive walkers
    // to break cycles. Two FsNodes that would list the same children must give
    // the same value here, and unrelated directories must not collide.
    //
    // `id` alone is not good enough everywhere. On NTFS, HFS, HFS+ and APFS it
    // is a real object number (MFT record, CNID, inode), so a directory that
    // points back at one of its own ancestors comes back with a number the
    // walker has already seen. On FAT and exFAT `id` is the byte offset of the
    // *directory entry*, and a damaged volume can hold any number of distinct
    // entries whose first cluster is the same directory - which is precisely
    // what an on-disk cycle looks like there. Those two override this to
    // return the first cluster instead.
    //
    // Returns 0 when there is no usable identity (an empty directory with no
    // cluster allocated, a record that no longer parses). Callers must treat 0
    // as "unknown" and fall back to their depth limit rather than assuming two
    // unknowns are the same directory.
    virtual uint64_t dirIdentity(const FsNode& dir) { return dir.id; }
};

// Upper bound on directory nesting for any recursive walk. Real filesystems do
// not come close - Windows capped whole *paths* at 260 characters for decades -
// so anything past this is a corrupt volume, not deep nesting. It is the
// backstop for what dirIdentity() cannot see: a cycle whose directories
// genuinely differ each time around, and any filesystem that returns 0.
inline constexpr int kMaxWalkDepth = 128;

// Sniff the volume and return a mounted Filesystem, or nullptr if unrecognised.
std::unique_ptr<Filesystem> detectFilesystem(std::shared_ptr<ImageSource> vol);

// Just the type label, for showing in the tree before the user opens a volume.
std::string detectFilesystemName(ImageSource& vol);

} // namespace de

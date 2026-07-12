#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <vector>

namespace de {

// Abstract random-access byte source. This is the single seam the whole tool is
// built on: a raw disk image, a partition slice, and (later) the merged
// Optane+QLC view are all just ImageSources, so the partition scanner and the
// filesystem parsers never care where the bytes physically come from.
class ImageSource {
public:
    virtual ~ImageSource() = default;

    // Total addressable size in bytes.
    virtual uint64_t size() const = 0;

    // Read up to `len` bytes at absolute byte offset `off` into `buf`.
    // Returns the number of bytes actually read (0 past EOF). Never throws for
    // a short read; callers that need exact reads use readExact().
    virtual size_t readAt(uint64_t off, void* buf, size_t len) = 0;

    // Human-readable name for the UI (file path, "Optane merge", ...).
    virtual std::string name() const = 0;

    // Convenience: return exactly `len` bytes or throw. Zero-fills any tail
    // past EOF so filesystem parsers reading a trailing structure still get a
    // full-size buffer to work with.
    std::vector<uint8_t> read(uint64_t off, size_t len);
};

// A raw disk image backed by a file on disk (dd/E01-raw/.img/.bin/device node).
//
// Reads are thread-safe: readAt() uses pread(), which takes the offset as an
// argument and never touches a shared file position, so any number of threads
// may read the same source concurrently without locking. This is what lets the
// UI preview a file while an export worker streams another one.
class RawImageSource : public ImageSource {
public:
    explicit RawImageSource(const std::string& path);
    ~RawImageSource() override;
    // The source owns a file descriptor; copying would double-close it.
    RawImageSource(const RawImageSource&) = delete;
    RawImageSource& operator=(const RawImageSource&) = delete;

    uint64_t size() const override { return size_; }
    size_t readAt(uint64_t off, void* buf, size_t len) override;
    std::string name() const override { return path_; }

private:
    std::string path_;
    int fd_ = -1;
    uint64_t size_ = 0;
};

// A byte-range window onto a parent source, offset by `base`. Used to present a
// single partition to a filesystem parser as if it were a standalone image.
class SubImageSource : public ImageSource {
public:
    SubImageSource(std::shared_ptr<ImageSource> parent, uint64_t base,
                   uint64_t length, std::string label);
    uint64_t size() const override { return length_; }
    size_t readAt(uint64_t off, void* buf, size_t len) override;
    std::string name() const override { return label_; }

private:
    std::shared_ptr<ImageSource> parent_;
    uint64_t base_;
    uint64_t length_;
    std::string label_;
};

} // namespace de

#include "core/image_source.h"
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace de {

std::vector<uint8_t> ImageSource::read(uint64_t off, size_t len) {
    std::vector<uint8_t> buf(len, 0);
    size_t got = readAt(off, buf.data(), len);
    // Tail past EOF stays zero-filled; that is intentional (see header).
    (void)got;
    return buf;
}

RawImageSource::RawImageSource(const std::string& path) : path_(path) {
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0)
        throw std::runtime_error("cannot open image: " + path);
    struct stat st{};
    if (::fstat(fd_, &st) != 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("cannot stat image: " + path);
    }
    if (S_ISBLK(st.st_mode)) {
        // Block device (e.g. /dev/nvme0n1): st_size is 0, so query via lseek.
        off_t end = ::lseek(fd_, 0, SEEK_END);
        size_ = end > 0 ? static_cast<uint64_t>(end) : 0;
    } else {
        size_ = static_cast<uint64_t>(st.st_size);
    }
}

RawImageSource::~RawImageSource() {
    if (fd_ >= 0) ::close(fd_);
}

size_t RawImageSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= size_) return 0;
    if (off + len > size_) len = static_cast<size_t>(size_ - off);
    // pread() is atomic w.r.t. the file offset (it takes the offset as an
    // argument), so concurrent readAt() calls from multiple threads are safe
    // without locking. Loop to handle short reads and EINTR.
    auto* p = static_cast<uint8_t*>(buf);
    size_t total = 0;
    while (total < len) {
        ssize_t n = ::pread(fd_, p + total, len - total,
                            static_cast<off_t>(off + total));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;                      // read error: return what we have
        }
        if (n == 0) break;              // unexpected EOF
        total += static_cast<size_t>(n);
    }
    return total;
}

SubImageSource::SubImageSource(std::shared_ptr<ImageSource> parent, uint64_t base,
                               uint64_t length, std::string label)
    : parent_(std::move(parent)), base_(base), length_(length),
      label_(std::move(label)) {}

size_t SubImageSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= length_) return 0;
    if (off + len > length_) len = static_cast<size_t>(length_ - off);
    return parent_->readAt(base_ + off, buf, len);
}

} // namespace de

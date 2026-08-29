#pragma once
#include "core/image_source.h"
#include <cstdint>
#include <memory>
#include <optional>

namespace de::hfswrapper {

// An HFS *wrapper*: a small, real, mountable classic-HFS volume whose only
// purpose is to carry an HFS+ volume embedded inside one of its allocation
// blocks.
//
// Every drive formatted by Mac OS 8.1 through 10.3 - anything meant to also
// mount on Mac OS 9, which on an external drive of that era means all of them -
// is laid out this way. To Mac OS 9 the disk is HFS, holding a "you need Mac
// OS 8.1" README and a System file; to Mac OS X the wrapper is a pointer.
//
// So on such a volume the thing at +1024 is an HFS Master Directory Block
// ('BD'), not an HFS+ volume header ('H+'), and the real HFS+ volume starts
// megabytes further in. A reader that mounts what it finds at +1024 gets the
// wrapper: a handful of Apple files, on a disk holding a customer's entire
// archive.
struct Embedded {
    uint64_t offset = 0;   // byte offset of the HFS+ volume within the volume
    uint64_t length = 0;
};

// The embedded HFS+ volume a wrapper points at, or nullopt when `vol` is not a
// wrapper - including when it is a plain classic-HFS volume with no embedded
// extent, which the classic-HFS reader owns.
std::optional<Embedded> find(ImageSource& vol);

// `find`, as a source addressing just the embedded volume. Null if not wrapped.
std::shared_ptr<ImageSource> open(const std::shared_ptr<ImageSource>& vol);

} // namespace de::hfswrapper

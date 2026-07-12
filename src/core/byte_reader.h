#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>

// Little-endian read helpers over a byte buffer. All on-disk structures for the
// filesystems we target (NTFS, ext4, and the GPT/MBR partition tables) are
// little-endian, so these are the primitives every parser is built on.
namespace de {

inline uint8_t  rd8 (const uint8_t* p) { return p[0]; }
inline uint16_t rd16(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }
inline uint32_t rd32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
inline uint64_t rd64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

// Sign-extended little-endian integer of `len` bytes (1..8). Used by NTFS data
// runs, whose cluster offsets are signed and variable width.
inline int64_t rdSigned(const uint8_t* p, unsigned len) {
    if (len == 0) return 0;
    int64_t v = 0;
    for (unsigned i = 0; i < len; ++i)
        v |= static_cast<int64_t>(p[i]) << (8 * i);
    // sign-extend from the top byte
    if (p[len - 1] & 0x80) {
        for (unsigned i = len; i < 8; ++i)
            v |= static_cast<int64_t>(0xFF) << (8 * i);
    }
    return v;
}

// Unsigned little-endian integer of `len` bytes (0..8).
inline uint64_t rdUnsigned(const uint8_t* p, unsigned len) {
    uint64_t v = 0;
    for (unsigned i = 0; i < len; ++i)
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

// Bounds-checked view over a vector<uint8_t>, so a corrupt/hostile image can
// never walk us off the end of a buffer.
struct Span {
    const uint8_t* data = nullptr;
    size_t size = 0;

    const uint8_t* at(size_t off, size_t need) const {
        if (off + need < off || off + need > size)
            throw std::out_of_range("Span::at out of range");
        return data + off;
    }
    uint16_t u16(size_t off) const { return rd16(at(off, 2)); }
    uint32_t u32(size_t off) const { return rd32(at(off, 4)); }
    uint64_t u64(size_t off) const { return rd64(at(off, 8)); }
    uint8_t  u8 (size_t off) const { return *at(off, 1); }
};

} // namespace de

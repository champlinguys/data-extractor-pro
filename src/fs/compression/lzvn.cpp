// LZVN decompressor.
//
// LZVN is the byte-oriented LZ variant Apple uses for decmpfs types 7 and 8
// (and inside .cpgz/AppleFSCompression payloads). It is an LZ77 scheme with
// one-to-three-byte opcodes that pack a literal count, a match length and a
// match distance together; there is no entropy coding, which is why decoding
// is a plain loop with no tables.
//
// The opcode map and field layouts below follow Apple's reference decoder in
// the LZFSE project (lzvn_decode_base.c, BSD-3-Clause); the implementation
// here is our own, written against that format description with explicit
// bounds checks on every read and write, since a recovery tool routinely feeds
// damaged input to this code.
#include "fs/compression/decmpfs.h"
#include <cstring>

namespace de::compression {

namespace {

enum class Op : uint8_t {
    SmlD, // literal + match, 11-bit distance   (2 opcode bytes)
    MedD, // literal + match, 14-bit distance   (3 opcode bytes)
    LrgD, // literal + match, 16-bit distance   (3 opcode bytes)
    PreD, // literal + match, distance reused   (1 opcode byte)
    SmlM, // match only, length in the opcode   (1 opcode byte)
    LrgM, // match only, length in byte 1 + 16  (2 opcode bytes)
    SmlL, // literal only, length in the opcode (1 opcode byte)
    LrgL, // literal only, length in byte 1 +16 (2 opcode bytes)
    Nop,
    Eos,
    Udef,
};

// The 256-entry opcode map, written as the 32 rows of 8 it forms on disk. In
// most rows the low three bits of the opcode carry distance bits 8-10, so
// values 0-5 are "small distance"; 6 and 7 are escapes whose meaning depends
// on the row, and whole rows are given over to medium distances, literals and
// matches.
constexpr Op O_S = Op::SmlD, O_M = Op::MedD, O_L = Op::LrgD, O_P = Op::PreD;
constexpr Op O_U = Op::Udef;

constexpr Op OPC[256] = {
    // 0x00-0x3F: small/large distance, with end-of-stream and no-ops in the
    // escape slots.
    O_S, O_S, O_S, O_S, O_S, O_S, Op::Eos, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, Op::Nop, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, Op::Nop, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_U, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_U, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_U, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_U, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_U, O_L,
    // 0x40-0x6F: the escape slot now means "reuse the previous distance".
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    // 0x70-0x7F: unused.
    O_U, O_U, O_U, O_U, O_U, O_U, O_U, O_U,
    O_U, O_U, O_U, O_U, O_U, O_U, O_U, O_U,
    // 0x80-0x9F.
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    // 0xA0-0xBF: medium distance occupies the whole range.
    O_M, O_M, O_M, O_M, O_M, O_M, O_M, O_M,
    O_M, O_M, O_M, O_M, O_M, O_M, O_M, O_M,
    O_M, O_M, O_M, O_M, O_M, O_M, O_M, O_M,
    O_M, O_M, O_M, O_M, O_M, O_M, O_M, O_M,
    // 0xC0-0xCF.
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    O_S, O_S, O_S, O_S, O_S, O_S, O_P, O_L,
    // 0xD0-0xDF: unused.
    O_U, O_U, O_U, O_U, O_U, O_U, O_U, O_U,
    O_U, O_U, O_U, O_U, O_U, O_U, O_U, O_U,
    // 0xE0-0xEF: literal-only.
    Op::LrgL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL,
    Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL, Op::SmlL,
    // 0xF0-0xFF: match-only, reusing the previous distance.
    Op::LrgM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM,
    Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM, Op::SmlM,
};

} // namespace

size_t lzvnDecode(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen) {
    size_t si = 0, di = 0;
    size_t dist = 0; // carried between opcodes: pre_d/sml_m/lrg_m reuse it
    while (si < srcLen) {
        const uint8_t opc = src[si];
        size_t litLen = 0, matchLen = 0, opcLen = 0;
        switch (OPC[opc]) {
            case Op::SmlD:
                opcLen = 2;
                if (si + opcLen > srcLen) return di;
                litLen = (opc >> 6) & 0x3;
                matchLen = ((opc >> 3) & 0x7) + 3;
                dist = (static_cast<size_t>(opc & 0x7) << 8) | src[si + 1];
                break;
            case Op::MedD: {
                opcLen = 3;
                if (si + opcLen > srcLen) return di;
                // The two bytes after the opcode form a little-endian word
                // holding the low match-length bits and a 14-bit distance.
                uint32_t w = static_cast<uint32_t>(src[si + 1]) |
                             (static_cast<uint32_t>(src[si + 2]) << 8);
                litLen = (opc >> 3) & 0x3;
                matchLen = ((static_cast<size_t>(opc & 0x7) << 2) | (w & 0x3)) + 3;
                dist = w >> 2;
                break;
            }
            case Op::LrgD:
                opcLen = 3;
                if (si + opcLen > srcLen) return di;
                litLen = (opc >> 6) & 0x3;
                matchLen = ((opc >> 3) & 0x7) + 3;
                dist = static_cast<size_t>(src[si + 1]) |
                       (static_cast<size_t>(src[si + 2]) << 8);
                break;
            case Op::PreD:
                opcLen = 1;
                litLen = (opc >> 6) & 0x3;
                matchLen = ((opc >> 3) & 0x7) + 3;
                break;
            case Op::SmlM:
                opcLen = 1;
                matchLen = opc & 0xF;
                break;
            case Op::LrgM:
                opcLen = 2;
                if (si + opcLen > srcLen) return di;
                matchLen = static_cast<size_t>(src[si + 1]) + 16;
                break;
            case Op::SmlL:
                opcLen = 1;
                litLen = opc & 0xF;
                break;
            case Op::LrgL:
                opcLen = 2;
                if (si + opcLen > srcLen) return di;
                litLen = static_cast<size_t>(src[si + 1]) + 16;
                break;
            case Op::Nop:
                si += 1;
                continue;
            case Op::Eos:
                return di;
            case Op::Udef:
            default:
                return 0; // malformed stream
        }
        si += opcLen;

        if (litLen) {
            if (si + litLen > srcLen || di + litLen > dstLen) return 0;
            std::memcpy(dst + di, src + si, litLen);
            si += litLen;
            di += litLen;
        }
        if (matchLen) {
            // Matches routinely overlap their own output (run-length style),
            // so this must stay a forward byte copy, not memcpy/memmove.
            if (dist == 0 || dist > di || di + matchLen > dstLen) return 0;
            uint8_t* out = dst + di;
            const uint8_t* from = dst + di - dist;
            for (size_t i = 0; i < matchLen; ++i) out[i] = from[i];
            di += matchLen;
        }
    }
    return di;
}

} // namespace de::compression

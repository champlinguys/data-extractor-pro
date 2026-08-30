#include "core/apple_double.h"
#include <filesystem>
#include <fstream>

namespace de {

std::string appleDoublePath(const std::string& dataPath) {
    std::filesystem::path p(dataPath);
    return (p.parent_path() / ("._" + p.filename().string())).string();
}

bool writeAppleDouble(const std::string& dataPath, const std::vector<uint8_t>& rsrc) {
    std::ofstream os(appleDoublePath(dataPath), std::ios::binary | std::ios::trunc);
    if (!os) return false;
    auto be32 = [&](uint32_t v) {
        uint8_t b[4] = {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)};
        os.write(reinterpret_cast<const char*>(b), 4);
    };
    be32(0x00051607);            // AppleDouble magic
    be32(0x00020000);            // version 2
    for (int i = 0; i < 16; ++i) os.put(0);   // filler
    uint8_t n[2] = {0, 1};       // one entry
    os.write(reinterpret_cast<const char*>(n), 2);
    be32(2);                     // entry id 2 = resource fork
    be32(38);                    // offset: 26-byte header + one 12-byte entry
    be32(static_cast<uint32_t>(rsrc.size()));
    os.write(reinterpret_cast<const char*>(rsrc.data()),
             static_cast<std::streamsize>(rsrc.size()));
    return static_cast<bool>(os);
}

} // namespace de

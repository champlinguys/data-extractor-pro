#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace de {

// Where the AppleDouble sidecar for `dataPath` goes: "dir/name" -> "dir/._name".
std::string appleDoublePath(const std::string& dataPath);

// Write a file's resource fork beside it as an AppleDouble sidecar ("._name"),
// the form macOS itself uses when copying a Mac file onto a foreign filesystem.
// A classic Mac document can keep most of what matters in the resource fork, so
// dropping it silently loses content that the data fork alone does not carry.
//
// The format matters as much as the bytes: macOS reassembles a "._name" sidecar
// back into a real resource fork when the folder is copied to an HFS+/APFS
// volume, so the customer gets a working file again. A raw dump of the fork
// under some other name preserves the data but never reattaches, which is worse
// than it looks - the file appears recovered while still being broken.
//
// Returns false if the sidecar could not be written.
bool writeAppleDouble(const std::string& dataPath, const std::vector<uint8_t>& rsrc);

} // namespace de

#pragma once
#include <string>
#include "fs/filesystem.h"

namespace de {

// Stamp `t` onto an already-written file or directory so the export mirrors the
// dates the object had on the source volume - otherwise every recovered file
// dates from the moment of extraction, which wrecks the timeline once the
// customer uploads the folder to cloud storage.
//
// Only mtime and atime are settable on Linux: there is no portable syscall for
// birth time, so crtime is carried through the model (and shown in the UI) but
// not written to disk. An unknown (0) component falls back to the other known
// one, and if nothing is known the file is left untouched.
//
// Returns false if the timestamps could not be applied.
bool applyFileTimes(const std::string& path, const FsTimes& t);

} // namespace de

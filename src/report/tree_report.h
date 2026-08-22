#pragma once
#include <functional>
#include <ostream>
#include <string>
#include <vector>
#include "fs/filesystem.h"

// Producing a listing of everything on a volume.
//
// On a recovery job the customer usually wants some of their data now and the
// rest later, and deciding which is which means seeing what is actually there.
// A browsable tree in the GUI is fine for poking around, but not for "find
// every folder with 'osage' in the name" across nineteen thousand folders -
// for that you want the whole listing in one file you can search, keep, and
// send to the customer.
namespace de::report {

struct Options {
    bool includeFiles = true;
    size_t maxDepth = 64;
    // Called every so often with the running totals, for a progress line.
    std::function<void(uint64_t files, uint64_t dirs)> progress;
};

struct Stats {
    uint64_t files = 0;
    uint64_t dirs = 0;
    uint64_t bytes = 0;
};

// One entry per object, flattened, with parent links. Walking a large volume
// takes minutes, so the walk happens once and every output format is written
// from the result.
struct Entry {
    std::string name;
    int parent = -1; // index into the vector, -1 for a top-level object
    bool isDir = false;
    bool isDeleted = false;  // recovered from a freed directory entry
    uint64_t size = 0;
    int64_t mtime = 0;
};

std::vector<Entry> collectTree(Filesystem& fs, const FsNode& root, Stats& stats,
                               const Options& opt = {});

// Full path of entry `i`, e.g. "/BOSS SHOTSHELLS_EXT/BOSS ART".
std::string entryPath(const std::vector<Entry>& entries, int i);

// One line per object: size, date, full path. Plain text, so grep works.
void writeTextTree(const std::vector<Entry>& entries, std::ostream& out);

// A self-contained HTML page with a search box: folders expand on click, and
// typing filters every path on the volume. No external files, no network.
void writeHtmlTree(const std::vector<Entry>& entries, std::ostream& out,
                   const std::string& title);

// Case-insensitive substring search over names. `hit` gets the full path of
// each match; a folder that matches is reported without its contents being
// listed individually.
Stats findNames(Filesystem& fs, const FsNode& root,
                const std::vector<std::string>& needles,
                const std::function<void(const std::string& path, const FsNode& node)>& hit,
                const Options& opt = {});

} // namespace de::report

#include "core/file_times.h"

#include <fcntl.h>
#include <sys/stat.h>

namespace de {

namespace {

constexpr int64_t NS_PER_SEC = 1000000000;

// Unix nanoseconds -> timespec, flooring so pre-1970 times (plenty of drives
// carry a bogus 1969 or a genuinely old 1980s date) keep a non-negative
// nanosecond remainder, which is what utimensat requires.
timespec toTimespec(int64_t ns) {
    int64_t sec = ns / NS_PER_SEC;
    int64_t rem = ns % NS_PER_SEC;
    if (rem < 0) { rem += NS_PER_SEC; --sec; }
    timespec ts{};
    ts.tv_sec = static_cast<time_t>(sec);
    ts.tv_nsec = static_cast<long>(rem);
    return ts;
}

} // namespace

bool applyFileTimes(const std::string& path, const FsTimes& t) {
    // Fall back to whichever timestamp we do have rather than leaving one at
    // the extraction date: a file whose atime says "today" still looks wrong in
    // a timeline. Creation time is the last resort for both.
    int64_t mtime = t.mtime ? t.mtime : (t.crtime ? t.crtime : t.atime);
    int64_t atime = t.atime ? t.atime : mtime;
    if (!mtime) return true;   // nothing known; leave the file as written

    timespec times[2];
    times[0] = toTimespec(atime);  // access
    times[1] = toTimespec(mtime);  // modification
    // AT_SYMLINK_NOFOLLOW so a name we wrote is stamped itself, never a target
    // outside the export tree.
    return utimensat(AT_FDCWD, path.c_str(), times, AT_SYMLINK_NOFOLLOW) == 0;
}

} // namespace de
